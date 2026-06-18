package isolation

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// embedded isolation assets: Dockerfile + init/entrypoint scripts. The
// sha256 of their concatenated bytes (sorted by name for stability)
// becomes the image tag, so a binary that ships different assets
// automatically produces a different tag on first use.
//
//go:embed assets/Dockerfile assets/init-firewall.sh assets/entrypoint.sh
var isolationAssets embed.FS

const (
	isolationImageRepo = "agent-vault/isolation"
	// assetsHashLen is 12 hex chars — plenty of collision resistance
	// for this purpose and short enough to read in docker image ls.
	assetsHashLen = 12
	// assetsLabelKey is the build-time label carrying the FULL asset hash.
	// The cache decision trusts a locally-tagged image only when this label
	// matches the embedded assets — the tag alone is not proof of content
	// (the local daemon is a shared, multi-writer namespace and the tag is
	// deterministic and published, so an attacker can plant an image under
	// it). See imageTrusted.
	assetsLabelKey = "agent-vault.assets-sha256"
)

// assetFiles lists embedded assets in the canonical order used for
// hashing. Order is load-bearing — changing it invalidates every
// user's cached image.
var assetFiles = []string{
	"assets/Dockerfile",
	"assets/entrypoint.sh",
	"assets/init-firewall.sh",
}

// TODO: concurrent vault-run invocations that both miss the image
// cache each docker-build the same content. Last writer wins, same
// bytes — one extra minute of wasted CPU. Acceptable for v1.

// EnsureImage guarantees the isolation image exists locally and returns
// the fully qualified tag. If override is non-empty, the user's own
// image is used as-is and no build is performed.
//
// Content-hash tag pinning means that bumping agent-vault with changed
// assets automatically triggers a rebuild on next use.
func EnsureImage(ctx context.Context, override string, stderr io.Writer) (string, error) {
	if override != "" {
		return override, nil
	}
	fullHash, err := assetsFullHash()
	if err != nil {
		return "", err
	}
	tag := isolationImageRepo + ":" + fullHash[:assetsHashLen]
	if imageTrusted(ctx, tag, fullHash, inspectImageLabel) {
		return tag, nil
	}

	dir, err := unpackAssets(fullHash[:assetsHashLen])
	if err != nil {
		return "", err
	}
	fmt.Fprintln(stderr, "agent-vault: building isolation image (one-time setup)...")
	// --pull=never: never silently pull a registry image under our tag.
	// --label stamps the provenance hash so a later run can verify the
	// cached image was built from exactly these assets (see imageTrusted).
	build := exec.CommandContext(ctx, "docker", "build",
		"--pull=never",
		"--label", assetsLabelKey+"="+fullHash,
		"-t", tag,
		dir,
	)
	build.Stdout = stderr
	build.Stderr = stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("docker build: %w", err)
	}
	return tag, nil
}

// imageTrusted reports whether the locally-tagged image was built from the
// expected assets. It trusts the image ONLY when the build-time provenance
// label equals the full asset hash — the tag's mere existence is not proof,
// since the local Docker daemon is a shared, multi-writer namespace and the
// tag is deterministic and published, so an attacker could plant an arbitrary
// (e.g. firewall-skipping) image under it. A missing/mismatched label, or any
// inspect error (tag absent), is untrusted → triggers a rebuild.
func imageTrusted(ctx context.Context, tag, wantHash string, fetchLabel func(ctx context.Context, tag, key string) (string, error)) bool {
	got, err := fetchLabel(ctx, tag, assetsLabelKey)
	if err != nil {
		return false
	}
	return got != "" && got == wantHash
}

// inspectImageLabel returns the value of a label on a locally-tagged image,
// or an error if the image is absent.
func inspectImageLabel(ctx context.Context, tag, key string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect",
		"-f", fmt.Sprintf("{{ index .Config.Labels %q }}", key), tag).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// assetsHash returns the short (12-hex) asset hash used in the image tag.
func assetsHash() (string, error) {
	full, err := assetsFullHash()
	if err != nil {
		return "", err
	}
	return full[:assetsHashLen], nil
}

// assetsFullHash returns the full sha256 (hex) of the embedded assets. The
// full hash is used as the provenance label; only its prefix appears in the
// human-readable tag.
func assetsFullHash() (string, error) {
	h := sha256.New()
	for _, name := range assetFiles {
		data, err := isolationAssets.ReadFile(name)
		if err != nil {
			return "", fmt.Errorf("read embedded asset %s: %w", name, err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unpackAssets writes the embedded files to
// ~/.agent-vault/isolation/<hash>/ (idempotent) and returns the path.
// Scripts are emitted 0o755 so docker build's COPY preserves mode.
func unpackAssets(hash string) (string, error) {
	dir, err := hostIsolationDir()
	if err != nil {
		return "", err
	}
	outDir := filepath.Join(dir, hash)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	for _, name := range assetFiles {
		data, err := isolationAssets.ReadFile(name)
		if err != nil {
			return "", err
		}
		base := filepath.Base(name)
		mode := os.FileMode(0o644)
		if filepath.Ext(base) == ".sh" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(outDir, base), data, mode); err != nil {
			return "", fmt.Errorf("write %s: %w", base, err)
		}
	}
	return outDir, nil
}
