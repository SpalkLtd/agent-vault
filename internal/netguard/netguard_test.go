package netguard

import (
	"net"
	"testing"
)

func TestIsBlockedIP_AlwaysBlocked(t *testing.T) {
	// IMDS endpoints are blocked regardless of policy (allowlist does NOT bypass).
	imds := net.ParseIP("169.254.169.254")

	if !isBlockedIP(imds, false, nil) {
		t.Error("169.254.169.254 should be blocked when private ranges are blocked")
	}
	if !isBlockedIP(imds, true, nil) {
		t.Error("169.254.169.254 should be blocked even when private ranges are allowed")
	}

	// Even with allowlist containing the IMDS IP, it should still be blocked.
	allowlist := []net.IPNet{parseCIDR("169.254.169.254/32")}
	if !isBlockedIP(imds, false, allowlist) {
		t.Error("169.254.169.254 should be blocked even when allowlisted (always-blocked takes precedence)")
	}

	// AWS IMDSv2 IPv6
	imdsV6 := net.ParseIP("fd00:ec2::254")
	if !isBlockedIP(imdsV6, true, nil) {
		t.Error("fd00:ec2::254 should be blocked even when private ranges are allowed")
	}
}

func TestIsBlockedIP_UnspecifiedAddresses(t *testing.T) {
	// SECURITY (HIGH): the IPv6 unspecified address :: routes to loopback on
	// Linux/macOS exactly like 0.0.0.0, so it must be blocked when private
	// ranges are blocked. Previously :: was omitted from privateRanges.
	for _, ip := range []string{"0.0.0.0", "::"} {
		if !isBlockedIP(net.ParseIP(ip), false, nil) {
			t.Errorf("%s should be blocked when private ranges are blocked (routes to loopback)", ip)
		}
	}
}

func TestIsBlockedIP_MetadataAlwaysBlocked(t *testing.T) {
	// SECURITY (MEDIUM): cloud metadata / instance-credential endpoints must be
	// blocked regardless of AGENT_VAULT_ALLOW_PRIVATE_RANGES. Previously only
	// 169.254.169.254 and fd00:ec2::254 were in the always-blocked set, so the
	// AWS ECS task-role endpoint and Alibaba IMDS leaked when allowPrivate=true.
	metadata := []string{
		"169.254.169.254", // AWS/GCP/Azure IMDS
		"169.254.170.2",   // AWS ECS/EKS task-role credentials endpoint
		"100.100.100.200", // Alibaba Cloud IMDS
	}
	for _, ip := range metadata {
		if !isBlockedIP(net.ParseIP(ip), true, nil) {
			t.Errorf("%s (cloud metadata) should be blocked even when private ranges are allowed", ip)
		}
		// Allowlisting must not bypass metadata blocking either.
		allow := []net.IPNet{parseCIDR(ip + "/32")}
		if !isBlockedIP(net.ParseIP(ip), false, allow) {
			t.Errorf("%s (cloud metadata) should be blocked even when allowlisted", ip)
		}
	}
}

func TestIsBlockedIP_AllowPrivate(t *testing.T) {
	// When private ranges are allowed, RFC-1918 etc. should NOT be blocked.
	cases := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"fe80::1",
		"127.0.0.1",
	}
	for _, ip := range cases {
		if isBlockedIP(net.ParseIP(ip), true, nil) {
			t.Errorf("%s should NOT be blocked when private ranges are allowed", ip)
		}
	}
}

func TestIsBlockedIP_BlockPrivate(t *testing.T) {
	// When private ranges are blocked, RFC-1918, loopback, link-local, CGN should be blocked.
	blocked := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"127.0.0.1",
		"169.254.0.1",
		"100.64.0.1",
	}
	for _, ip := range blocked {
		if !isBlockedIP(net.ParseIP(ip), false, nil) {
			t.Errorf("%s should be blocked when private ranges are blocked", ip)
		}
	}

	// Public IPs should NOT be blocked.
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"104.18.0.1",
	}
	for _, ip := range allowed {
		if isBlockedIP(net.ParseIP(ip), false, nil) {
			t.Errorf("%s should NOT be blocked (public IP)", ip)
		}
	}
}

func TestIsBlockedIP_Allowlist(t *testing.T) {
	allowlist := []net.IPNet{
		parseCIDR("10.163.0.0/16"),
		parseCIDR("192.168.1.1/32"),
	}

	// IPs in allowlist should NOT be blocked.
	allowlisted := []string{
		"10.163.0.1",
		"10.163.255.254",
		"192.168.1.1",
	}
	for _, ip := range allowlisted {
		if isBlockedIP(net.ParseIP(ip), false, allowlist) {
			t.Errorf("%s should NOT be blocked when allowlisted", ip)
		}
	}

	// Private IPs not in allowlist should be blocked.
	blocked := []string{
		"10.0.0.1",
		"192.168.1.2",
		"172.16.0.1",
	}
	for _, ip := range blocked {
		if !isBlockedIP(net.ParseIP(ip), false, allowlist) {
			t.Errorf("%s should be blocked (not allowlisted)", ip)
		}
	}
}

func TestAllowPrivateFromEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", false},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"t", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"f", false},
		{"garbage", false}, // unparseable falls back to safe default
	}
	for _, c := range cases {
		t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", c.env)
		if got := AllowPrivateFromEnv(); got != c.want {
			t.Errorf("AllowPrivateFromEnv() with env=%q = %v, want %v", c.env, got, c.want)
		}
	}
}

func TestAllowlistFromEnv(t *testing.T) {
	// Empty env var returns nil.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
	if ranges := AllowlistFromEnv(); ranges != nil {
		t.Error("empty AGENT_VAULT_NETWORK_ALLOWLIST should return nil")
	}

	// Single CIDR.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16")
	ranges := AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("10.163.0.38")) {
		t.Error("10.163.0.0/16 should contain 10.163.0.38")
	}

	// Multiple CIDRs.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16,192.168.1.0/24")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	// Bare IPv4 → /32.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "192.168.1.1")
	ranges = AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("192.168.1.1")) {
		t.Error("bare IPv4 192.168.1.1 should be /32 and contain itself")
	}
	if ranges[0].Contains(net.ParseIP("192.168.1.2")) {
		t.Error("192.168.1.1/32 should NOT contain 192.168.1.2")
	}

	// Bare IPv6 → /128, NOT /32 (regression for IPv6 sizing bug).
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "fd00::1")
	ranges = AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
	if !ranges[0].Contains(net.ParseIP("fd00::1")) {
		t.Error("bare IPv6 fd00::1 should be /128 and contain itself")
	}
	if ranges[0].Contains(net.ParseIP("fd00::2")) {
		t.Error("bare IPv6 fd00::1 must NOT expand to a /32 prefix (IPv6 sizing regression)")
	}

	// Mixed CIDR and bare IP.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16,192.168.1.1")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges, got %d", len(ranges))
	}

	// Whitespace is trimmed.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "  10.163.0.0/16  ,  192.168.1.1  ")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 ranges after trimming, got %d", len(ranges))
	}

	// Invalid entries are skipped.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "10.163.0.0/16,invalid,192.168.1.0/24")
	ranges = AllowlistFromEnv()
	if len(ranges) != 2 {
		t.Fatalf("expected 2 valid ranges (invalid skipped), got %d", len(ranges))
	}

	// Whole-family entries are accepted (operator escape hatch) — startup warns separately.
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "0.0.0.0/0")
	ranges = AllowlistFromEnv()
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
}

func TestParseCIDRList(t *testing.T) {
	// Empty input returns nil.
	if got := ParseCIDRList("", "TEST"); got != nil {
		t.Errorf("empty input should return nil, got %v", got)
	}

	// Mixed valid and invalid entries: bad-IP, valid CIDR, malformed CIDR,
	// bare IPv4, bare IPv6. Only the three valid forms should survive.
	got := ParseCIDRList("invalid,10.0.0.0/8,bad/x,192.168.1.1,fd00::1", "TEST")
	if len(got) != 3 {
		t.Fatalf("expected 3 valid ranges, got %d: %v", len(got), got)
	}
	if !got[0].Contains(net.ParseIP("10.255.255.1")) {
		t.Error("range[0] should be 10.0.0.0/8")
	}
	if !got[1].Contains(net.ParseIP("192.168.1.1")) || got[1].Contains(net.ParseIP("192.168.1.2")) {
		t.Error("range[1] should be 192.168.1.1/32")
	}
	if !got[2].Contains(net.ParseIP("fd00::1")) || got[2].Contains(net.ParseIP("fd00::2")) {
		t.Error("range[2] should be fd00::1/128, not a wider IPv6 prefix")
	}
}
