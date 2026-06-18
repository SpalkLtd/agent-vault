package netguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// AllowPrivateFromEnv reads AGENT_VAULT_ALLOW_PRIVATE_RANGES and returns whether
// the proxy should allow connections to private/reserved IP ranges (RFC-1918,
// loopback, link-local, IPv6 ULA, CGN). Defaults to false (block) when unset
// or unparseable — the safe default for network-exposed deployments. Cloud
// metadata endpoints are blocked regardless of this setting.
func AllowPrivateFromEnv() bool {
	v := os.Getenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES")
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

// AllowlistFromEnv reads AGENT_VAULT_NETWORK_ALLOWLIST and returns a list of
// IP networks to allow when private-range blocking is on.
func AllowlistFromEnv() []net.IPNet {
	return ParseCIDRList(os.Getenv("AGENT_VAULT_NETWORK_ALLOWLIST"), "AGENT_VAULT_NETWORK_ALLOWLIST")
}

// ParseCIDRList parses a comma-separated list of CIDRs or bare IPs. Bare IPv4
// addresses are expanded to /32, bare IPv6 to /128. Invalid entries are logged
// via slog.Warn and skipped. Entries that cover an entire address family
// (mask 0, i.e. 0.0.0.0/0 or ::/0) are accepted but logged as warnings —
// they're rarely intended and effectively disable any per-range policy.
// envName labels the source in log messages.
func ParseCIDRList(raw, envName string) []net.IPNet {
	if raw == "" {
		return nil
	}

	var out []net.IPNet
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		cidr := p
		if !strings.Contains(p, "/") {
			ip := net.ParseIP(p)
			if ip == nil {
				slog.Warn("netguard: invalid IP, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
					slog.String("env", envName), slog.String("value", p))
				continue
			}
			if ip.To4() != nil {
				cidr = p + "/32"
			} else {
				cidr = p + "/128"
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			slog.Warn("netguard: invalid CIDR, skipping", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", p), slog.String("error", err.Error()))
			continue
		}

		if mask, _ := ipNet.Mask.Size(); mask == 0 {
			slog.Warn("netguard: CIDR list entry covers an entire address family", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
				slog.String("env", envName), slog.String("value", p))
		}

		out = append(out, *ipNet)
	}

	if len(out) > 0 {
		slog.Debug("netguard: loaded CIDR list", //nolint:gosec // G706: structured slog attrs, handlers quote control chars
			slog.String("env", envName), slog.Int("count", len(out)))
	}

	return out
}

// alwaysBlocked contains IP ranges that are blocked regardless of policy
// (checked before the allowPrivate short-circuit and the allowlist). These
// are cloud metadata / instance-credential endpoints and other dangerous
// destinations that must never be reachable through the proxy.
var alwaysBlocked = []net.IPNet{
	// AWS/GCP/Azure/Oracle IMDS
	parseCIDR("169.254.169.254/32"),
	// AWS ECS/EKS task-role credential endpoint (AWS_CONTAINER_CREDENTIALS_*)
	parseCIDR("169.254.170.2/32"),
	// Alibaba Cloud / OpenStack IMDS
	parseCIDR("100.100.100.200/32"),
	// AWS IMDSv2 IPv6
	parseCIDR("fd00:ec2::254/128"),
}

// carrierGradeNAT is RFC 6598 shared address space (100.64.0.0/10). It is
// private/reserved but net.IP.IsPrivate does NOT cover it, so it is checked
// explicitly alongside the stdlib predicates in isBlockedIP.
var carrierGradeNAT = parseCIDR("100.64.0.0/10")

// nat64WellKnownPrefix is RFC 6052 64:ff9b::/96. Addresses in this prefix
// embed an IPv4 address in their low 32 bits; a NAT64 host translates them to
// that IPv4 (e.g. 64:ff9b::a9fe:a9fe → 169.254.169.254). isBlockedIP unwraps
// the embedded IPv4 and evaluates it under the same policy so NAT64 cannot
// smuggle a request past the IPv4 rules. No stdlib predicate catches these —
// they look like ordinary global IPv6 unicast.
var nat64WellKnownPrefix = parseCIDR("64:ff9b::/96")

func parseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic("netguard: bad CIDR: " + s)
	}
	return *ipNet
}

// isBlockedIP checks if an IP is blocked. Cloud metadata endpoints are always
// blocked. When allowPrivate is false, private/reserved ranges are also
// blocked unless the IP is in the allowlist.
//
// Private/reserved matching uses the stdlib net.IP predicates rather than a
// hand-maintained CIDR list, so unspecified (0.0.0.0, ::), loopback, RFC1918,
// IPv6 ULA, link-local unicast (incl. all of 169.254.0.0/16) and link-local
// multicast — for both IPv4 and IPv4-mapped IPv6 — are covered without
// enumeration. CGN (RFC6598) is added explicitly because IsPrivate omits it.
func isBlockedIP(ip net.IP, allowPrivate bool, allowed []net.IPNet) bool {
	// NAT64: unwrap the embedded IPv4 and evaluate it under the same policy.
	if len(ip) == net.IPv6len && nat64WellKnownPrefix.Contains(ip) {
		embedded := net.IP(ip[len(ip)-net.IPv4len:])
		return isBlockedIP(embedded, allowPrivate, allowed)
	}

	for _, n := range alwaysBlocked {
		if n.Contains(ip) {
			return true
		}
	}

	if allowPrivate {
		return false
	}

	for _, n := range allowed {
		if n.Contains(ip) {
			return false
		}
	}

	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		carrierGradeNAT.Contains(ip)
}

// SafeDialContext returns a DialContext function that blocks connections to
// forbidden IP ranges. When allowPrivate is true, only IMDS endpoints are
// blocked. When false, private/reserved ranges are also blocked unless
// allowlisted via AGENT_VAULT_NETWORK_ALLOWLIST.
func SafeDialContext(allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var allowed []net.IPNet
	if !allowPrivate {
		allowed = AllowlistFromEnv()
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("netguard: invalid address %q: %w", addr, err)
		}

		// Resolve the hostname to IP addresses.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("netguard: DNS lookup failed for %q: %w", host, err)
		}

		// Check all resolved IPs before connecting.
		for _, ipAddr := range ips {
			if isBlockedIP(ipAddr.IP, allowPrivate, allowed) {
				return nil, fmt.Errorf("netguard: connection to %s (%s) blocked by network policy",
					host, ipAddr.IP.String())
			}
		}

		// All IPs are safe — connect directly to a validated IP to prevent
		// DNS rebinding (TOCTOU: a second resolution could return a different IP).
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}
