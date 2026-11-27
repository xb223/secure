package render

import (
	"fmt"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
)

const resolvedPath = "/etc/systemd/resolved.conf.d/90-obsidian.conf"

func renderResolved(p *policy.Policy) Artifact {
	var b strings.Builder
	b.WriteString(header("systemd-resolved"))
	b.WriteString("[Resolve]\n")
	b.WriteString("# Disable multicast discovery and DNS leaks through fallback resolvers.\n")
	b.WriteString("LLMNR=no\n")
	b.WriteString("MulticastDNS=no\n")
	b.WriteString("DNSSEC=allow-downgrade\n")
	b.WriteString("Cache=yes\n")
	b.WriteString("DNSStubListener=yes\n")
	b.WriteString("Domains=~.\n")
	b.WriteString("FallbackDNS=\n")
	if len(p.Privacy.DNSServers) > 0 {
		fmt.Fprintf(&b, "DNS=%s\n", strings.Join(p.Privacy.DNSServers, " "))
	}
	switch p.Privacy.DNSOverTLS {
	case "yes":
		b.WriteString("DNSOverTLS=yes\n")
	case "no":
		b.WriteString("DNSOverTLS=no\n")
	default:
		b.WriteString("DNSOverTLS=opportunistic\n")
	}
	return Artifact{
		Path: resolvedPath, Content: []byte(b.String()), Mode: 0o644,
		Reason:  "local caching resolver without LLMNR, mDNS or fallback DNS leaks",
		Section: "privacy", Kind: KindConfig,
	}
}
