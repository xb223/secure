package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
)

const (
	firewallPath      = "/etc/obsidian/firewall.nft"
	firewallUnitPath  = "/etc/systemd/system/obsidian-firewall.service"
	firewallUnitName  = "obsidian-firewall.service"
	sandboxFWPath     = "/etc/obsidian/sandbox.nft"
	sandboxFWUnitPath = "/etc/systemd/system/obsidian-sandbox-firewall.service"
	sandboxFWUnitName = "obsidian-sandbox-firewall.service"
)

type exposureSpec struct {
	name  string
	proto string
	port  int
	mode  string
}

func exposureSpecs(p *policy.Policy) []exposureSpec {
	return []exposureSpec{
		{"ssh", "tcp", p.Admin.SSHPort, p.Exposure.SSH},
		{"https", "tcp", 443, p.Exposure.HTTPS},
		{"http", "tcp", 80, p.Exposure.HTTP},
		{"smtp", "tcp", 25, p.Exposure.SMTP},
		{"dns", "tcp", 53, p.Exposure.DNS},
		{"dns", "udp", 53, p.Exposure.DNS},
		{"ntp", "udp", 123, p.Exposure.NTP},
	}
}

func renderFirewall(p *policy.Policy) (NFTTable, error) {
	return renderFirewallExtra(p, 0)
}

// RenderFirewallTransition returns a temporary ruleset that also accepts the
// old SSH port, so a port change can be applied without losing the live
// session. The final ruleset remains the one written by Render.
func RenderFirewallTransition(p *policy.Policy, oldPort int) (NFTTable, error) {
	return renderFirewallExtra(p, oldPort)
}

func renderFirewallExtra(p *policy.Policy, extraSSHPort int) (NFTTable, error) {
	var b strings.Builder
	b.WriteString(header("firewall"))
	b.WriteString("# Exposure model: input is denied by default; loopback and replies are allowed.\n")
	b.WriteString("# Public services are accepted only on the public interface. Admin-only\n")
	b.WriteString("# services are accepted only from admin.source_cidrs on admin interfaces.\n")
	b.WriteString("flush table inet obsidian\n")
	b.WriteString("table inet obsidian {\n")

	prefixes := p.AdminPrefixes()
	var v4, v6 []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	if len(v4) > 0 {
		b.WriteString("  set admin_v4 {\n    type ipv4_addr\n    flags interval\n    elements = { ")
		b.WriteString(joinPrefixes(v4))
		b.WriteString(" }\n  }\n")
	}
	if len(v6) > 0 {
		b.WriteString("  set admin_v6 {\n    type ipv6_addr\n    flags interval\n    elements = { ")
		b.WriteString(joinPrefixes(v6))
		b.WriteString(" }\n  }\n")
	}

	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority filter; policy drop;\n")
	b.WriteString("    iifname \"lo\" accept comment \"obsidian:loopback\"\n")
	b.WriteString("    ct state established,related accept comment \"obsidian:replies\"\n")
	b.WriteString("    ct state invalid drop comment \"obsidian:invalid\"\n")
	b.WriteString("    udp sport 67 udp dport 68 accept comment \"obsidian:dhcp-client\"\n")
	b.WriteString("    udp sport 547 udp dport 546 accept comment \"obsidian:dhcpv6-client\"\n")
	b.WriteString("    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept comment \"obsidian:icmp\"\n")
	b.WriteString("    icmp type echo-request limit rate 5/second burst 10 packets accept comment \"obsidian:icmp-echo\"\n")
	b.WriteString("    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, nd-redirect } accept comment \"obsidian:icmpv6\"\n")
	b.WriteString("    icmpv6 type echo-request limit rate 5/second burst 10 packets accept comment \"obsidian:icmpv6-echo\"\n")

	interfaces := p.AdminInterfaces()
	commented := map[string]bool{}
	for _, spec := range exposureSpecs(p) {
		field := "exposure." + spec.name
		switch spec.mode {
		case policy.ExposureDisabled:
			if !commented[field] {
				fmt.Fprintf(&b, "    # %s = disabled: no accept rule\n", field)
				commented[field] = true
			}
		case policy.ExposureLoopback:
			if !commented[field] {
				fmt.Fprintf(&b, "    # %s = loopback: only the loopback accept above\n", field)
				commented[field] = true
			}
		case policy.ExposurePublic:
			if p.PublicInterface == "" {
				return NFTTable{}, fmt.Errorf("%s = public requires public_interface", field)
			}
			fmt.Fprintf(&b, "    iifname %s %s dport %d accept comment %s\n",
				quoteNftString(p.PublicInterface), spec.proto, spec.port,
				quoteNftString("obsidian:"+field+"=public"))
			if spec.name == "ssh" && extraSSHPort > 0 && extraSSHPort != spec.port {
				fmt.Fprintf(&b, "    iifname %s %s dport %d accept comment %s\n",
					quoteNftString(p.PublicInterface), spec.proto, extraSSHPort,
					quoteNftString("obsidian:ssh-transition"))
			}
		case policy.ExposureAdminOnly:
			if len(prefixes) == 0 {
				return NFTTable{}, fmt.Errorf("%s = admin-only requires admin.source_cidrs", field)
			}
			if len(interfaces) == 0 {
				return NFTTable{}, fmt.Errorf("%s = admin-only requires an interface", field)
			}
			ifaceSet := nftStringSet(interfaces)
			if len(v4) > 0 {
				fmt.Fprintf(&b, "    iifname %s ip saddr @admin_v4 %s dport %d accept comment %s\n",
					ifaceSet, spec.proto, spec.port, quoteNftString("obsidian:"+field+"=admin-only"))
			}
			if len(v6) > 0 {
				fmt.Fprintf(&b, "    iifname %s ip6 saddr @admin_v6 %s dport %d accept comment %s\n",
					ifaceSet, spec.proto, spec.port, quoteNftString("obsidian:"+field+"=admin-only"))
			}
			if spec.name == "ssh" && extraSSHPort > 0 && extraSSHPort != spec.port {
				if len(v4) > 0 {
					fmt.Fprintf(&b, "    iifname %s ip saddr @admin_v4 %s dport %d accept comment %s\n",
						ifaceSet, spec.proto, extraSSHPort, quoteNftString("obsidian:ssh-transition"))
				}
				if len(v6) > 0 {
					fmt.Fprintf(&b, "    iifname %s ip6 saddr @admin_v6 %s dport %d accept comment %s\n",
						ifaceSet, spec.proto, extraSSHPort, quoteNftString("obsidian:ssh-transition"))
				}
			}
		}
	}

	b.WriteString("    limit rate 10/minute log prefix \"obsidian:input-drop: \" level warn\n")
	b.WriteString("  }\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter; policy drop;\n")
	b.WriteString("  }\n")
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority filter; policy accept;\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")

	unit := firewallUnit(firewallUnitName, "obsidian firewall", firewallPath, "inet obsidian")
	return NFTTable{
		Name: "inet obsidian", Path: firewallPath, Content: []byte(b.String()),
		ServiceName: firewallUnitName, ServicePath: firewallUnitPath, ServiceContent: []byte(unit),
		Reason: "default-deny inbound firewall with policy exposures",
	}, nil
}

func joinPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

func nftStringSet(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, quoteNftString(v))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func nftArtifacts(t NFTTable) []Artifact {
	return []Artifact{
		{Path: t.Path, Content: t.Content, Mode: 0o644, Reason: t.Reason, Section: "firewall", Kind: KindNFT},
		{Path: t.ServicePath, Content: t.ServiceContent, Mode: 0o644, Reason: "persist the firewall across reboots", Section: "firewall", Kind: KindUnit},
	}
}

func firewallUnit(name, description, rulesPath, table string) string {
	parts := strings.Fields(table)
	family, tableName := "inet", table
	if len(parts) == 2 {
		family, tableName = parts[0], parts[1]
	}
	return header("firewall unit") + fmt.Sprintf(`[Unit]
Description=%s
DefaultDependencies=no
After=local-fs.target nftables.service
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft add table %s %s
ExecStart=/usr/sbin/nft -f %s
ExecReload=-/usr/sbin/nft add table %s %s
ExecReload=/usr/sbin/nft -f %s
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
SystemCallArchitectures=native
ReadOnlyPaths=/etc/obsidian

[Install]
WantedBy=multi-user.target
`, description, family, tableName, rulesPath, family, tableName, rulesPath)
}

func renderSandboxFirewall(p *policy.Policy, opts Options) (*NFTTable, error) {
	var rules []string
	for _, name := range p.SandboxNames() {
		sb := p.Sandbox[name]
		if sb.Network == "outbound" {
			// Unrestricted by explicit policy; no egress rules.
			continue
		}
		uid, ok := 0, false
		if opts.UserID != nil {
			uid, ok = opts.UserID(sb.RunAs)
		}
		if !ok {
			return nil, fmt.Errorf("sandbox.%s.run_as: user %q does not exist on this host", name, sb.RunAs)
		}
		match := fmt.Sprintf("meta skuid %d", uid)
		comment := func(suffix string) string {
			return quoteNftString("obsidian:sandbox." + name + ":" + suffix)
		}
		switch sb.Network {
		case "none":
			rules = append(rules,
				fmt.Sprintf("    %s oifname \"lo\" accept comment %s", match, comment("loopback")),
				fmt.Sprintf("    %s drop comment %s", match, comment("network-none")))
		case "loopback":
			rules = append(rules,
				fmt.Sprintf("    %s oifname \"lo\" accept comment %s", match, comment("loopback")),
				fmt.Sprintf("    %s drop comment %s", match, comment("network-loopback-only")))
		case "outbound-https":
			rules = append(rules,
				fmt.Sprintf("    %s oifname \"lo\" accept comment %s", match, comment("loopback")),
				fmt.Sprintf("    %s meta l4proto { tcp, udp } th dport 53 accept comment %s", match, comment("dns")),
				fmt.Sprintf("    %s meta l4proto tcp th dport 443 accept comment %s", match, comment("https")),
				fmt.Sprintf("    %s drop comment %s", match, comment("egress-deny")))
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}
	var b strings.Builder
	b.WriteString(header("sandbox egress"))
	b.WriteString("# Egress rules match the UID of each sandbox service. Every sandbox must\n")
	b.WriteString("# use its own run_as user; rules are evaluated in order.\n")
	b.WriteString("flush table inet obsidian_sandbox\n")
	b.WriteString("table inet obsidian_sandbox {\n")
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority filter; policy accept;\n")
	for _, rule := range rules {
		b.WriteString(rule)
		b.WriteString("\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	unit := firewallUnit(sandboxFWUnitName, "obsidian sandbox egress firewall", sandboxFWPath, "inet obsidian_sandbox")
	return &NFTTable{
		Name: "inet obsidian_sandbox", Path: sandboxFWPath, Content: []byte(b.String()),
		ServiceName: sandboxFWUnitName, ServicePath: sandboxFWUnitPath, ServiceContent: []byte(unit),
		Reason: "restrict sandbox egress to the policy network mode", Sandbox: true,
	}, nil
}
