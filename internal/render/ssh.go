package render

import (
	"fmt"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
)

const sshDropInPath = "/etc/ssh/sshd_config.d/00-obsidian.conf"

func renderSSHD(p *policy.Policy) Artifact {
	var b strings.Builder
	b.WriteString(header("sshd"))
	b.WriteString("# This file is included first by Debian's sshd_config, so these values win\n")
	b.WriteString("# over later drop-ins. Validate with: sshd -t\n")
	fmt.Fprintf(&b, "Port %d\n", p.Admin.SSHPort)
	fmt.Fprintf(&b, "PermitRootLogin %s\n", p.Admin.RootLogin)
	fmt.Fprintf(&b, "PubkeyAuthentication yes\n")
	fmt.Fprintf(&b, "PermitEmptyPasswords no\n")
	fmt.Fprintf(&b, "PasswordAuthentication %s\n", yesNo(p.Admin.PasswordAuth))
	fmt.Fprintf(&b, "KbdInteractiveAuthentication %s\n", yesNo(p.Admin.PasswordAuth))
	if !p.Admin.PasswordAuth {
		b.WriteString("AuthenticationMethods publickey\n")
	}
	fmt.Fprintf(&b, "AllowTcpForwarding %s\n", yesNo(p.Admin.AllowTCPForwarding))
	b.WriteString("AllowAgentForwarding no\n")
	b.WriteString("AllowStreamLocalForwarding no\n")
	b.WriteString("GatewayPorts no\n")
	b.WriteString("PermitTunnel no\n")
	b.WriteString("X11Forwarding no\n")
	b.WriteString("PermitUserEnvironment no\n")
	b.WriteString("IgnoreRhosts yes\n")
	b.WriteString("HostbasedAuthentication no\n")
	b.WriteString("GSSAPIAuthentication no\n")
	b.WriteString("UsePAM yes\n")
	b.WriteString("UseDNS no\n")
	b.WriteString("StrictModes yes\n")
	b.WriteString("MaxAuthTries 3\n")
	b.WriteString("MaxSessions 10\n")
	b.WriteString("LoginGraceTime 30\n")
	b.WriteString("ClientAliveInterval 300\n")
	b.WriteString("ClientAliveCountMax 2\n")
	b.WriteString("LogLevel VERBOSE\n")
	b.WriteString("DebianBanner no\n")

	return Artifact{
		Path: sshDropInPath, Content: []byte(b.String()), Mode: 0o644,
		Reason:  "disable root and password login, restrict forwarding, and reduce auth exposure",
		Section: "ssh", Kind: KindConfig,
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
