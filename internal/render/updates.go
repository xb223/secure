package render

import (
	"fmt"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
)

const unattendedPath = "/etc/apt/apt.conf.d/52obsidian-unattended"

func renderUnattended(p *policy.Policy) Artifact {
	var b strings.Builder
	b.WriteString(header("unattended-upgrades"))
	b.WriteString("// Install only Debian security updates; never replace administrator policy.\n")
	b.WriteString(`APT::Periodic::Update-Package-Lists "1";` + "\n")
	b.WriteString(`APT::Periodic::Unattended-Upgrade "1";` + "\n")
	b.WriteString(`APT::Periodic::AutocleanInterval "7";` + "\n")
	b.WriteString(`Unattended-Upgrade::Origins-Pattern {` + "\n")
	b.WriteString(`  "origin=Debian,codename=${distro_codename},label=Debian-Security";` + "\n")
	b.WriteString(`  "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";` + "\n")
	b.WriteString("};\n")
	b.WriteString(`Unattended-Upgrade::Package-Blacklist {};` + "\n")
	b.WriteString(`Unattended-Upgrade::AutoFixInterruptedDpkg "true";` + "\n")
	b.WriteString(`Unattended-Upgrade::MinimalSteps "true";` + "\n")
	b.WriteString(`Unattended-Upgrade::Remove-Unused-Dependencies "true";` + "\n")
	b.WriteString(`Unattended-Upgrade::Remove-New-Unused-Dependencies "true";` + "\n")
	b.WriteString(`Unattended-Upgrade::SyslogEnable "true";` + "\n")
	if p.Updates.AutoReboot {
		b.WriteString(`Unattended-Upgrade::Automatic-Reboot "true";` + "\n")
		fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot-Time %q;\n", p.Updates.RebootTime)
	} else {
		b.WriteString(`Unattended-Upgrade::Automatic-Reboot "false";` + "\n")
	}
	return Artifact{
		Path: unattendedPath, Content: []byte(b.String()), Mode: 0o644,
		Reason:  "automatic Debian security updates without automatic reboots",
		Section: "updates", Kind: KindConfig,
	}
}
