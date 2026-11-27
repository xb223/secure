package render

import (
	"fmt"
	"runtime"
	"strings"
)

const auditRulesPath = "/etc/audit/rules.d/90-obscure.rules"

func renderAuditRules(pathExists func(string) bool) Artifact {
	var b strings.Builder
	b.WriteString(header("auditd"))
	b.WriteString("# Loaded with augenrules --load. Rules are additive to the distribution\n")
	b.WriteString("# baseline; this file does not start with -D.\n")
	b.WriteString("-b 8192\n")
	b.WriteString("--backlog_wait_time 60000\n")
	b.WriteString("-f 1\n")
	b.WriteString("\n# Identity and privilege databases\n")
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers"} {
		fmt.Fprintf(&b, "-w %s -p wa -k identity\n", path)
	}
	for _, path := range []string{"/etc/sudoers.d/", "/etc/ssh/sshd_config.d/", "/etc/sysctl.d/", "/etc/apt/apt.conf.d/"} {
		if pathExists != nil && !pathExists(path) {
			continue
		}
		fmt.Fprintf(&b, "-w %s -p wa -k config-change\n", path)
	}
	// /etc/obscure is created by obscure before audit rules are loaded.
	b.WriteString("-w /etc/obscure/ -p wa -k config-change\n")
	if pathExists == nil || pathExists("/etc/ssh/sshd_config") {
		b.WriteString("-w /etc/ssh/sshd_config -p wa -k sshd-config\n")
	}
	if pathExists == nil || pathExists("/etc/apparmor.d/") {
		b.WriteString("-w /etc/apparmor.d/ -p wa -k apparmor-config\n")
	}
	b.WriteString("\n# Privilege and namespace changes\n")
	for _, arch := range auditArchitectures() {
		fmt.Fprintf(&b, "-a always,exit -F arch=%s -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid>=1000 -F auid!=unset -k privilege-change\n", arch)
		fmt.Fprintf(&b, "-a always,exit -F arch=%s -S mount,umount2 -k mount\n", arch)
		fmt.Fprintf(&b, "-a always,exit -F arch=%s -S init_module,finit_module,delete_module -k kernel-module\n", arch)
		fmt.Fprintf(&b, "-a always,exit -F arch=%s -S sethostname,setdomainname -k hostname\n", arch)
		fmt.Fprintf(&b, "-a always,exit -F arch=%s -S ptrace -k ptrace\n", arch)
		fmt.Fprintf(&b, "-a always,exit -F arch=%s -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root-exec\n", arch)
	}
	b.WriteString("\n# Enable auditing without making the rules immutable.\n")
	b.WriteString("-e 1\n")
	return Artifact{
		Path: auditRulesPath, Content: []byte(b.String()), Mode: 0o640,
		Reason:  "audit identity, privilege, mount, module and root command activity",
		Section: "audit", Kind: KindConfig,
	}
}

func auditArchitectures() []string {
	if runtime.GOARCH == "amd64" {
		return []string{"b64", "b32"}
	}
	return []string{"b64"}
}
