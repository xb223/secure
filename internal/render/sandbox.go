package render

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/policy"
	"github.com/obscure-toolkit/obscure/internal/sandbox"
)

const (
	sandboxDir     = "/etc/obscure/sandbox"
	sandboxUnitDir = "/etc/systemd/system"
	appArmorDir    = "/etc/apparmor.d"
	obscureBin    = "/usr/local/bin/obscure"
)

var implicitReadOnly = []string{
	"/usr",
	"/lib",
	"/lib64",
	"/bin",
	"/sbin",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/pki",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/passwd",
	"/etc/group",
	"/etc/gai.conf",
	"/etc/services",
	"/etc/protocols",
	"/etc/localtime",
	"/run/systemd/resolve",
}

func renderSandbox(p *policy.Policy, name string, sb policy.Sandbox, opts Options, d *Desired) (Sandbox, error) {
	profileName := "obscure-" + name
	unitName := "obscure-" + name + ".service"
	unitPath := sandboxUnitDir + "/" + unitName
	configPath := sandboxDir + "/" + name + ".json"
	profilePath := appArmorDir + "/" + profileName

	out := Sandbox{
		Name: name, UnitName: unitName, UnitPath: unitPath,
		ConfigPath: configPath, ProfilePath: profilePath, ProfileName: profileName,
		Network: sb.Network,
		Reason:  "isolate " + name + " with systemd sandboxing",
	}

	appArmorMode := sb.AppArmor
	if appArmorMode == "auto" {
		if opts.AppArmorEnabled {
			appArmorMode = "enforce"
		} else {
			appArmorMode = "off"
		}
	}
	if appArmorMode != "off" && !opts.AppArmorEnabled {
		out.AppArmorUnsupported = true
		d.Warnings = append(d.Warnings, policy.Warning{
			Field:   "sandbox." + name + ".apparmor",
			Message: "AppArmor is not enabled; the requested profile cannot be enforced",
		})
		appArmorMode = "off"
	}
	out.AppArmorMode = appArmorMode

	landlock := false
	switch sb.Landlock {
	case "on":
		if opts.LandlockABI > 0 && appArmorMode == "off" {
			landlock = true
		} else if opts.LandlockABI == 0 {
			out.LandlockUnsupported = true
			d.Warnings = append(d.Warnings, policy.Warning{
				Field:   "sandbox." + name + ".landlock",
				Message: "the kernel does not support Landlock; filesystem rules will be omitted",
			})
		} else if appArmorMode != "off" {
			d.Notes = append(d.Notes, fmt.Sprintf("sandbox.%s: AppArmor is active, so Landlock is not layered on top", name))
		}
	case "auto":
		if opts.LandlockABI > 0 && appArmorMode == "off" {
			landlock = true
		}
	}
	out.Landlock = landlock

	if !opts.SeccompSupported {
		out.SeccompUnsupported = true
	}

	if appArmorMode != "off" {
		out.ProfileContent = []byte(renderAppArmorProfile(name, sb, appArmorMode))
	}

	cfg := sandbox.Config{
		Name: name, Binary: sb.Binary, Args: sb.Args,
		ReadWrite: sb.ReadWrite, ReadOnly: sb.ReadOnly,
		ImplicitReadOnly: implicitReadOnly,
	}
	cfgData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Sandbox{}, err
	}
	cfgData = append(cfgData, '\n')
	out.ConfigJSON = cfgData
	out.UnitContent = []byte(renderSandboxUnit(name, sb, out))

	return out, nil
}

func sandboxArtifacts(sb Sandbox) []Artifact {
	out := []Artifact{
		{Path: sb.UnitPath, Content: sb.UnitContent, Mode: 0o644, Reason: sb.Reason, Section: "sandbox." + sb.Name, Kind: KindUnit},
		{Path: sb.ConfigPath, Content: sb.ConfigJSON, Mode: 0o644, Reason: "sandbox runtime configuration for " + sb.Name, Section: "sandbox." + sb.Name, Kind: KindConfig},
	}
	if sb.AppArmorMode != "off" {
		out = append(out, Artifact{
			Path: sb.ProfilePath, Content: sb.ProfileContent, Mode: 0o644, Mutable: true,
			Reason:  "AppArmor " + sb.AppArmorMode + " profile for " + sb.Name,
			Section: "sandbox." + sb.Name, Kind: KindAppArmor,
		})
	}
	return out
}

func renderSandboxUnit(name string, sb policy.Sandbox, out Sandbox) string {
	var b strings.Builder
	b.WriteString(header("sandbox " + name))
	b.WriteString("[Unit]\n")
	fmt.Fprintf(&b, "Description=obscure sandbox: %s\n", name)
	if sb.Network != "none" {
		b.WriteString("After=network-online.target\nWants=network-online.target\n")
	}
	b.WriteString("StartLimitIntervalSec=60\nStartLimitBurst=5\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "User=%s\n", sb.RunAs)
	if sb.Group != "" {
		fmt.Fprintf(&b, "Group=%s\n", sb.Group)
	}
	if out.Landlock {
		fmt.Fprintf(&b, "ExecStart=%s sandbox-run --config %s\n", unitArg(obscureBin), unitArg(out.ConfigPath))
	} else {
		parts := []string{unitArg(sb.Binary)}
		for _, a := range sb.Args {
			parts = append(parts, unitArg(a))
		}
		fmt.Fprintf(&b, "ExecStart=%s\n", strings.Join(parts, " "))
	}
	b.WriteString("WorkingDirectory=/\n")
	switch sb.Restart {
	case "always":
		b.WriteString("Restart=always\n")
	case "on-failure":
		b.WriteString("Restart=on-failure\n")
	default:
		b.WriteString("Restart=no\n")
	}
	b.WriteString("RestartSec=2s\n")
	b.WriteString("UMask=0077\n")
	b.WriteString("StandardOutput=journal\nStandardError=journal\n")
	fmt.Fprintf(&b, "SyslogIdentifier=obscure-%s\n", name)
	b.WriteString("\n# Process hardening\n")
	b.WriteString("NoNewPrivileges=yes\n")
	b.WriteString("PrivateTmp=yes\n")
	b.WriteString("PrivateDevices=yes\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=yes\n")
	b.WriteString("ProtectKernelTunables=yes\n")
	b.WriteString("ProtectKernelModules=yes\n")
	b.WriteString("ProtectKernelLogs=yes\n")
	b.WriteString("ProtectControlGroups=yes\n")
	b.WriteString("ProtectClock=yes\n")
	b.WriteString("ProtectHostname=yes\n")
	b.WriteString("ProtectProc=invisible\n")
	b.WriteString("ProcSubset=pid\n")
	b.WriteString("RestrictNamespaces=yes\n")
	b.WriteString("RestrictRealtime=yes\n")
	b.WriteString("RestrictSUIDSGID=yes\n")
	b.WriteString("LockPersonality=yes\n")
	b.WriteString("MemoryDenyWriteExecute=yes\n")
	b.WriteString("SystemCallArchitectures=native\n")
	if !out.SeccompUnsupported && sb.SyscallFilter != "none" {
		fmt.Fprintf(&b, "SystemCallFilter=%s\n", sb.SyscallFilter)
		b.WriteString("SystemCallErrorNumber=EPERM\n")
	}
	b.WriteString("CapabilityBoundingSet=\n")
	b.WriteString("AmbientCapabilities=\n")
	b.WriteString("DevicePolicy=closed\n")

	b.WriteString("\n# Network isolation\n")
	{
		switch sb.Network {
		case "none":
			b.WriteString("RestrictAddressFamilies=AF_UNIX\n")
			b.WriteString("IPAddressDeny=any\n")
		case "loopback":
			b.WriteString("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n")
			b.WriteString("IPAddressDeny=any\n")
			b.WriteString("IPAddressAllow=localhost\n")
		default:
			b.WriteString("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n")
		}
	}
	if out.AppArmorMode != "off" {
		fmt.Fprintf(&b, "AppArmorProfile=%s\n", out.ProfileName)
	}

	b.WriteString("\n# Filesystem\n")
	if len(sb.ReadWrite) > 0 {
		fmt.Fprintf(&b, "ReadWritePaths=%s\n", strings.Join(quoteUnitPaths(sb.ReadWrite), " "))
	}
	if len(sb.ReadOnly) > 0 {
		fmt.Fprintf(&b, "ReadOnlyPaths=%s\n", strings.Join(quoteUnitPaths(sb.ReadOnly), " "))
	}
	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

func quoteUnitPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, unitArg(p))
	}
	return out
}

func unitArg(s string) string {
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	if strings.ContainsAny(s, " \t\"'\\") {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return `"` + s + `"`
	}
	return s
}

func renderAppArmorProfile(name string, sb policy.Sandbox, mode string) string {
	var b strings.Builder
	b.WriteString(header("apparmor " + name))
	b.WriteString("#include <tunables/global>\n\n")
	flags := "attach_disconnected,mediate_deleted"
	if mode == "complain" {
		flags += ",complain"
	}
	fmt.Fprintf(&b, "profile %s %s flags=(%s) {\n", "obscure-"+name, sb.Binary, flags)
	b.WriteString("  #include <abstractions/base>\n")
	b.WriteString("  #include <abstractions/nameservice>\n")
	b.WriteString("  #include <abstractions/ssl_certs>\n\n")
	switch sb.Network {
	case "none":
		b.WriteString("  network unix stream,\n  network unix dgram,\n")
	default:
		b.WriteString("  network inet stream,\n  network inet dgram,\n")
		b.WriteString("  network inet6 stream,\n  network inet6 dgram,\n")
	}
	fmt.Fprintf(&b, "\n  %s mr,\n", sb.Binary)
	for _, path := range implicitReadOnly {
		fmt.Fprintf(&b, "  %s r,\n  %s/** r,\n", path, path)
	}
	b.WriteString("  /run/systemd/resolve/ r,\n  /run/systemd/resolve/** r,\n")
	b.WriteString("  /tmp/ rw,\n  /tmp/** rw,\n")
	b.WriteString("  /dev/null rw,\n  /dev/zero rw,\n  /dev/urandom r,\n  /dev/random r,\n")
	for _, path := range sb.ReadOnly {
		fmt.Fprintf(&b, "  %s r,\n  %s/** r,\n", path, path)
	}
	for _, path := range sb.ReadWrite {
		fmt.Fprintf(&b, "  %s rwlk,\n  %s/** rwlk,\n", path, path)
	}
	b.WriteString("\n  # Explicitly deny secrets even if a broad abstraction would allow them.\n")
	b.WriteString("  deny /etc/shadow r,\n  deny /etc/shadow- r,\n  deny /etc/gshadow r,\n  deny /etc/gshadow- r,\n")
	b.WriteString("  deny /etc/sudoers r,\n  deny /etc/sudoers.d/** r,\n")
	b.WriteString("  deny /root/** r,\n  deny /home/** r,\n")
	b.WriteString("}\n")
	return b.String()
}
