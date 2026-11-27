package render

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/obscure-toolkit/obscure/internal/policy"
)

func example(t *testing.T) *policy.Policy {
	t.Helper()
	data, err := os.ReadFile("../../examples/web-server.toml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func defaultOpts() Options {
	return Options{
		SSHDInstalled: true, AppArmorEnabled: true,
		SeccompSupported: true, LandlockABI: 5,
		SysctlExists:     func(string) bool { return true },
		PathExists:       func(string) bool { return true },
		PackageInstalled: func(string) bool { return true },
		UserID:           func(string) (int, bool) { return 1234, true },
	}
}

func findArtifact(d *Desired, path string) *Artifact {
	for i := range d.Artifacts {
		if d.Artifacts[i].Path == path {
			return &d.Artifacts[i]
		}
	}
	return nil
}

func findService(d *Desired, name string) *Service {
	for i := range d.Services {
		if d.Services[i].Name == name {
			return &d.Services[i]
		}
	}
	return nil
}

func TestRenderExample(t *testing.T) {
	d, err := Render(example(t), defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	nft := string(d.NFT[0].Content)
	for _, want := range []string{
		"policy drop;",
		"iifname \"eth0\" tcp dport 443 accept",
		"ip saddr @admin_v4 tcp dport 22 accept",
		"203.0.113.0/24",
		"ct state established,related accept",
		"icmpv6 type",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("firewall missing %q:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "tcp dport 25") {
		t.Error("smtp should be disabled by default")
	}
	ssh := findArtifact(d, sshDropInPath)
	if ssh == nil {
		t.Fatal("missing ssh drop-in")
	}
	sshText := string(ssh.Content)
	for _, want := range []string{"PermitRootLogin no", "PasswordAuthentication no", "AuthenticationMethods publickey", "Port 22"} {
		if !strings.Contains(sshText, want) {
			t.Errorf("sshd missing %q", want)
		}
	}
	if findArtifact(d, sysctlPath) == nil {
		t.Error("missing sysctl baseline")
	}
	if findArtifact(d, resolvedPath) == nil {
		t.Error("missing resolved config")
	}
	if findArtifact(d, auditRulesPath) == nil {
		t.Error("missing audit rules")
	}
	if findArtifact(d, unattendedPath) == nil {
		t.Error("missing unattended-upgrades config")
	}
	if findArtifact(d, journaldPath) == nil {
		t.Error("missing journald config")
	}
	if len(d.Sandboxes) != 1 {
		t.Fatalf("sandboxes = %d", len(d.Sandboxes))
	}
	sb := d.Sandboxes[0]
	if sb.AppArmorMode != "enforce" {
		t.Errorf("apparmor mode = %q", sb.AppArmorMode)
	}
	if sb.Landlock {
		t.Error("Landlock should not be layered on AppArmor by default")
	}
	unit := string(sb.UnitContent)
	for _, want := range []string{
		"User=myapp",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/myapp",
		"ReadOnlyPaths=/etc/myapp",
		"AppArmorProfile=obscure-myapp",
		"NoNewPrivileges=yes",
		"SystemCallFilter=@system-service",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q:\n%s", want, unit)
		}
	}
	if strings.Contains(unit, "IPAddressDeny=any") {
		t.Error("outbound-https must not block all egress in the unit")
	}
	snft := string(d.NFT[1].Content)
	for _, want := range []string{
		"meta skuid 1234",
		"th dport 53 accept",
		"th dport 443 accept",
		"drop comment",
	} {
		if !strings.Contains(snft, want) {
			t.Errorf("sandbox firewall missing %q:\n%s", want, snft)
		}
	}
	profile := string(sb.ProfileContent)
	for _, want := range []string{
		"profile obscure-myapp /usr/local/bin/myapp",
		"/var/lib/myapp/** rwlk",
		"/etc/myapp/** r",
		"deny /etc/shadow r",
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing %q:\n%s", want, profile)
		}
	}
	if svc := findService(d, "popularity-contest"); svc == nil || svc.Enable != "masked" {
		t.Errorf("telemetry service not masked: %+v", svc)
	}
	if svc := findService(d, "nginx"); svc == nil || svc.Enable != "enabled" {
		t.Errorf("nginx not enabled: %+v", svc)
	}
	if svc := findService(d, "postfix"); svc == nil || svc.Enable != "disabled" {
		t.Errorf("postfix not disabled: %+v", svc)
	}
	if svc := findService(d, "ssh"); svc == nil || !svc.Reload {
		t.Errorf("ssh reload missing: %+v", svc)
	}
	for _, pkg := range []string{"nftables", "openssh-server", "auditd", "unattended-upgrades", "systemd-resolved", "apparmor-utils"} {
		found := false
		for _, got := range d.Packages {
			if got == pkg {
				found = true
			}
		}
		if !found {
			t.Errorf("package %s missing from %v", pkg, d.Packages)
		}
	}
}

func TestDisabledSSHHasNoAcceptRule(t *testing.T) {
	p, err := policy.Parse([]byte(`
role = "workstation"
[exposure]
https = "loopback"
`))
	if err != nil {
		t.Fatal(err)
	}
	opts := defaultOpts()
	opts.SSHDInstalled = false
	d, err := Render(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	nft := string(d.NFT[0].Content)
	if strings.Contains(nft, "tcp dport 22") {
		t.Errorf("disabled ssh still accepted:\n%s", nft)
	}
	if d.SSHManaged {
		t.Error("SSH should not be managed when disabled and absent")
	}
}

func TestLandlockFallback(t *testing.T) {
	p := example(t)
	opts := defaultOpts()
	opts.AppArmorEnabled = false
	opts.LandlockABI = 6
	d, err := Render(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	sb := d.Sandboxes[0]
	if sb.AppArmorMode != "off" {
		t.Fatalf("apparmor mode = %q", sb.AppArmorMode)
	}
	if !sb.Landlock {
		t.Fatal("Landlock should be used when AppArmor is unavailable")
	}
	unit := string(sb.UnitContent)
	if !strings.Contains(unit, "sandbox-run --config /etc/obscure/sandbox/myapp.json") {
		t.Errorf("unit missing Landlock wrapper:\n%s", unit)
	}
	if sb.ProfileContent != nil {
		t.Error("profile rendered while AppArmor is off")
	}
}

func TestRenderDeterministic(t *testing.T) {
	p := example(t)
	a, err := Render(p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Artifacts) != len(b.Artifacts) {
		t.Fatal("artifact count differs")
	}
	for i := range a.Artifacts {
		if a.Artifacts[i].Path != b.Artifacts[i].Path || !bytes.Equal(a.Artifacts[i].Content, b.Artifacts[i].Content) {
			t.Fatalf("artifact %d is not deterministic", i)
		}
	}
}

func TestNoSandboxNoSandboxTable(t *testing.T) {
	p, err := policy.Parse([]byte(`
role = "custom"
public_interface = "eth0"
[exposure]
https = "public"
[admin]
source_cidrs = ["203.0.113.0/24"]
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Render(p, defaultOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.NFT) != 1 {
		t.Fatalf("NFT tables = %d, want 1", len(d.NFT))
	}
}
