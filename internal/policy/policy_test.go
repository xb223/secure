package policy

import (
	"os"
	"strings"
	"testing"
)

func TestParseExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/web-server.toml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Role != RoleWebServer {
		t.Fatalf("role = %q", p.Role)
	}
	if p.Admin.SSHPort != 22 || p.Admin.RootLogin != "no" {
		t.Fatalf("admin defaults not applied: %+v", p.Admin)
	}
	if p.Privacy.Telemetry != "deny" || p.Privacy.LogRetentionDays != 14 {
		t.Fatalf("privacy defaults: %+v", p.Privacy)
	}
	if !p.Unattended() || !p.AuditEnabled() || !p.SysctlEnabled() {
		t.Fatal("default feature switches should be on")
	}
	if got := p.AdminInterfaces(); len(got) != 1 || got[0] != "eth0" {
		t.Fatalf("AdminInterfaces = %v", got)
	}
	if len(p.Sandbox) != 1 || p.Sandbox["myapp"].Network != "outbound-https" {
		t.Fatalf("sandbox = %+v", p.Sandbox)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := Parse([]byte(`
role = "web-server"
public_interface = "eth0"
[exposure]
https = "public"
ssh = "admin-only"
[admin]
source_cidrs = ["203.0.113.0/24"]
typo_here = true
`))
	if err == nil || !strings.Contains(err.Error(), "unknown policy key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestUnknownNestedKeyRejected(t *testing.T) {
	_, err := Parse([]byte(`
role = "custom"
[sandbox.app]
binary = "/bin/true"
run_as = "nobody"
nope = 1
`))
	if err == nil || !strings.Contains(err.Error(), "unknown policy key") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestAdminOnlyNeedsCIDRs(t *testing.T) {
	_, err := Parse([]byte(`
role = "web-server"
public_interface = "eth0"
[exposure]
ssh = "admin-only"
`))
	if err == nil || !strings.Contains(err.Error(), "source_cidrs") {
		t.Fatalf("expected source_cidrs error, got %v", err)
	}
}

func TestBadCIDR(t *testing.T) {
	_, err := Parse([]byte(`
role = "web-server"
public_interface = "eth0"
[exposure]
ssh = "admin-only"
[admin]
source_cidrs = ["203.0.113.0/99"]
`))
	if err == nil || !strings.Contains(err.Error(), "source_cidrs") {
		t.Fatalf("expected CIDR error, got %v", err)
	}
}

func TestExposureValidation(t *testing.T) {
	_, err := Parse([]byte(`
role = "web-server"
public_interface = "eth0"
[exposure]
https = "everyone"
`))
	if err == nil || !strings.Contains(err.Error(), "exposure.https") {
		t.Fatalf("expected exposure error, got %v", err)
	}
}

func TestWarnings(t *testing.T) {
	p, err := Parse([]byte(`
role = "web-server"
public_interface = "eth0"
[exposure]
https = "public"
ssh = "public"
[admin]
password_auth = true
[privacy]
telemetry = "allow"
`))
	if err != nil {
		t.Fatal(err)
	}
	warnings := p.Warnings()
	joined := ""
	for _, w := range warnings {
		joined += w.String() + "\n"
	}
	for _, want := range []string{"password_auth", "SSH is exposed", "telemetry is allowed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in:\n%s", want, joined)
		}
	}
}

func TestSandboxPathRefused(t *testing.T) {
	_, err := Parse([]byte(`
role = "custom"
[sandbox.app]
binary = "/bin/true"
run_as = "nobody"
read_write = ["/"]
`))
	if err == nil || !strings.Contains(err.Error(), "whole filesystem") {
		t.Fatalf("expected filesystem refusal, got %v", err)
	}
}

func TestDNSValidation(t *testing.T) {
	_, err := Parse([]byte(`
role = "custom"
[privacy]
dns = "local-resolver"
dns_servers = ["not-an-ip#example.com"]
`))
	if err == nil || !strings.Contains(err.Error(), "dns_servers") {
		t.Fatalf("expected DNS server error, got %v", err)
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	_, err := Parse([]byte(`
role = "custom"
role = "web-server"
`))
	if err == nil {
		t.Fatal("duplicate key accepted")
	}
}
