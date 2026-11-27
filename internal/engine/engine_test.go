package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
	"github.com/obsidian-toolkit/obsidian/internal/system"
)

type fakeUnit struct {
	exists  bool
	enabled string
	active  bool
	masked  bool
}

type fakeRunner struct {
	mu      sync.Mutex
	root    string
	units   map[string]*fakeUnit
	nft     map[string]string
	nftSeen map[string]bool
}

func newFakeRunner(root string) *fakeRunner {
	return &fakeRunner{root: root, units: map[string]*fakeUnit{}, nft: map[string]string{}, nftSeen: map[string]bool{}}
}

func (f *fakeRunner) ok(out string) system.Result {
	return system.Result{Stdout: []byte(out), ExitCode: 0}
}

func (f *fakeRunner) fail(msg string) system.Result {
	return system.Result{Stderr: []byte("" + msg), ExitCode: 1, Err: fmt.Errorf("%s", msg)}
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	switch name {
	case "nft", "systemctl", "sshd", "sysctl", "dpkg-query", "ss", "auditctl",
		"augenrules", "aa-status", "aa-enforce", "aa-complain", "apparmor_parser",
		"systemd-analyze", "apt-get", "ip":
		return "/usr/bin/" + name, nil
	}
	return "", fmt.Errorf("%s: not found", name)
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) system.Result {
	return f.RunInput(ctx, nil, name, args...)
}

func (f *fakeRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) system.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch name {
	case "systemctl":
		return f.systemctl(args)
	case "nft":
		return f.nftCmd(input, args)
	case "sshd":
		if len(args) > 0 && args[0] == "-T" {
			return f.ok("port 22\npermitrootlogin no\npubkeyauthentication yes\npermitemptypasswords no\npasswordauthentication no\nkbdinteractiveauthentication no\nallowtcpforwarding no\nallowagentforwarding no\nx11forwarding no\npermituserenvironment no\nmaxauthtries 3\nmaxsessions 10\nlogingracetime 30\nclientaliveinterval 300\nclientalivecountmax 2\nusedns no\n")
		}
		return f.ok("")
	case "dpkg-query":
		return f.ok("install ok installed")
	case "sysctl":
		return f.ok("")
	case "auditctl":
		if len(args) > 0 && args[0] == "-s" {
			return f.ok("enabled 1\n")
		}
		return f.ok("-w /etc/passwd -p wa\n-w /etc/shadow -p wa\n-w /etc/sudoers -p wa\n-w /etc/obsidian/ -p wa\n")
	case "augenrules", "apparmor_parser", "systemd-analyze", "apt-get", "aa-enforce", "aa-complain":
		return f.ok("")
	case "aa-status":
		return f.ok(`{"profiles":{}}`)
	case "ss":
		return f.ok("")
	case "ip":
		return f.ok("")
	}
	return f.fail("unexpected command " + name)
}

func (f *fakeRunner) systemctl(args []string) system.Result {
	if len(args) == 0 {
		return f.fail("systemctl: no args")
	}
	switch args[0] {
	case "show":
		unit := args[len(args)-1]
		u := f.unit(unit)
		load, enabled, active := "not-found", "", "inactive"
		if u.exists {
			load = "loaded"
			enabled = u.enabled
			if enabled == "" {
				enabled = "disabled"
			}
			if u.masked {
				enabled = "masked"
			}
			if u.active {
				active = "active"
			}
		}
		return f.ok("LoadState=" + load + "\nUnitFileState=" + enabled + "\nActiveState=" + active + "\n")
	case "daemon-reload":
		f.scanUnits()
		return f.ok("")
	case "enable", "reenable":
		u := f.unit(args[1])
		u.exists = true
		u.enabled = "enabled"
		return f.ok("")
	case "disable":
		u := f.unit(args[1])
		u.enabled = "disabled"
		return f.ok("")
	case "mask":
		u := f.unit(args[1])
		u.exists = true
		u.masked = true
		return f.ok("")
	case "unmask":
		u := f.unit(args[1])
		u.masked = false
		return f.ok("")
	case "start", "restart":
		u := f.unit(args[1])
		u.exists = true
		u.active = true
		return f.ok("")
	case "stop":
		u := f.unit(args[1])
		u.active = false
		return f.ok("")
	case "reload":
		return f.ok("")
	}
	return f.fail("systemctl " + strings.Join(args, " "))
}

func (f *fakeRunner) unit(name string) *fakeUnit {
	if !strings.Contains(name, ".") {
		name += ".service"
	}
	u, ok := f.units[name]
	if !ok {
		u = &fakeUnit{}
		f.units[name] = u
	}
	return u
}

func (f *fakeRunner) scanUnits() {
	entries, err := os.ReadDir(filepath.Join(f.root, "etc/systemd/system"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".service") {
			continue
		}
		u := f.unit(entry.Name())
		u.exists = true
	}
}

func (f *fakeRunner) nftCmd(input []byte, args []string) system.Result {
	if len(args) == 0 {
		return f.fail("nft: no args")
	}
	switch args[0] {
	case "-c":
		return f.ok("")
	case "-j":
		// nft -j list table FAMILY NAME
		if len(args) >= 5 && args[1] == "list" && args[2] == "table" {
			table := args[3] + " " + args[4]
			if !f.nftSeen[table] {
				return f.fail("no such table " + table)
			}
			payload := map[string]any{"nftables": []any{
				map[string]any{"table": map[string]any{"family": args[3], "name": args[4]}},
			}}
			data, _ := json.Marshal(payload)
			return f.ok(string(data))
		}
		return f.fail("nft -j: unsupported " + strings.Join(args, " "))
	case "-f":
		table := tableFromRules(string(input))
		if table == "" {
			return f.fail("cannot determine table from rules")
		}
		f.nft[table] = string(input)
		f.nftSeen[table] = true
		return f.ok("")
	case "add":
		if len(args) >= 4 && args[1] == "table" {
			f.nftSeen[args[2]+" "+args[3]] = true
			return f.ok("")
		}
		return f.ok("")
	case "delete":
		if len(args) >= 4 && args[1] == "table" {
			table := args[2] + " " + args[3]
			delete(f.nft, table)
			delete(f.nftSeen, table)
			return f.ok("")
		}
		return f.ok("")
	case "list":
		jsonOut := false
		idx := 1
		if args[1] == "-j" {
			jsonOut = true
			idx = 2
		}
		if len(args) < idx+3 || args[idx] != "table" {
			return f.fail("nft list: unsupported")
		}
		table := args[idx+1] + " " + args[idx+2]
		if !f.nftSeen[table] {
			return f.fail("no such table " + table)
		}
		if jsonOut {
			// Debug: print what we're returning
			payload := map[string]any{"nftables": []any{
				map[string]any{"table": map[string]any{"family": args[idx+1], "name": args[idx+2]}},
			}}
			data, _ := json.Marshal(payload)
			// Debug removed
			return f.ok(string(data))
		}
		if f.nft[table] == "" {
			return f.ok("table " + table + " {\n}\n")
		}
		return f.ok(f.nft[table])
	}
	return f.fail("nft " + strings.Join(args, " "))
}

func tableFromRules(rules string) string {
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "flush" && fields[1] == "table" {
			return fields[2] + " " + fields[3]
		}
		if len(fields) >= 3 && fields[0] == "table" {
			return fields[1] + " " + strings.TrimSuffix(fields[2], "{")
		}
	}
	return ""
}

func newTestEngine(t *testing.T) (*Engine, *fakeRunner, *policy.Policy) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc/systemd/system", "proc/sys", "var", "run", "usr/sbin", "usr/local/bin"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fake := newFakeRunner(root)
	for name, state := range map[string]*fakeUnit{
		"nginx.service":            {exists: true, enabled: "enabled", active: true},
		"postfix.service":          {exists: true, enabled: "disabled"},
		"systemd-journald.service": {exists: true, enabled: "static", active: true},
	} {
		fake.units[name] = state
	}
	sys := system.New()
	sys.Root = root
	sys.Runner = fake
	sys.EUIDFn = func() int { return 0 }
	sys.EnvFn = func(string) string { return "" }
	sys.AncestorCommsFn = func(int) ([]string, error) { return nil, nil }
	sys.InterfaceExistsFn = func(string) (bool, error) { return true, nil }
	sys.AppArmorEnabledFn = func() bool { return false }
	sys.CgroupV2Fn = func() bool { return true }
	sys.SeccompSupportedFn = func() bool { return true }
	sys.LandlockABIFn = func() int { return 0 }

	eng := &Engine{
		Sys: sys, StateDir: "/var/lib/obsidian", RunDir: "/run/obsidian",
		Out: os.Stderr, Err: os.Stderr, NoWatchdog: true,
	}
	pol := parseTestPolicy(t)
	eng.ConfigPath = pol.Path
	return eng, fake, pol
}

func parseTestPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	data := []byte(`
role = "web-server"
public_interface = "eth0"

[exposure]
https = "public"
ssh = "disabled"

[privacy]
telemetry = "deny"
dns = "system"
log_retention_days = 7

[services]
nginx = "enabled"
postfix = "disabled"

[updates]
unattended = false

[audit]
enabled = false
`)
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	p.Path = path
	p.Digest = system.SHA256(data)
	return p
}

func TestPlanApplyVerifyRollback(t *testing.T) {
	ctx := context.Background()
	eng, fake, p := newTestEngine(t)

	plan, err := eng.Plan(ctx, p, FullScope(), false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HasErrors() {
		t.Fatalf("plan errors: %v", plan.Errors)
	}
	if !plan.HasChanges() {
		t.Fatal("expected changes on first plan")
	}
	if plan.Lockout.Risky {
		t.Fatal("local session must not be treated as a lockout risk")
	}
	if !hasChange(plan, "file", "/etc/obsidian/firewall.nft") {
		t.Fatalf("missing firewall file change: %+v", plan.Changes)
	}
	if !hasChange(plan, "nft", "inet obsidian") {
		t.Fatalf("missing nft change: %+v", plan.Changes)
	}

	result, err := eng.Apply(ctx, p, FullScope(), 120, false, plan.Fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if result.RolledBack {
		t.Fatal("apply unexpectedly rolled back")
	}
	if result.Checks == nil || result.Checks.Drift() != 0 {
		t.Fatalf("post-apply drift: %+v", result.Checks)
	}
	for _, path := range []string{"/etc/obsidian/firewall.nft", "/etc/systemd/system/obsidian-firewall.service"} {
		if !eng.Sys.Exists(path) {
			t.Fatalf("expected %s to exist", path)
		}
	}
	if !fake.units["obsidian-firewall.service"].active {
		t.Fatal("firewall service was not started")
	}

	verify, err := eng.Verify(ctx, p, FullScope())
	if err != nil {
		t.Fatal(err)
	}
	if verify.Drift() != 0 {
		t.Fatalf("verify drift: %+v", verify.Checks)
	}

	// Tampering must show up as drift and as a planned repair.
	tampered := filepath.Join(eng.Sys.Root, "etc/obsidian/firewall.nft")
	if err := os.WriteFile(tampered, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verify, err = eng.Verify(ctx, p, FullScope())
	if err != nil {
		t.Fatal(err)
	}
	if verify.Drift() == 0 {
		t.Fatal("expected drift after tampering")
	}
	plan, err = eng.Plan(ctx, p, FullScope(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChange(plan, "file", "/etc/obsidian/firewall.nft") {
		t.Fatal("expected the tampered file to be repaired")
	}

	m, err := eng.Rollback(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != "rolled-back" {
		t.Fatalf("manifest status = %q", m.Status)
	}
	if eng.Sys.Exists("/etc/obsidian/firewall.nft") {
		t.Fatal("rollback should remove a file that did not exist before apply")
	}
	if eng.Sys.Exists("/etc/systemd/system/obsidian-firewall.service") {
		t.Fatal("rollback should remove the generated unit")
	}
	if eng.Sys.Exists(eng.StatePath()) {
		t.Fatal("rollback should restore the absent state file")
	}
}

func hasChange(p *Plan, kind, target string) bool {
	for _, c := range p.Changes {
		if c.Kind == kind && c.Target == target {
			return true
		}
	}
	return false
}

func TestLockoutRefusedWithoutFlag(t *testing.T) {
	ctx := context.Background()
	eng, _, p := newTestEngine(t)
	// Pretend the operator is connected over SSH from an address that is not
	// in admin.source_cidrs.
	eng.Sys.EnvFn = func(name string) string {
		if name == "SSH_CONNECTION" {
			return "198.51.100.9 40000 203.0.113.10 22"
		}
		return ""
	}
	p.Exposure.SSH = policy.ExposureAdminOnly
	p.Admin.SourceCIDRs = []string{"203.0.113.0/24"}
	p.Digest = system.SHA256([]byte("lockout"))

	plan, err := eng.Plan(ctx, p, FullScope(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Lockout.Risky {
		t.Fatalf("expected lockout risk, got %+v", plan.Lockout)
	}
	if !plan.HasErrors() {
		t.Fatal("lockout without --allow-lockout must be an error")
	}

	allowed, err := eng.Plan(ctx, p, FullScope(), true)
	if err != nil {
		t.Fatal(err)
	}
	if allowed.HasErrors() {
		t.Fatalf("--allow-lockout should permit the plan: %v", allowed.Errors)
	}
}
