package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/policy"
	"github.com/obscure-toolkit/obscure/internal/render"
	"github.com/obscure-toolkit/obscure/internal/system"
	"github.com/obscure-toolkit/obscure/internal/textdiff"
)

const (
	orderPackage  = 10
	orderFile     = 20
	orderAppArmor = 30
	orderSysctl   = 40
	orderAudit    = 50
	orderNFT      = 60
	orderService  = 70
	orderSSH      = 80
	orderState    = 90
)

// Plan computes changes without modifying the host.
func (e *Engine) Plan(ctx context.Context, p *policy.Policy, scope Scope, allowLockout bool) (*Plan, error) {
	st, err := e.LoadState()
	if err != nil {
		return nil, err
	}
	d, err := e.BuildDesired(ctx, p)
	if err != nil {
		return nil, err
	}
	if !scope.IsFull() {
		if scope.Sandbox != "" {
			if _, ok := p.Sandbox[scope.Sandbox]; !ok {
				return nil, fmt.Errorf("sandbox %q is not in the policy", scope.Sandbox)
			}
		}
		d = FilterDesired(d, scope)
	}
	plan := &Plan{
		Policy: p, Desired: d, State: st, Scope: scope,
		PolicyPath: p.Path, PolicyHash: p.Digest, Generated: e.Sys.Now(),
		Warnings: append([]policy.Warning{}, d.Warnings...),
	}
	if e.Strict {
		for _, w := range plan.Warnings {
			plan.Errors = append(plan.Errors, "strict: "+w.String())
		}
	}

	desiredPaths := map[string]render.Artifact{}
	for _, art := range d.Artifacts {
		desiredPaths[art.Path] = art
	}
	changedSections := map[string]bool{}

	for _, art := range d.Artifacts {
		if !inScope(art.Path, scope) {
			continue
		}
		change, warn, err := e.planFile(art)
		if err != nil {
			plan.Errors = append(plan.Errors, err.Error())
			continue
		}
		if warn != "" {
			plan.Warnings = append(plan.Warnings, policy.Warning{Field: art.Path, Message: warn})
		}
		if change != nil {
			plan.Changes = append(plan.Changes, *change)
			changedSections[art.Section] = true
		}
	}

	// Orphaned files from earlier applies.
	for path, hash := range st.Files {
		if _, ok := desiredPaths[path]; ok {
			continue
		}
		if !inScope(path, scope) {
			continue
		}
		if !e.Sys.Exists(path) {
			continue
		}
		current, err := e.Sys.SHA256File(path)
		if err != nil {
			plan.Warnings = append(plan.Warnings, policy.Warning{Field: path, Message: "cannot read obsolete managed file: " + err.Error()})
			continue
		}
		if current != hash {
			plan.Warnings = append(plan.Warnings, policy.Warning{Field: path, Message: "file was modified after obscure created it; leaving it in place"})
			continue
		}
		plan.Changes = append(plan.Changes, Change{
			Order: orderFile, Kind: "delete-file", Target: path, Action: "delete",
			Reason: "no longer managed by the policy", Risk: RiskSafe,
		})
	}

	planServices(ctx, e, p, d, st, changedSections, plan)
	planPackages(ctx, e, d, plan)
	planSysctls(e, d, changedSections, plan)
	planNFT(ctx, e, p, d, st, scope, plan)
	planAppArmor(ctx, e, d, changedSections, plan)
	planAudit(ctx, e, d, changedSections, plan)
	planSSH(ctx, e, p, d, changedSections, plan)

	if scope.IsFull() && st.PolicyHash != p.Digest {
		plan.Changes = append(plan.Changes, Change{
			Order: orderState, Kind: "state", Target: e.StatePath(), Action: "record",
			Reason: "record the applied policy digest", Risk: RiskSafe,
		})
	}

	plan.Lockout = e.assessLockout(ctx, p, d, plan.Changes, allowLockout)
	if plan.Lockout.Risky {
		for i := range plan.Changes {
			if changeAffectsSSH(plan.Changes[i]) {
				plan.Changes[i].Risk = RiskLockout
			}
		}
		if !allowLockout {
			plan.Errors = append(plan.Errors, "SSH lockout risk: "+strings.Join(plan.Lockout.Reasons, "; ")+" (re-run with --allow-lockout if this is intended)")
		}
	}
	sort.SliceStable(plan.Changes, func(i, j int) bool {
		if plan.Changes[i].Order != plan.Changes[j].Order {
			return plan.Changes[i].Order < plan.Changes[j].Order
		}
		return plan.Changes[i].Target < plan.Changes[j].Target
	})
	return plan, nil
}

func changeAffectsSSH(c Change) bool {
	if c.Kind == "ssh" {
		return true
	}
	if c.Kind == "nft" && c.Target == "inet obscure" {
		return true
	}
	if c.Kind == "service" && (c.Target == "ssh" || c.Target == "sshd") {
		return true
	}
	if c.Target == "/etc/ssh/sshd_config.d/00-obscure.conf" {
		return true
	}
	return false
}

func (e *Engine) planFile(art render.Artifact) (*Change, string, error) {
	info, err := e.Sys.Lstat(art.Path)
	if err != nil {
		if !e.Sys.Exists(art.Path) {
			return &Change{
				Order: orderFile, Kind: "file", Target: art.Path, Action: "create",
				Reason: art.Reason, Risk: fileRisk(art), Diff: textdiff.Unified(art.Path, "", string(art.Content)),
			}, "", nil
		}
		return nil, "", fmt.Errorf("stat %s: %w", art.Path, err)
	}
	if info.IsDir {
		return nil, "", fmt.Errorf("%s is a directory but the policy needs a file", art.Path)
	}
	if info.IsSymlink {
		return &Change{
			Order: orderFile, Kind: "file", Target: art.Path, Action: "replace symlink",
			Reason: art.Reason, Risk: fileRisk(art), Old: "symlink -> " + info.LinkTarget,
			Diff: textdiff.Unified(art.Path, "", string(art.Content)),
		}, "", nil
	}
	current, err := e.Sys.ReadFile(art.Path)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", art.Path, err)
	}
	contentSame := art.Mutable || system.SHA256(current) == system.SHA256(art.Content)
	modeSame := info.Mode.Perm() == art.Mode.Perm()
	if contentSame && modeSame {
		return nil, "", nil
	}
	action := "update"
	if contentSame {
		action = "update mode"
	}
	warn := ""
	if !contentSame && !strings.Contains(string(current), "Managed by obscure") && len(current) > 0 {
		warn = "existing file was not created by obscure and will be replaced (a snapshot is kept)"
	}
	return &Change{
		Order: orderFile, Kind: "file", Target: art.Path, Action: action,
		Reason: art.Reason, Risk: fileRisk(art),
		Diff: textdiff.Unified(art.Path, string(current), string(art.Content)),
	}, warn, nil
}

func fileRisk(art render.Artifact) string {
	switch art.Kind {
	case render.KindAppArmor:
		return RiskAttention
	case render.KindNFT:
		return RiskAttention
	}
	if strings.HasPrefix(art.Path, "/etc/ssh/") {
		return RiskAttention
	}
	return RiskSafe
}

func inScope(path string, scope Scope) bool {
	if scope.IsFull() {
		return true
	}
	if strings.HasPrefix(path, "/etc/obscure/sandbox/") || path == "/etc/obscure/sandbox.nft" {
		return true
	}
	if strings.HasPrefix(path, "/etc/apparmor.d/obscure-") {
		return scope.Sandbox == "" || path == "/etc/apparmor.d/obscure-"+scope.Sandbox
	}
	if strings.HasPrefix(path, "/etc/systemd/system/obscure-") {
		if path == "/etc/systemd/system/obscure-firewall.service" {
			return false
		}
		if path == "/etc/systemd/system/obscure-sandbox-firewall.service" {
			return true
		}
		return scope.Sandbox == "" || path == "/etc/systemd/system/obscure-"+scope.Sandbox+".service"
	}
	return false
}

func planServices(ctx context.Context, e *Engine, p *policy.Policy, d *render.Desired, st *State, changedSections map[string]bool, plan *Plan) {
	desired := map[string]render.Service{}
	for _, svc := range d.Services {
		desired[svc.Name] = svc
	}
	newUnits := map[string]bool{}
	for _, art := range d.Artifacts {
		if art.Kind == render.KindUnit {
			newUnits[path.Base(art.Path)] = true
		}
	}
	for _, svc := range d.Services {
		if !serviceInScope(svc.Name, plan.Scope) {
			continue
		}
		live := e.serviceState(ctx, svc.Name)
		if !live.Exists && newUnits[svc.Name] {
			// The unit file is part of this same transaction, so systemd has
			// not loaded it yet. Plan the enable/start as if it were absent.
			if svc.Enable == "enabled" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "enable and start",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: "not loaded", New: "enabled/active",
				})
			}
			continue
		}
		if !live.Exists {
			switch {
			case svc.Optional, svc.Enable == "disabled", svc.Enable == "masked":
				continue
			case svc.Enable == "enabled" || svc.Active == "active":
				plan.Errors = append(plan.Errors, fmt.Sprintf("service %s is required by policy but its unit does not exist", svc.Name))
			}
			continue
		}
		if svc.Enable == "enabled" {
			if !serviceEnabled(live.UnitFileState) {
				if serviceCanEnable(live.UnitFileState) {
					plan.Changes = append(plan.Changes, Change{
						Order: orderService, Kind: "service", Target: svc.Name, Action: "enable",
						Reason: svc.Reason, Risk: serviceRisk(svc), Old: live.UnitFileState, New: "enabled",
					})
				} else {
					plan.Warnings = append(plan.Warnings, policy.Warning{Field: "service " + svc.Name, Message: "unit is " + live.UnitFileState + " and cannot be enabled; it will be started if needed"})
				}
			}
			if svc.Active == "active" && live.ActiveState != "active" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "start",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: live.ActiveState, New: "active",
				})
			}
		}
		if svc.Enable == "disabled" {
			if live.UnitFileState == "masked" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "unmask and disable",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: "masked", New: "disabled",
				})
			} else if live.UnitFileState == "enabled" || live.UnitFileState == "enabled-runtime" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "disable",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: live.UnitFileState, New: "disabled",
				})
			}
			if live.ActiveState == "active" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "stop",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: "active", New: "inactive",
				})
			}
		}
		if svc.Enable == "masked" {
			if live.UnitFileState != "masked" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "mask",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: live.UnitFileState, New: "masked",
				})
			}
			if live.ActiveState == "active" {
				plan.Changes = append(plan.Changes, Change{
					Order: orderService, Kind: "service", Target: svc.Name, Action: "stop",
					Reason: svc.Reason, Risk: serviceRisk(svc), Old: "active", New: "inactive",
				})
			}
		}
		if svc.Restart && (restartSectionChanged(svc.Name, changedSections) || live.ActiveState != "active") {
			plan.Changes = append(plan.Changes, Change{
				Order: orderService, Kind: "service", Target: svc.Name, Action: "restart",
				Reason: svc.Reason, Risk: serviceRisk(svc),
			})
		}
		if svc.Reload && (changedSections["ssh"] || live.ActiveState != "active") {
			plan.Changes = append(plan.Changes, Change{
				Order: orderService, Kind: "service", Target: svc.Name, Action: "reload",
				Reason: svc.Reason, Risk: serviceRisk(svc),
			})
		}
	}
	// Services obscure used to manage but the policy no longer mentions.
	for name, origin := range st.Services {
		if _, ok := desired[name]; ok || !serviceInScope(name, plan.Scope) {
			continue
		}
		live := e.serviceState(ctx, name)
		if serviceMatches(live, origin) {
			continue
		}
		plan.Changes = append(plan.Changes, Change{
			Order: orderService, Kind: "service", Target: name, Action: "restore original state",
			Reason: "service is no longer managed by the policy", Risk: RiskAttention,
			Old: live.UnitFileState + "/" + live.ActiveState, New: origin.Enabled + "/" + activeWord(origin.Active),
		})
	}
}

func activeWord(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

func restartSectionChanged(name string, changed map[string]bool) bool {
	switch name {
	case "systemd-resolved":
		return changed["privacy"]
	case "systemd-journald":
		return changed["privacy"]
	case "ssh":
		return changed["ssh"]
	}
	return false
}

func serviceRisk(svc render.Service) string {
	if svc.Critical {
		return RiskAttention
	}
	return RiskSafe
}

func serviceInScope(name string, scope Scope) bool {
	if scope.IsFull() {
		return true
	}
	if name == "obscure-sandbox-firewall.service" {
		return true
	}
	if strings.HasPrefix(name, "obscure-") && name != "obscure-firewall.service" {
		return scope.Sandbox == "" || name == "obscure-"+scope.Sandbox+".service"
	}
	return false
}

func planPackages(ctx context.Context, e *Engine, d *render.Desired, plan *Plan) {
	if _, err := e.Sys.Runner.LookPath("dpkg-query"); err != nil {
		plan.Warnings = append(plan.Warnings, policy.Warning{Field: "packages", Message: "dpkg-query is unavailable; package state cannot be checked"})
		return
	}
	for _, pkg := range d.Packages {
		installed, known := e.packageInstalled(ctx, pkg)
		if !known {
			plan.Warnings = append(plan.Warnings, policy.Warning{Field: "packages", Message: "cannot query package " + pkg})
			continue
		}
		if installed {
			continue
		}
		if e.NoPackages {
			plan.Errors = append(plan.Errors, fmt.Sprintf("package %s is missing and --no-packages was used", pkg))
			continue
		}
		plan.Packages = append(plan.Packages, pkg)
		plan.Changes = append(plan.Changes, Change{
			Order: orderPackage, Kind: "package", Target: pkg, Action: "install",
			Reason: "required by the policy", Risk: RiskAttention,
		})
	}
}

func planSysctls(e *Engine, d *render.Desired, changedSections map[string]bool, plan *Plan) {
	if len(d.Sysctls) == 0 {
		return
	}
	var mismatched []string
	for _, s := range d.Sysctls {
		current := e.currentSysctl(s.Key)
		if current != "" && current != s.Value {
			mismatched = append(mismatched, fmt.Sprintf("%s=%s (want %s)", s.Key, current, s.Value))
		}
	}
	if len(mismatched) > 0 || changedSections["hardening"] {
		reason := "apply the kernel and network hardening baseline"
		if len(mismatched) > 0 {
			reason = "live values differ: " + strings.Join(mismatched, ", ")
		}
		plan.Changes = append(plan.Changes, Change{
			Order: orderSysctl, Kind: "sysctl", Target: "/proc/sys", Action: "apply",
			Reason: reason, Risk: RiskSafe,
		})
	}
}

func planNFT(ctx context.Context, e *Engine, p *policy.Policy, d *render.Desired, st *State, scope Scope, plan *Plan) {
	for _, table := range d.NFT {
		if !tableInScope(table, scope) {
			continue
		}
		expected := ""
		if st.PolicyHash == p.Digest {
			expected = st.NFT[table.Name]
		}
		if expected == "" {
			plan.Changes = append(plan.Changes, Change{
				Order: orderNFT, Kind: "nft", Target: table.Name, Action: "apply",
				Reason: table.Reason, Risk: RiskAttention,
			})
			continue
		}
		live, err := e.nftCanonical(ctx, table.Name)
		if err != nil || live != expected {
			plan.Changes = append(plan.Changes, Change{
				Order: orderNFT, Kind: "nft", Target: table.Name, Action: "apply",
				Reason: table.Reason, Risk: RiskAttention,
			})
		}
	}
	for name := range st.NFT {
		found := false
		for _, table := range d.NFT {
			if table.Name == name {
				found = true
			}
		}
		if found || !tableNameInScope(name, scope) {
			continue
		}
		plan.Changes = append(plan.Changes, Change{
			Order: orderNFT, Kind: "nft", Target: name, Action: "delete",
			Reason: "table is no longer managed by the policy", Risk: RiskAttention,
		})
	}
}

func tableInScope(table render.NFTTable, scope Scope) bool {
	if scope.IsFull() {
		return true
	}
	return table.Sandbox
}

func tableNameInScope(name string, scope Scope) bool {
	if scope.IsFull() {
		return true
	}
	return name == "inet obscure_sandbox"
}

func planAppArmor(ctx context.Context, e *Engine, d *render.Desired, changedSections map[string]bool, plan *Plan) {
	modes, err := e.appArmorModes(ctx)
	if err != nil {
		for _, sb := range d.Sandboxes {
			if sb.AppArmorMode == "enforce" || sb.AppArmorMode == "complain" {
				plan.Warnings = append(plan.Warnings, policy.Warning{Field: "apparmor", Message: "cannot read AppArmor status: " + err.Error()})
			}
		}
		return
	}
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode == "off" {
			continue
		}
		if changedSections["sandbox."+sb.Name] {
			plan.Changes = append(plan.Changes, Change{
				Order: orderAppArmor, Kind: "apparmor", Target: sb.ProfileName, Action: "load and " + sb.AppArmorMode,
				Reason: "apply the generated AppArmor profile", Risk: RiskAttention,
			})
			continue
		}
		if modes[sb.ProfileName] != sb.AppArmorMode {
			plan.Changes = append(plan.Changes, Change{
				Order: orderAppArmor, Kind: "apparmor", Target: sb.ProfileName, Action: "load and " + sb.AppArmorMode,
				Reason: "profile mode is " + orUnknown(modes[sb.ProfileName]) + ", policy wants " + sb.AppArmorMode, Risk: RiskAttention,
			})
		}
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "not loaded"
	}
	return s
}

func (e *Engine) appArmorModes(ctx context.Context) (map[string]string, error) {
	res := e.Sys.Runner.Run(ctx, "aa-status", "--json")
	if !res.Success() {
		return nil, fmt.Errorf("%s", res.Error())
	}
	var payload struct {
		Profiles map[string]any `json:"profiles"`
	}
	if err := json.Unmarshal(res.Stdout, &payload); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for name, value := range payload.Profiles {
		switch v := value.(type) {
		case string:
			out[name] = v
		case map[string]any:
			if mode, ok := v["mode"].(string); ok {
				out[name] = mode
			}
		}
	}
	return out, nil
}

func planAudit(ctx context.Context, e *Engine, d *render.Desired, changedSections map[string]bool, plan *Plan) {
	if !d.AuditManaged {
		return
	}
	if changedSections["audit"] {
		plan.Changes = append(plan.Changes, Change{
			Order: orderAudit, Kind: "audit", Target: "/etc/audit/rules.d/90-obscure.rules", Action: "load",
			Reason: "apply the audit baseline", Risk: RiskAttention,
		})
		return
	}
	res := e.Sys.Runner.Run(ctx, "auditctl", "-l")
	if !res.Success() {
		plan.Warnings = append(plan.Warnings, policy.Warning{Field: "audit", Message: "cannot read loaded audit rules: " + res.Error()})
		return
	}
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/obscure"} {
		if !strings.Contains(string(res.Stdout), path) {
			plan.Changes = append(plan.Changes, Change{
				Order: orderAudit, Kind: "audit", Target: "/etc/audit/rules.d/90-obscure.rules", Action: "load",
				Reason: "loaded audit rules are missing a watch on " + path, Risk: RiskAttention,
			})
			return
		}
	}
}

func planSSH(ctx context.Context, e *Engine, p *policy.Policy, d *render.Desired, changedSections map[string]bool, plan *Plan) {
	if !d.SSHManaged {
		return
	}
	effective := e.sshdEffective(ctx)
	if len(effective) == 0 {
		plan.Warnings = append(plan.Warnings, policy.Warning{Field: "ssh", Message: "cannot read effective sshd configuration; run as root to verify it"})
		return
	}
	var mismatches []string
	for key, want := range sshDesired(p) {
		if effective[key] != want {
			mismatches = append(mismatches, fmt.Sprintf("%s=%s (want %s)", key, orUnknown(effective[key]), want))
		}
	}
	if len(mismatches) == 0 && !changedSections["ssh"] {
		return
	}
	reloadPlanned := false
	for _, c := range plan.Changes {
		if c.Kind == "service" && (c.Target == "ssh" || c.Target == "sshd") && c.Action == "reload" {
			reloadPlanned = true
		}
	}
	if !reloadPlanned {
		reason := "effective sshd settings differ: " + strings.Join(mismatches, ", ")
		if changedSections["ssh"] {
			reason = "the managed sshd drop-in changed; reload without dropping sessions"
		}
		plan.Changes = append(plan.Changes, Change{
			Order: orderSSH, Kind: "ssh", Target: "sshd", Action: "reload",
			Reason: reason, Risk: RiskAttention,
		})
	}
}

func sshDesired(p *policy.Policy) map[string]string {
	m := map[string]string{
		"port":                         fmt.Sprintf("%d", p.Admin.SSHPort),
		"permitrootlogin":              p.Admin.RootLogin,
		"pubkeyauthentication":         "yes",
		"permitemptypasswords":         "no",
		"passwordauthentication":       yesNo(p.Admin.PasswordAuth),
		"kbdinteractiveauthentication": yesNo(p.Admin.PasswordAuth),
		"allowtcpforwarding":           yesNo(p.Admin.AllowTCPForwarding),
		"allowagentforwarding":         "no",
		"x11forwarding":                "no",
		"permituserenvironment":        "no",
		"maxauthtries":                 "3",
		"maxsessions":                  "10",
		"logingracetime":               "30",
		"clientaliveinterval":          "300",
		"clientalivecountmax":          "2",
		"usedns":                       "no",
	}
	return m
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func sandboxStateFiles(st *State, scope Scope) []string {
	var out []string
	for path := range st.Files {
		if inScope(path, scope) {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}
