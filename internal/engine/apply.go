package engine

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/obscure-toolkit/obscure/internal/policy"
	"github.com/obscure-toolkit/obscure/internal/render"
	"github.com/obscure-toolkit/obscure/internal/system"
)

// ApplyResult describes a completed or rolled-back apply.
type ApplyResult struct {
	TransactionID string        `json:"transaction_id"`
	Changes       int           `json:"changes"`
	RolledBack    bool          `json:"rolled_back"`
	Checks        *VerifyResult `json:"checks,omitempty"`
	Duration      time.Duration `json:"duration"`
}

// Apply validates, snapshots, applies and verifies a plan. It rolls back on
// any failure. The caller must have confirmed the plan with the operator.
func (e *Engine) Apply(ctx context.Context, p *policy.Policy, scope Scope, timeout int, allowLockout bool, expectedFingerprint string) (*ApplyResult, error) {
	start := time.Now()
	if e.Sys.EUID() != 0 {
		return nil, fmt.Errorf("apply requires root (try: sudo doit apply)")
	}
	if err := e.ensureDirs(); err != nil {
		return nil, err
	}
	lock, err := system.AcquireLock(e.Sys.Path(filepath.Join(e.RunDir, "obscure.lock")))
	if err != nil {
		return nil, err
	}
	defer lock.Release()

	fresh, err := e.Plan(ctx, p, scope, allowLockout)
	if err != nil {
		return nil, err
	}
	if fresh.HasErrors() {
		return nil, fmt.Errorf("refusing to apply: %s", strings.Join(fresh.Errors, "; "))
	}
	if expectedFingerprint != "" && planFingerprint(fresh) != expectedFingerprint {
		return nil, fmt.Errorf("host or policy changed after the plan was displayed; re-run doit plan")
	}
	if !fresh.HasChanges() {
		return &ApplyResult{Changes: 0, Duration: time.Since(start)}, nil
	}

	if len(fresh.Packages) > 0 {
		e.logf("installing packages: %s", strings.Join(fresh.Packages, " "))
		args := append([]string{"install", "-y", "--no-install-recommends"}, fresh.Packages...)
		res := e.Sys.Runner.Run(ctx, "apt-get", args...)
		if !res.Success() {
			return nil, fmt.Errorf("apt-get install failed: %s", res.Error())
		}
	}

	if err := e.preflight(ctx, p, fresh.Desired, fresh); err != nil {
		return nil, err
	}

	dir, manifest, err := e.newTransaction(p.Digest, scope, len(fresh.Changes))
	if err != nil {
		return nil, err
	}
	manifest.Packages = append([]string{}, fresh.Packages...)
	e.logf("transaction %s", manifest.ID)
	if err := e.snapshot(ctx, p, fresh.Desired, fresh.State, scope, dir, manifest); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if err := e.writeManifest(dir, manifest); err != nil {
		return nil, err
	}

	logFile, err := os.OpenFile(e.Sys.Path(filepath.Join(dir, "apply.log")), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	oldOut := e.Out
	if oldOut == nil {
		oldOut = io.Discard
	}
	e.Out = io.MultiWriter(oldOut, logFile)
	defer func() {
		e.Out = oldOut
		logFile.Close()
	}()

	stopHeartbeat := func() {}
	if !e.NoWatchdog {
		stopHeartbeat = e.startWatchdog(ctx, dir, timeout)
	}
	committed := false
	defer func() {
		stopHeartbeat()
		if !committed {
			_ = e.markManifest(dir, manifest, "failed", "apply did not commit")
		}
	}()

	var checks *VerifyResult
	applyErr := e.execute(ctx, p, fresh, dir, manifest)
	if applyErr == nil {
		state, err := e.buildState(ctx, p, fresh.Desired, fresh.State, scope, manifest)
		if err != nil {
			applyErr = fmt.Errorf("record state: %w", err)
		} else if err := e.WriteState(state); err != nil {
			applyErr = fmt.Errorf("write state: %w", err)
		}
	}
	if applyErr == nil {
		checks, applyErr = e.Verify(ctx, p, scope)
		if applyErr != nil {
			applyErr = fmt.Errorf("verify after apply: %w", applyErr)
		} else if checks.Drift() > 0 {
			var detail []string
			for _, c := range checks.Checks {
				if c.Status == CheckDrift {
					detail = append(detail, c.Target+" ("+c.Expected+" != "+c.Actual+")")
				}
			}
			applyErr = fmt.Errorf("verification found %d drift item(s) after apply: %s", checks.Drift(), strings.Join(detail, "; "))
			fresh.Checks = checks
		}
	}
	if applyErr != nil {
		e.logf("apply failed: %v", applyErr)
		e.logf("rolling back transaction %s", manifest.ID)
		rbErr := e.RollbackTransaction(ctx, dir, "apply failed: "+applyErr.Error())
		if rbErr != nil {
			return nil, fmt.Errorf("%w (rollback also failed: %v)", applyErr, rbErr)
		}
		return &ApplyResult{TransactionID: manifest.ID, Changes: len(fresh.Changes), RolledBack: true, Duration: time.Since(start)},
			fmt.Errorf("%w; transaction rolled back", applyErr)
	}

	committed = true
	_ = e.markManifest(dir, manifest, "committed", "")
	_ = e.Sys.WriteFileRaw(filepath.Join(dir, "committed"), []byte(manifest.ID+"\n"), 0o600)
	e.logf("committed transaction %s", manifest.ID)
	return &ApplyResult{TransactionID: manifest.ID, Changes: len(fresh.Changes), Checks: checks, Duration: time.Since(start)}, nil
}

func (e *Engine) execute(ctx context.Context, p *policy.Policy, plan *Plan, dir string, manifest *Manifest) error {
	d := plan.Desired
	currentPort := p.Admin.SSHPort
	if d.SSHManaged {
		if v, ok := e.sshdEffective(ctx)["port"]; ok {
			fields := strings.Fields(v)
			if len(fields) > 0 {
				currentPort = atoiDefault(fields[0], currentPort)
			}
		}
	}

	for _, art := range d.Artifacts {
		if !inScope(art.Path, plan.Scope) {
			continue
		}
		if err := e.writeArtifact(art); err != nil {
			return err
		}
	}

	// AppArmor profiles must be loaded before the sandbox starts, and obsolete
	// profiles must be unloaded before their files disappear.
	if err := e.applyAppArmor(ctx, d, plan.State, plan.Scope); err != nil {
		return err
	}

	for _, c := range plan.Changes {
		if c.Kind != "delete-file" {
			continue
		}
		if err := e.Sys.Remove(c.Target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete %s: %w", c.Target, err)
		}
		e.logf("deleted %s", c.Target)
	}

	if len(d.Sysctls) > 0 {
		res := e.Sys.Runner.Run(ctx, "sysctl", "--system")
		if !res.Success() {
			return fmt.Errorf("sysctl --system failed: %s", res.Error())
		}
	}
	if err := e.daemonReload(ctx); err != nil {
		return err
	}

	mainNFT := findNFT(d, "inet obscure")
	sandboxNFT := findNFT(d, "inet obscure_sandbox")
	transition := false
	if d.SSHManaged && p.Exposure.SSH != policy.ExposureDisabled && p.Exposure.SSH != policy.ExposureLoopback && currentPort != p.Admin.SSHPort {
		trans, err := render.RenderFirewallTransition(p, currentPort)
		if err != nil {
			return err
		}
		if err := e.applyNFT(ctx, "inet obscure", trans.Content); err != nil {
			return err
		}
		e.logf("applied transition firewall accepting SSH on ports %d and %d", currentPort, p.Admin.SSHPort)
		transition = true
		if err := e.reloadSSH(ctx); err != nil {
			return err
		}
	}
	if mainNFT != nil {
		if err := e.applyNFT(ctx, mainNFT.Name, mainNFT.Content); err != nil {
			return err
		}
		e.logf("applied firewall table %s", mainNFT.Name)
	}
	if sandboxNFT != nil {
		if err := e.applyNFT(ctx, sandboxNFT.Name, sandboxNFT.Content); err != nil {
			return err
		}
		e.logf("applied sandbox egress table %s", sandboxNFT.Name)
	} else if plan.Scope.IsFull() {
		if err := e.deleteNFT(ctx, "inet obscure_sandbox"); err != nil {
			e.logf("note: could not delete obsolete sandbox table: %v", err)
		}
	}
	for name := range plan.State.NFT {
		if name == "inet obscure" || name == "inet obscure_sandbox" {
			continue
		}
		_ = e.deleteNFT(ctx, name)
	}
	_ = transition

	if d.SSHManaged && !transition {
		if err := e.reloadSSH(ctx); err != nil {
			return err
		}
	}
	if err := e.applyServices(ctx, p, d, plan); err != nil {
		return err
	}
	if d.AuditManaged {
		if err := e.loadAuditRules(ctx); err != nil {
			return err
		}
	}
	return nil
}

func findNFT(d *render.Desired, name string) *render.NFTTable {
	for i := range d.NFT {
		if d.NFT[i].Name == name {
			return &d.NFT[i]
		}
	}
	return nil
}

func (e *Engine) writeArtifact(art render.Artifact) error {
	info, err := e.Sys.Lstat(art.Path)
	if err == nil && info.IsDir {
		return fmt.Errorf("%s is a directory", art.Path)
	}
	if _, err := e.Sys.EnsureParentDirs(art.Path); err != nil {
		return err
	}
	if err := e.Sys.WriteFileAtomic(art.Path, art.Content, art.Mode, art.Preserve); err != nil {
		return fmt.Errorf("write %s: %w", art.Path, err)
	}
	e.logf("wrote %s", art.Path)
	return nil
}

func (e *Engine) applyNFT(ctx context.Context, table string, content []byte) error {
	if err := e.ensureNFTTable(ctx, table); err != nil {
		return err
	}
	res := e.Sys.Runner.RunInput(ctx, content, "nft", "-f", "-")
	if !res.Success() {
		return fmt.Errorf("nft -f %s: %s", table, res.Error())
	}
	return nil
}

// ensureNFTTable creates the table if it is absent. The generated rules start
// with "flush table", which only works when the table already exists; the
// flush and the new rules are then committed as one atomic nftables batch.
func (e *Engine) ensureNFTTable(ctx context.Context, table string) error {
	parts := strings.Fields(table)
	if len(parts) != 2 {
		return fmt.Errorf("invalid nft table %q", table)
	}
	if res := e.Sys.Runner.Run(ctx, "nft", "list", "table", parts[0], parts[1]); res.Success() {
		return nil
	}
	res := e.Sys.Runner.Run(ctx, "nft", "add", "table", parts[0], parts[1])
	if !res.Success() {
		return fmt.Errorf("nft add table %s: %s", table, res.Error())
	}
	return nil
}

func (e *Engine) deleteNFT(ctx context.Context, table string) error {
	parts := strings.Fields(table)
	if len(parts) != 2 {
		return fmt.Errorf("invalid table %q", table)
	}
	res := e.Sys.Runner.Run(ctx, "nft", "delete", "table", parts[0], parts[1])
	if !res.Success() {
		return fmt.Errorf("nft delete table %s: %s", table, res.Error())
	}
	return nil
}

func (e *Engine) daemonReload(ctx context.Context) error {
	res := e.Sys.Runner.Run(ctx, "systemctl", "daemon-reload")
	if !res.Success() {
		return fmt.Errorf("systemctl daemon-reload: %s", res.Error())
	}
	return nil
}

func (e *Engine) reloadSSH(ctx context.Context) error {
	bin := e.sshdBin()
	if bin == "" {
		return nil
	}
	if res := e.Sys.Runner.Run(ctx, bin, "-t"); !res.Success() {
		return fmt.Errorf("sshd -t: %s", res.Error())
	}
	name := "ssh"
	live := e.serviceState(ctx, name)
	if !live.Exists {
		name = "sshd"
		live = e.serviceState(ctx, name)
	}
	if !live.Exists || live.ActiveState != "active" {
		return nil
	}
	if res := e.Sys.Runner.Run(ctx, "systemctl", "reload", name); !res.Success() {
		return fmt.Errorf("systemctl reload %s: %s", name, res.Error())
	}
	e.logf("reloaded %s", name)
	return nil
}

func (e *Engine) loadAuditRules(ctx context.Context) error {
	if e.commandExists("augenrules") {
		res := e.Sys.Runner.Run(ctx, "augenrules", "--load")
		if res.Success() {
			return nil
		}
		// auditd may not be running yet; start it and retry once.
		_ = e.Sys.Runner.Run(ctx, "systemctl", "start", "auditd")
		res = e.Sys.Runner.Run(ctx, "augenrules", "--load")
		if !res.Success() {
			return fmt.Errorf("augenrules --load: %s", res.Error())
		}
		return nil
	}
	if e.commandExists("auditctl") {
		res := e.Sys.Runner.Run(ctx, "auditctl", "-R", auditRulesFile)
		if !res.Success() {
			return fmt.Errorf("auditctl -R: %s", res.Error())
		}
		return nil
	}
	return fmt.Errorf("neither augenrules nor auditctl is available")
}

const auditRulesFile = "/etc/audit/rules.d/90-obscure.rules"

func (e *Engine) applyAppArmor(ctx context.Context, d *render.Desired, st *State, scope Scope) error {
	if !e.commandExists("apparmor_parser") {
		for _, sb := range d.Sandboxes {
			if sb.AppArmorMode != "off" {
				return fmt.Errorf("apparmor_parser is not installed but a profile is required")
			}
		}
		return nil
	}
	desired := map[string]bool{}
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode == "off" {
			continue
		}
		desired[sb.ProfileName] = true
		res := e.Sys.Runner.Run(ctx, "apparmor_parser", "-r", sb.ProfilePath)
		if !res.Success() {
			return fmt.Errorf("apparmor_parser -r %s: %s", sb.ProfilePath, res.Error())
		}
		tool := "aa-enforce"
		if sb.AppArmorMode == "complain" {
			tool = "aa-complain"
		}
		if res := e.Sys.Runner.Run(ctx, tool, sb.ProfileName); !res.Success() {
			return fmt.Errorf("%s %s: %s", tool, sb.ProfileName, res.Error())
		}
		e.logf("loaded AppArmor profile %s (%s)", sb.ProfileName, sb.AppArmorMode)
	}
	for name := range st.AppArmor {
		if desired[name] {
			continue
		}
		path := filepath.Join("/etc/apparmor.d", name)
		if e.Sys.Exists(path) {
			res := e.Sys.Runner.Run(ctx, "apparmor_parser", "-R", path)
			if !res.Success() {
				e.logf("warning: could not unload AppArmor profile %s: %s", name, res.Error())
			}
		}
	}
	return nil
}

func (e *Engine) applyServices(ctx context.Context, p *policy.Policy, d *render.Desired, plan *Plan) error {
	desired := map[string]render.Service{}
	for _, svc := range d.Services {
		if serviceInScope(svc.Name, plan.Scope) {
			desired[svc.Name] = svc
		}
	}
	var stopFirst, startLater []render.Service
	for _, svc := range desired {
		if svc.Enable == "disabled" || svc.Enable == "masked" {
			stopFirst = append(stopFirst, svc)
		} else {
			startLater = append(startLater, svc)
		}
	}
	sort.Slice(stopFirst, func(i, j int) bool { return stopFirst[i].Name < stopFirst[j].Name })
	sort.Slice(startLater, func(i, j int) bool { return startLater[i].Name < startLater[j].Name })
	for _, svc := range stopFirst {
		if err := e.applyService(ctx, svc, plan); err != nil {
			return err
		}
	}
	// Restore services that left the policy before starting new ones.
	for name, origin := range plan.State.Services {
		if _, ok := desired[name]; ok || !serviceInScope(name, plan.Scope) {
			continue
		}
		if err := e.restoreService(ctx, name, origin); err != nil {
			return err
		}
	}
	for _, svc := range startLater {
		if err := e.applyService(ctx, svc, plan); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) applyService(ctx context.Context, svc render.Service, plan *Plan) error {
	live := e.serviceState(ctx, svc.Name)
	if !live.Exists {
		if svc.Optional || svc.Enable == "disabled" || svc.Enable == "masked" {
			return nil
		}
		return fmt.Errorf("service %s is required by policy but does not exist", svc.Name)
	}
	switch svc.Enable {
	case "masked":
		if live.UnitFileState != "masked" {
			if res := e.Sys.Runner.Run(ctx, "systemctl", "mask", svc.Name); !res.Success() {
				return fmt.Errorf("systemctl mask %s: %s", svc.Name, res.Error())
			}
		}
		if live.ActiveState == "active" {
			if res := e.Sys.Runner.Run(ctx, "systemctl", "stop", svc.Name); !res.Success() {
				return fmt.Errorf("systemctl stop %s: %s", svc.Name, res.Error())
			}
		}
	case "disabled":
		if live.UnitFileState == "masked" {
			_ = e.Sys.Runner.Run(ctx, "systemctl", "unmask", svc.Name)
		}
		if live.UnitFileState == "enabled" || live.UnitFileState == "enabled-runtime" {
			if res := e.Sys.Runner.Run(ctx, "systemctl", "disable", svc.Name); !res.Success() {
				return fmt.Errorf("systemctl disable %s: %s", svc.Name, res.Error())
			}
		}
		if live.ActiveState == "active" {
			if res := e.Sys.Runner.Run(ctx, "systemctl", "stop", svc.Name); !res.Success() {
				return fmt.Errorf("systemctl stop %s: %s", svc.Name, res.Error())
			}
		}
	case "enabled":
		if !serviceEnabled(live.UnitFileState) && serviceCanEnable(live.UnitFileState) {
			if res := e.Sys.Runner.Run(ctx, "systemctl", "enable", svc.Name); !res.Success() {
				return fmt.Errorf("systemctl enable %s: %s", svc.Name, res.Error())
			}
		}
		if svc.Active == "active" && live.ActiveState != "active" {
			if res := e.Sys.Runner.Run(ctx, "systemctl", "start", svc.Name); !res.Success() {
				return fmt.Errorf("systemctl start %s: %s", svc.Name, res.Error())
			}
		}
	}
	if svc.Restart && (restartSectionChanged(svc.Name, changedSectionsFromPlan(plan)) || live.ActiveState != "active") {
		if res := e.Sys.Runner.Run(ctx, "systemctl", "restart", svc.Name); !res.Success() {
			return fmt.Errorf("systemctl restart %s: %s", svc.Name, res.Error())
		}
	}
	if svc.Reload && changedSectionsFromPlan(plan)["ssh"] {
		if res := e.Sys.Runner.Run(ctx, "systemctl", "reload", svc.Name); !res.Success() {
			return fmt.Errorf("systemctl reload %s: %s", svc.Name, res.Error())
		}
	}
	e.logf("service %s: %s", svc.Name, svc.Enable)
	return nil
}

func changedSectionsFromPlan(plan *Plan) map[string]bool {
	out := map[string]bool{}
	for _, c := range plan.Changes {
		if c.Kind == "file" || c.Kind == "delete-file" {
			switch {
			case c.Target == "/etc/ssh/sshd_config.d/00-obscure.conf":
				out["ssh"] = true
			case strings.Contains(c.Target, "journald") || strings.Contains(c.Target, "resolved"):
				out["privacy"] = true
			case strings.HasPrefix(c.Target, "/etc/obscure/sandbox/"):
				out["sandbox"] = true
			}
		}
	}
	return out
}

func (e *Engine) restoreService(ctx context.Context, name string, origin ServiceOrigin) error {
	if origin.Masked {
		_ = e.Sys.Runner.Run(ctx, "systemctl", "mask", name)
	} else {
		_ = e.Sys.Runner.Run(ctx, "systemctl", "unmask", name)
	}
	switch origin.Enabled {
	case "enabled", "enabled-runtime":
		_ = e.Sys.Runner.Run(ctx, "systemctl", "enable", name)
	case "disabled":
		_ = e.Sys.Runner.Run(ctx, "systemctl", "disable", name)
	}
	if origin.Active {
		_ = e.Sys.Runner.Run(ctx, "systemctl", "start", name)
	} else {
		_ = e.Sys.Runner.Run(ctx, "systemctl", "stop", name)
	}
	return nil
}

func (e *Engine) preflight(ctx context.Context, p *policy.Policy, d *render.Desired, plan *Plan) error {
	required := []string{"nft", "systemctl"}
	if d.SSHManaged && e.sshdBin() == "" {
		return fmt.Errorf("sshd is required by policy but was not found")
	}
	if len(d.Sysctls) > 0 {
		required = append(required, "sysctl")
	}
	if d.AuditManaged {
		if !e.commandExists("augenrules") && !e.commandExists("auditctl") {
			return fmt.Errorf("auditd is required by policy but augenrules/auditctl are missing")
		}
	}
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode != "off" {
			required = append(required, "apparmor_parser", "aa-enforce", "aa-complain")
		}
	}
	for _, name := range required {
		if !e.commandExists(name) {
			return fmt.Errorf("required command %q is not installed", name)
		}
	}
	for _, table := range d.NFT {
		if err := e.nftCheck(ctx, table); err != nil {
			return err
		}
	}
	if d.SSHManaged {
		if bin := e.sshdBin(); bin == "" {
			return fmt.Errorf("sshd is required by policy but was not found")
		} else if res := e.Sys.Runner.Run(ctx, bin, "-t"); !res.Success() {
			return fmt.Errorf("current sshd configuration is invalid: %s", res.Error())
		}
		sshArt := findArtifact(d, "/etc/ssh/sshd_config.d/00-obscure.conf")
		if sshArt != nil {
			path, err := e.tempFile("preflight-sshd.conf", sshArt.Content)
			if err != nil {
				return err
			}
			defer e.Sys.Remove(path)
			if res := e.Sys.Runner.Run(ctx, e.sshdBin(), "-t", "-f", path); !res.Success() {
				return fmt.Errorf("generated sshd configuration is invalid: %s", res.Error())
			}
		}
	}
	if e.commandExists("systemd-analyze") {
		for _, art := range d.Artifacts {
			if art.Kind != render.KindUnit {
				continue
			}
			path, err := e.tempFile("preflight-"+sanitize(filepath.Base(art.Path)), art.Content)
			if err != nil {
				return err
			}
			res := e.Sys.Runner.Run(ctx, "systemd-analyze", "verify", path)
			e.Sys.Remove(path)
			if !res.Success() {
				return fmt.Errorf("systemd-analyze verify %s: %s", art.Path, res.Error())
			}
		}
	}
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode == "off" {
			continue
		}
		path, err := e.tempFile("preflight-"+sb.ProfileName, sb.ProfileContent)
		if err != nil {
			return err
		}
		res := e.Sys.Runner.Run(ctx, "apparmor_parser", "-Q", path)
		e.Sys.Remove(path)
		if !res.Success() {
			return fmt.Errorf("AppArmor profile for %s is invalid: %s", sb.Name, res.Error())
		}
	}
	if len(plan.Packages) > 0 && !e.commandExists("apt-get") {
		return fmt.Errorf("apt-get is required to install %s", strings.Join(plan.Packages, ", "))
	}
	return nil
}

// nftCheck validates the generated rules without depending on the live table.
// "flush table" is removed and the table is renamed to a scratch name, so the
// check works on a first apply and never touches the real firewall.
func (e *Engine) nftCheck(ctx context.Context, table render.NFTTable) error {
	parts := strings.Fields(table.Name)
	if len(parts) != 2 {
		return fmt.Errorf("invalid nft table %q", table.Name)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(table.Content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "flush table ") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	scratch := "obscure_validate"
	content := strings.ReplaceAll(b.String(), "table "+parts[0]+" "+parts[1], "table "+parts[0]+" "+scratch)
	path, err := e.tempFile("preflight-"+sanitize(strings.ReplaceAll(table.Name, " ", "-"))+".nft", []byte(content))
	if err != nil {
		return err
	}
	defer e.Sys.Remove(path)
	res := e.Sys.Runner.Run(ctx, "nft", "-c", "-f", path)
	if !res.Success() {
		return fmt.Errorf("nftables rules for %s are invalid: %s", table.Name, res.Error())
	}
	return nil
}

func (e *Engine) tempFile(name string, content []byte) (string, error) {
	if err := e.Sys.MkdirAll(e.RunDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(e.RunDir, name)
	if err := e.Sys.WriteFileRaw(path, content, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func findArtifact(d *render.Desired, path string) *render.Artifact {
	for i := range d.Artifacts {
		if d.Artifacts[i].Path == path {
			return &d.Artifacts[i]
		}
	}
	return nil
}

func (e *Engine) buildState(ctx context.Context, p *policy.Policy, d *render.Desired, old *State, scope Scope, m *Manifest) (*State, error) {
	next := newState()
	if !scope.IsFull() {
		next = &State{
			Version: stateVersion, PolicyPath: old.PolicyPath, PolicyHash: old.PolicyHash,
			Files: map[string]string{}, AppArmor: map[string]string{},
			Services: map[string]ServiceOrigin{}, NFT: map[string]string{},
			Sandboxes: append([]string{}, old.Sandboxes...),
		}
		for path, hash := range old.Files {
			if !inScope(path, scope) {
				next.Files[path] = hash
			}
		}
		for name, origin := range old.Services {
			if !serviceInScope(name, scope) {
				next.Services[name] = origin
			}
		}
		for name, hash := range old.AppArmor {
			if !strings.HasPrefix(name, "obscure-") {
				next.AppArmor[name] = hash
			}
		}
		for name, hash := range old.NFT {
			if !tableNameInScope(name, scope) {
				next.NFT[name] = hash
			}
		}
	}
	origins := map[string]ServiceOrigin{}
	for _, snap := range m.Services {
		origins[snap.Name] = snap.Origin
	}
	for _, art := range d.Artifacts {
		if !inScope(art.Path, scope) {
			continue
		}
		next.Files[art.Path] = system.SHA256(art.Content)
		if art.Kind == render.KindUnit {
			next.Units = append(next.Units, art.Path)
		}
	}
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode == "off" {
			continue
		}
		next.AppArmor[sb.ProfileName] = system.SHA256(sb.ProfileContent)
	}
	for _, svc := range d.Services {
		if !serviceInScope(svc.Name, scope) {
			continue
		}
		if oldOrigin, ok := old.Services[svc.Name]; ok {
			next.Services[svc.Name] = oldOrigin
		} else if origin, ok := origins[svc.Name]; ok {
			next.Services[svc.Name] = origin
		} else {
			next.Services[svc.Name] = ServiceOrigin{}
		}
	}
	for _, table := range d.NFT {
		if !tableInScope(table, scope) {
			continue
		}
		hash, err := e.nftCanonical(ctx, table.Name)
		if err != nil {
			return nil, fmt.Errorf("record nft state for %s: %w", table.Name, err)
		}
		next.NFT[table.Name] = hash
	}
	names := map[string]bool{}
	for _, n := range next.Sandboxes {
		names[n] = true
	}
	for _, sb := range d.Sandboxes {
		names[sb.Name] = true
	}
	next.Sandboxes = nil
	for n := range names {
		next.Sandboxes = append(next.Sandboxes, n)
	}
	sort.Strings(next.Sandboxes)
	next.Units = dedupeStrings(next.Units)
	next.LastApply = e.Sys.Now()
	next.LastScope = scope.Kind
	if scope.Sandbox != "" {
		next.LastScope += ":" + scope.Sandbox
	}
	next.Transaction = m.ID
	next.PolicyPath = p.Path
	if scope.IsFull() {
		next.PolicyHash = p.Digest
	}
	return next, nil
}

func (e *Engine) logf(format string, args ...any) {
	if e.Out != nil {
		fmt.Fprintf(e.Out, format+"\n", args...)
	}
}

func (e *Engine) markManifest(dir string, m *Manifest, status, reason string) error {
	m.Status = status
	m.Reason = reason
	return e.writeManifest(dir, m)
}
