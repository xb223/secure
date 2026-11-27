package engine

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
	"github.com/obsidian-toolkit/obsidian/internal/render"
	"github.com/obsidian-toolkit/obsidian/internal/system"
)

// Verify compares the live host to policy without changing anything.
func (e *Engine) Verify(ctx context.Context, p *policy.Policy, scope Scope) (*VerifyResult, error) {
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
	res := &VerifyResult{
		PolicyPath: p.Path, PolicyHash: p.Digest, Scope: scope,
		CheckedAt: e.Sys.Now(), Warnings: append([]policy.Warning{}, d.Warnings...),
	}
	add := func(c Check) { res.Checks = append(res.Checks, c) }

	if scope.IsFull() {
		switch {
		case st.PolicyHash == "":
			add(Check{ID: "state:policy", Section: "state", Target: "state", Status: CheckDrift,
				Expected: "an applied policy", Actual: "never applied", Detail: "run obsidian apply"})
		case st.PolicyHash != p.Digest:
			add(Check{ID: "state:policy", Section: "state", Target: "state", Status: CheckDrift,
				Expected: p.Digest, Actual: st.PolicyHash, Detail: "policy changed since the last apply"})
		default:
			add(Check{ID: "state:policy", Section: "state", Target: "state", Status: CheckOK})
		}
	}

	desiredPaths := map[string]render.Artifact{}
	for _, art := range d.Artifacts {
		if !inScope(art.Path, scope) {
			continue
		}
		desiredPaths[art.Path] = art
		info, err := e.Sys.Lstat(art.Path)
		if err != nil {
			if !e.Sys.Exists(art.Path) {
				add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckDrift,
					Expected: "present", Actual: "missing", Detail: art.Reason})
				continue
			}
			add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckWarn,
				Expected: "readable", Actual: err.Error()})
			continue
		}
		if info.IsSymlink {
			add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckDrift,
				Expected: "regular file", Actual: "symlink -> " + info.LinkTarget})
			continue
		}
		data, err := e.Sys.ReadFile(art.Path)
		if err != nil {
			add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckDrift,
				Expected: "readable", Actual: err.Error()})
			continue
		}
		if !art.Mutable && system.SHA256(data) != system.SHA256(art.Content) {
			add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckDrift,
				Expected: "content matching policy", Actual: "modified", Detail: art.Reason})
			continue
		}
		if info.Mode.Perm() != art.Mode.Perm() {
			add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckDrift,
				Expected: fmt.Sprintf("%04o", art.Mode.Perm()), Actual: fmt.Sprintf("%04o", info.Mode.Perm())})
			continue
		}
		add(Check{ID: "file:" + art.Path, Section: "file", Target: art.Path, Status: CheckOK})
	}
	for path, hash := range st.Files {
		if _, ok := desiredPaths[path]; ok || !inScope(path, scope) || !e.Sys.Exists(path) {
			continue
		}
		current, err := e.Sys.SHA256File(path)
		if err != nil {
			continue
		}
		if current == hash {
			add(Check{ID: "orphan:" + path, Section: "file", Target: path, Status: CheckDrift,
				Expected: "absent", Actual: "obsolete managed file still present"})
		} else {
			add(Check{ID: "orphan:" + path, Section: "file", Target: path, Status: CheckWarn,
				Expected: "absent", Actual: "modified file left in place"})
		}
	}

	desiredServices := map[string]render.Service{}
	for _, svc := range d.Services {
		if !serviceInScope(svc.Name, scope) {
			continue
		}
		desiredServices[svc.Name] = svc
		e.verifyService(ctx, svc, add)
	}
	for name, origin := range st.Services {
		if _, ok := desiredServices[name]; ok || !serviceInScope(name, scope) {
			continue
		}
		live := e.serviceState(ctx, name)
		if serviceMatches(live, origin) {
			add(Check{ID: "service:" + name, Section: "service", Target: name, Status: CheckOK})
		} else {
			add(Check{ID: "service:" + name, Section: "service", Target: name, Status: CheckDrift,
				Expected: origin.Enabled + "/" + activeWord(origin.Active), Actual: live.UnitFileState + "/" + live.ActiveState,
				Detail: "service left the policy but its original state was not restored"})
		}
	}

	e.verifyNFT(ctx, p, d, st, scope, add)
	e.verifySysctls(d, add)
	e.verifySSH(ctx, p, d, add)
	e.verifyAppArmor(ctx, d, st, add)
	e.verifyAudit(ctx, d, add)
	e.verifyPackages(ctx, d, add)
	e.verifyListeners(ctx, p, add)
	return res, nil
}

func (e *Engine) verifyService(ctx context.Context, svc render.Service, add func(Check)) {
	live := e.serviceState(ctx, svc.Name)
	id := "service:" + svc.Name
	if !live.Exists {
		if svc.Optional || svc.Enable == "disabled" || svc.Enable == "masked" {
			add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckOK, Detail: "unit is not installed (optional)"})
			return
		}
		add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckDrift, Expected: "unit exists", Actual: "not found"})
		return
	}
	switch svc.Enable {
	case "enabled":
		if !serviceEnabled(live.UnitFileState) {
			add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckDrift,
				Expected: "enabled", Actual: live.UnitFileState})
			return
		}
	case "disabled":
		if live.UnitFileState == "enabled" || live.UnitFileState == "enabled-runtime" || live.UnitFileState == "masked" {
			add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckDrift,
				Expected: "disabled", Actual: live.UnitFileState})
			return
		}
	case "masked":
		if live.UnitFileState != "masked" {
			add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckDrift,
				Expected: "masked", Actual: live.UnitFileState})
			return
		}
	}
	if svc.Active == "active" && live.ActiveState != "active" {
		add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckDrift,
			Expected: "active", Actual: live.ActiveState})
		return
	}
	if svc.Active == "inactive" && live.ActiveState == "active" {
		add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckDrift,
			Expected: "inactive", Actual: live.ActiveState})
		return
	}
	add(Check{ID: id, Section: "service", Target: svc.Name, Status: CheckOK})
}

func (e *Engine) verifyNFT(ctx context.Context, p *policy.Policy, d *render.Desired, st *State, scope Scope, add func(Check)) {
	for _, table := range d.NFT {
		if !tableInScope(table, scope) {
			continue
		}
		id := "nft:" + table.Name
		expected := ""
		if st.PolicyHash == p.Digest {
			expected = st.NFT[table.Name]
		}
		if expected == "" {
			add(Check{ID: id, Section: "nft", Target: table.Name, Status: CheckDrift,
				Expected: "applied policy ruleset", Actual: "no applied ruleset recorded", Detail: "run obsidian apply"})
			continue
		}
		live, err := e.nftCanonical(ctx, table.Name)
		if err != nil {
			add(Check{ID: id, Section: "nft", Target: table.Name, Status: CheckDrift,
				Expected: "table present", Actual: err.Error()})
			continue
		}
		if live != expected {
			add(Check{ID: id, Section: "nft", Target: table.Name, Status: CheckDrift,
				Expected: expected, Actual: live, Detail: "live nftables rules differ from the applied policy"})
			continue
		}
		add(Check{ID: id, Section: "nft", Target: table.Name, Status: CheckOK})
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
		if _, err := e.nftCanonical(ctx, name); err == nil {
			add(Check{ID: "nft:" + name, Section: "nft", Target: name, Status: CheckDrift,
				Expected: "absent", Actual: "obsolete table still present"})
		} else {
			add(Check{ID: "nft:" + name, Section: "nft", Target: name, Status: CheckOK})
		}
	}
}

func (e *Engine) verifySysctls(d *render.Desired, add func(Check)) {
	for _, s := range d.Sysctls {
		current, err := e.Sys.SysctlValue(s.Key)
		if err != nil {
			add(Check{ID: "sysctl:" + s.Key, Section: "sysctl", Target: s.Key, Status: CheckSkip,
				Expected: s.Value, Actual: "not supported by this kernel"})
			continue
		}
		current = strings.Join(strings.Fields(current), " ")
		if current != s.Value {
			add(Check{ID: "sysctl:" + s.Key, Section: "sysctl", Target: s.Key, Status: CheckDrift,
				Expected: s.Value, Actual: current, Detail: s.Reason})
		} else {
			add(Check{ID: "sysctl:" + s.Key, Section: "sysctl", Target: s.Key, Status: CheckOK})
		}
	}
}

func (e *Engine) verifySSH(ctx context.Context, p *policy.Policy, d *render.Desired, add func(Check)) {
	if !d.SSHManaged {
		return
	}
	test := e.Sys.Runner.Run(ctx, "sshd", "-t")
	if !test.Success() {
		add(Check{ID: "ssh:config", Section: "ssh", Target: "sshd", Status: CheckDrift,
			Expected: "valid configuration", Actual: test.Error()})
		return
	}
	effective := e.sshdEffective(ctx)
	if len(effective) == 0 {
		add(Check{ID: "ssh:config", Section: "ssh", Target: "sshd", Status: CheckWarn,
			Expected: "effective configuration", Actual: "sshd -T failed"})
		return
	}
	for key, want := range sshDesired(p) {
		got := effective[key]
		if got != want {
			add(Check{ID: "ssh:" + key, Section: "ssh", Target: key, Status: CheckDrift,
				Expected: want, Actual: orUnknown(got)})
		} else {
			add(Check{ID: "ssh:" + key, Section: "ssh", Target: key, Status: CheckOK})
		}
	}
}

func (e *Engine) verifyAppArmor(ctx context.Context, d *render.Desired, st *State, add func(Check)) {
	modes, err := e.appArmorModes(ctx)
	if err != nil {
		for _, sb := range d.Sandboxes {
			if sb.AppArmorMode != "off" {
				add(Check{ID: "apparmor:" + sb.ProfileName, Section: "apparmor", Target: sb.ProfileName, Status: CheckWarn,
					Expected: sb.AppArmorMode, Actual: "cannot read AppArmor status: " + err.Error()})
			}
		}
		return
	}
	desired := map[string]bool{}
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode == "off" {
			continue
		}
		desired[sb.ProfileName] = true
		if modes[sb.ProfileName] != sb.AppArmorMode {
			add(Check{ID: "apparmor:" + sb.ProfileName, Section: "apparmor", Target: sb.ProfileName, Status: CheckDrift,
				Expected: sb.AppArmorMode, Actual: orUnknown(modes[sb.ProfileName])})
		} else {
			add(Check{ID: "apparmor:" + sb.ProfileName, Section: "apparmor", Target: sb.ProfileName, Status: CheckOK})
		}
	}
	for name := range st.AppArmor {
		if desired[name] {
			continue
		}
		if mode, ok := modes[name]; ok {
			add(Check{ID: "apparmor:" + name, Section: "apparmor", Target: name, Status: CheckDrift,
				Expected: "not loaded", Actual: mode, Detail: "obsolete profile still loaded"})
		}
	}
}

func (e *Engine) verifyAudit(ctx context.Context, d *render.Desired, add func(Check)) {
	if !d.AuditManaged {
		return
	}
	status := e.Sys.Runner.Run(ctx, "auditctl", "-s")
	if !status.Success() {
		add(Check{ID: "audit:status", Section: "audit", Target: "auditd", Status: CheckWarn,
			Expected: "enabled", Actual: status.Error()})
		return
	}
	enabled := false
	for _, line := range strings.Split(string(status.Stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "enabled 1" || line == "enabled 2" {
			enabled = true
		}
	}
	if !enabled {
		add(Check{ID: "audit:status", Section: "audit", Target: "auditd", Status: CheckDrift,
			Expected: "enabled 1", Actual: status.Output()})
		return
	}
	rules := e.Sys.Runner.Run(ctx, "auditctl", "-l")
	if !rules.Success() {
		add(Check{ID: "audit:rules", Section: "audit", Target: "auditd", Status: CheckDrift,
			Expected: "loaded rules", Actual: rules.Error()})
		return
	}
	missing := []string{}
	for _, path := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/obsidian"} {
		if !strings.Contains(string(rules.Stdout), path) {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		add(Check{ID: "audit:rules", Section: "audit", Target: "auditd", Status: CheckDrift,
			Expected: "watches on " + strings.Join(missing, ", "), Actual: "missing"})
		return
	}
	add(Check{ID: "audit:rules", Section: "audit", Target: "auditd", Status: CheckOK})
}

func (e *Engine) verifyPackages(ctx context.Context, d *render.Desired, add func(Check)) {
	if _, err := e.Sys.Runner.LookPath("dpkg-query"); err != nil {
		add(Check{ID: "packages", Section: "package", Target: "dpkg", Status: CheckWarn,
			Expected: "dpkg-query", Actual: "unavailable"})
		return
	}
	for _, pkg := range d.Packages {
		installed, known := e.packageInstalled(ctx, pkg)
		switch {
		case !known:
			add(Check{ID: "package:" + pkg, Section: "package", Target: pkg, Status: CheckWarn,
				Expected: "installed", Actual: "cannot query"})
		case !installed:
			add(Check{ID: "package:" + pkg, Section: "package", Target: pkg, Status: CheckDrift,
				Expected: "installed", Actual: "missing"})
		default:
			add(Check{ID: "package:" + pkg, Section: "package", Target: pkg, Status: CheckOK})
		}
	}
}

type listener struct {
	netid string
	host  string
	port  int
}

func (e *Engine) verifyListeners(ctx context.Context, p *policy.Policy, add func(Check)) {
	if _, err := e.Sys.Runner.LookPath("ss"); err != nil {
		add(Check{ID: "exposure:ss", Section: "exposure", Target: "ss", Status: CheckWarn,
			Expected: "ss available", Actual: "not found"})
		return
	}
	res := e.Sys.Runner.Run(ctx, "ss", "-H", "-lntu")
	if !res.Success() {
		add(Check{ID: "exposure:ss", Section: "exposure", Target: "ss", Status: CheckWarn,
			Expected: "listening sockets", Actual: res.Error()})
		return
	}
	var listeners []listener
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		host, port, ok := splitAddress(fields[4])
		if !ok {
			continue
		}
		listeners = append(listeners, listener{netid: fields[0], host: host, port: port})
	}
	specs := []struct {
		field string
		proto string
		port  int
		mode  string
	}{
		{"exposure.ssh", "tcp", p.Admin.SSHPort, p.Exposure.SSH},
		{"exposure.https", "tcp", 443, p.Exposure.HTTPS},
		{"exposure.http", "tcp", 80, p.Exposure.HTTP},
		{"exposure.smtp", "tcp", 25, p.Exposure.SMTP},
		{"exposure.dns", "tcp", 53, p.Exposure.DNS},
		{"exposure.dns", "udp", 53, p.Exposure.DNS},
		{"exposure.ntp", "udp", 123, p.Exposure.NTP},
	}
	for _, spec := range specs {
		if spec.mode != policy.ExposureDisabled && spec.mode != policy.ExposureLoopback {
			continue
		}
		id := fmt.Sprintf("exposure:%s/%s", spec.field, spec.proto)
		var found []listener
		for _, l := range listeners {
			if l.port == spec.port && l.netid == spec.proto {
				found = append(found, l)
			}
		}
		switch spec.mode {
		case policy.ExposureDisabled:
			var exposed []listener
			for _, l := range found {
				if !isLoopbackHost(l.host) {
					exposed = append(exposed, l)
				}
			}
			if len(exposed) > 0 {
				add(Check{ID: id, Section: "exposure", Target: spec.field, Status: CheckDrift,
					Expected: "no listener on port " + strconv.Itoa(spec.port),
					Actual:   describeListeners(exposed)})
			} else {
				add(Check{ID: id, Section: "exposure", Target: spec.field, Status: CheckOK})
			}
		case policy.ExposureLoopback:
			var public []listener
			for _, l := range found {
				if !isLoopbackHost(l.host) {
					public = append(public, l)
				}
			}
			if len(public) > 0 {
				add(Check{ID: id, Section: "exposure", Target: spec.field, Status: CheckDrift,
					Expected: "loopback-only listener on port " + strconv.Itoa(spec.port),
					Actual:   describeListeners(public)})
			} else {
				add(Check{ID: id, Section: "exposure", Target: spec.field, Status: CheckOK})
			}
		}
	}
}

func splitAddress(addr string) (string, int, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "*:*" {
		return "", 0, false
	}
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return "", 0, false
	}
	host := strings.Trim(addr[:idx], "[]")
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

func isLoopbackHost(host string) bool {
	if host == "" || host == "*" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func describeListeners(ls []listener) string {
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		parts = append(parts, fmt.Sprintf("%s/%s:%d", l.netid, l.host, l.port))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}
