package engine

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
	"github.com/obsidian-toolkit/obsidian/internal/render"
)

func (e *Engine) assessLockout(ctx context.Context, p *policy.Policy, d *render.Desired, changes []Change, allow bool) LockoutReport {
	report := LockoutReport{PolicyPort: p.Admin.SSHPort}
	sess := e.Sys.Session()
	report.Remote = sess.Remote
	report.Source = sess.Source
	report.SessionPort = sess.ServerPort
	if sess.ClientIP.IsValid() {
		report.ClientIP = sess.ClientIP.String()
	}
	if !sess.Remote {
		report.Allowed = true
		return report
	}
	if !sshReachabilityChanged(changes) {
		report.Allowed = true
		return report
	}

	effective := e.sshdEffective(ctx)
	currentPort := p.Admin.SSHPort
	if v, ok := effective["port"]; ok {
		fields := strings.Fields(v)
		if len(fields) > 0 {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				currentPort = n
			}
		}
	}
	report.SessionPort = currentPort

	if p.Exposure.SSH == policy.ExposureDisabled || p.Exposure.SSH == policy.ExposureLoopback {
		report.Reasons = append(report.Reasons, "the policy blocks new SSH connections")
	}
	if p.Exposure.SSH == policy.ExposureAdminOnly {
		if !sess.ClientIP.IsValid() {
			report.Reasons = append(report.Reasons, "the SSH client address is unknown, so it cannot be matched against admin.source_cidrs")
		} else if !prefixContains(p.AdminPrefixes(), sess.ClientIP) {
			report.Reasons = append(report.Reasons, fmt.Sprintf("SSH client %s is not inside admin.source_cidrs", sess.ClientIP))
		}
	}
	if currentPort != p.Admin.SSHPort {
		report.Reasons = append(report.Reasons, fmt.Sprintf("SSH port changes from %d to %d", currentPort, p.Admin.SSHPort))
	}
	for _, svc := range d.Services {
		if (svc.Name == "ssh" || svc.Name == "sshd") && (svc.Enable == "disabled" || svc.Enable == "masked") {
			report.Reasons = append(report.Reasons, "the policy disables the SSH service")
		}
	}
	if value, ok := effective["passwordauthentication"]; ok && value == "yes" && !p.Admin.PasswordAuth {
		// Disabling password authentication does not end the current session,
		// but it can lock out the administrator's next login. Only treat it as
		// a lockout risk when the session used a password or when no usable key
		// can be found for the account that invoked obsidian.
		switch e.sshSessionAuthMethod(ctx, sess.ClientIP) {
		case "publickey":
			// The current administrator already authenticates with a key.
		case "password":
			report.Reasons = append(report.Reasons, "the current SSH session used a password; disabling password authentication would lock out the next login")
		default:
			if !e.remoteUserHasKey() {
				report.Reasons = append(report.Reasons, "password authentication is being disabled and no authorized key was found for the invoking user")
			}
		}
	}
	if value, ok := effective["permitrootlogin"]; ok && value != "no" && p.Admin.RootLogin == "no" && e.Sys.Env("SUDO_USER") == "" {
		report.Reasons = append(report.Reasons, "root login is being disabled while obsidian appears to run as root over SSH")
	}

	if len(report.Reasons) == 0 {
		report.Allowed = true
		return report
	}
	report.Risky = true
	report.Allowed = allow
	return report
}

func sshReachabilityChanged(changes []Change) bool {
	for _, c := range changes {
		switch c.Kind {
		case "nft":
			if c.Target == "inet obsidian" {
				return true
			}
		case "service":
			if c.Target == "ssh" || c.Target == "sshd" {
				return true
			}
		case "ssh":
			return true
		case "file":
			if c.Target == "/etc/ssh/sshd_config.d/00-obsidian.conf" {
				return true
			}
		}
	}
	return false
}

func prefixContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// sshSessionAuthMethod reports the authentication method of the most recent
// accepted login from addr, using the journal. An empty string means unknown.
func (e *Engine) sshSessionAuthMethod(ctx context.Context, addr netip.Addr) string {
	if !addr.IsValid() || !e.commandExists("journalctl") {
		return ""
	}
	res := e.Sys.Runner.Run(ctx, "journalctl", "--no-pager", "-q", "-o", "cat", "-u", "ssh", "--since", "-6 hours")
	if !res.Success() {
		return ""
	}
	method := ""
	needle := " from " + addr.String() + " port "
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if !strings.HasPrefix(line, "Accepted ") || !strings.Contains(line, needle) {
			continue
		}
		if fields := strings.Fields(line); len(fields) >= 2 {
			method = fields[1]
		}
	}
	return method
}

// remoteUserHasKey reports whether the account that invoked obsidian (via
// sudo) has a non-empty authorized_keys file.
func (e *Engine) remoteUserHasKey() bool {
	name := e.Sys.Env("SUDO_USER")
	if name == "" || name == "root" {
		name = e.Sys.Env("USER")
	}
	if name == "" || name == "root" {
		return false
	}
	u, err := e.Sys.LookupUser(name)
	if err != nil || u.Home == "" {
		return false
	}
	data, err := e.Sys.ReadFile(filepath.Join(u.Home, ".ssh", "authorized_keys"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return true
		}
	}
	return false
}
