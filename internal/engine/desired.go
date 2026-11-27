package engine

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
	"github.com/obsidian-toolkit/obsidian/internal/render"
)

// BuildDesired renders and validates the policy against the host.
func (e *Engine) BuildDesired(ctx context.Context, p *policy.Policy) (*render.Desired, error) {
	opts := render.Options{
		Policy:           p,
		SSHDInstalled:    e.commandExists("sshd") || e.Sys.Exists("/usr/sbin/sshd"),
		AppArmorEnabled:  e.Sys.AppArmorEnabled(),
		SeccompSupported: e.Sys.SeccompSupported(),
		LandlockABI:      e.Sys.LandlockABI(),
		PathExists:       e.Sys.Exists,
		UserID: func(name string) (int, bool) {
			u, err := e.Sys.LookupUser(name)
			if err != nil {
				return 0, false
			}
			return u.UID, true
		},
	}
	if e.Sys.Exists("/proc/sys") {
		opts.SysctlExists = e.Sys.SysctlExists
	}
	d, err := render.Render(p, opts)
	if err != nil {
		return nil, err
	}
	if err := e.validateDesired(ctx, p, d); err != nil {
		return nil, err
	}
	return d, nil
}

func (e *Engine) commandExists(name string) bool {
	_, err := e.Sys.Runner.LookPath(name)
	return err == nil
}

func (e *Engine) validateDesired(ctx context.Context, p *policy.Policy, d *render.Desired) error {
	if runtime.GOOS == "linux" {
		for _, iface := range append([]string{p.PublicInterface}, p.AdminInterfaces()...) {
			if iface == "" {
				continue
			}
			ok, err := e.Sys.InterfaceExists(iface)
			if err != nil {
				return fmt.Errorf("check interface %s: %w", iface, err)
			}
			if !ok {
				return fmt.Errorf("interface %q does not exist", iface)
			}
		}
	}
	if p.Exposure.SSH != policy.ExposureDisabled && !d.SSHManaged && e.NoPackages {
		return fmt.Errorf("SSH exposure is enabled but openssh-server is not installed and --no-packages was used")
	}
	for _, name := range p.SandboxNames() {
		sb := p.Sandbox[name]
		u, err := e.Sys.LookupUser(sb.RunAs)
		if err != nil {
			return fmt.Errorf("sandbox.%s: %w", name, err)
		}
		if u.UID >= 1000 && u.Shell != "/usr/sbin/nologin" && u.Shell != "/bin/false" {
			d.Warnings = append(d.Warnings, policy.Warning{
				Field:   "sandbox." + name + ".run_as",
				Message: "uses login account " + sb.RunAs + "; its other processes share the sandbox egress rules. Use a dedicated service account.",
			})
		}
		if sb.Group != "" {
			if _, err := e.Sys.LookupGroup(sb.Group); err != nil {
				return fmt.Errorf("sandbox.%s: %w", name, err)
			}
		}
		info, err := e.Sys.Stat(sb.Binary)
		if err != nil {
			return fmt.Errorf("sandbox.%s.binary %s: %w", name, sb.Binary, err)
		}
		if info.IsDir || info.Mode&0o111 == 0 {
			return fmt.Errorf("sandbox.%s.binary %s is not an executable file", name, sb.Binary)
		}
		for _, path := range sb.ReadWrite {
			if !e.Sys.Exists(path) {
				return fmt.Errorf("sandbox.%s.read_write %s does not exist", name, path)
			}
		}
		for _, path := range sb.ReadOnly {
			if !e.Sys.Exists(path) {
				return fmt.Errorf("sandbox.%s.read_only %s does not exist", name, path)
			}
		}
		if sb.AppArmor == "enforce" || sb.AppArmor == "complain" {
			if !e.Sys.AppArmorEnabled() && !e.AllowDegraded {
				return fmt.Errorf("sandbox.%s.apparmor = %s but AppArmor is not enabled (use --allow-degraded to omit it)", name, sb.AppArmor)
			}
		}
	}
	if p.Exposure.SSH != policy.ExposureDisabled && !d.SSHManaged && !e.commandExists("sshd") && e.NoPackages {
		return fmt.Errorf("SSH exposure is enabled but sshd is unavailable")
	}
	return nil
}

// FilterDesired restricts a rendered state to a scope.
func FilterDesired(d *render.Desired, scope Scope) *render.Desired {
	if scope.IsFull() {
		return d
	}
	out := &render.Desired{
		Warnings: append([]policy.Warning{}, d.Warnings...),
		Notes:    append([]string{}, d.Notes...),
	}
	allowed := func(name string) bool {
		return scope.Sandbox == "" || scope.Sandbox == name
	}
	for _, art := range d.Artifacts {
		if strings.HasPrefix(art.Section, "sandbox.") && allowed(strings.TrimPrefix(art.Section, "sandbox.")) {
			out.Artifacts = append(out.Artifacts, art)
		}
	}
	for _, nft := range d.NFT {
		if nft.Sandbox {
			out.NFT = append(out.NFT, nft)
		}
	}
	for _, sb := range d.Sandboxes {
		if allowed(sb.Name) {
			out.Sandboxes = append(out.Sandboxes, sb)
		}
	}
	for _, svc := range d.Services {
		if svc.Name == "obsidian-sandbox-firewall.service" || strings.HasPrefix(svc.Name, "obsidian-") && svc.Name != "obsidian-firewall.service" {
			if scope.Sandbox == "" || svc.Name == "obsidian-"+scope.Sandbox+".service" || svc.Name == "obsidian-sandbox-firewall.service" {
				out.Services = append(out.Services, svc)
			}
		}
	}
	for _, pkg := range d.Packages {
		if pkg == "nftables" || pkg == "apparmor" || pkg == "apparmor-utils" {
			out.Packages = append(out.Packages, pkg)
		}
	}
	return out
}
