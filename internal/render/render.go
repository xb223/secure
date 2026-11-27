// Package render turns a validated policy into the exact files and service
// states that obsidian will manage. Rendering is pure: it never touches the
// live host except through read-only fact probes supplied in Options.
package render

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
)

// ArtifactKind classifies a managed file.
type ArtifactKind string

const (
	KindConfig   ArtifactKind = "config"
	KindUnit     ArtifactKind = "unit"
	KindNFT      ArtifactKind = "nftables"
	KindAppArmor ArtifactKind = "apparmor"
)

// Artifact is one managed file.
type Artifact struct {
	Path     string      `json:"path"`
	Content  []byte      `json:"-"`
	Mode     fs.FileMode `json:"mode"`
	Preserve bool        `json:"preserve,omitempty"`
	// Mutable marks files that tools may rewrite in place (AppArmor profiles).
	Mutable bool         `json:"mutable,omitempty"`
	Reason  string       `json:"reason"`
	Section string       `json:"section"`
	Kind    ArtifactKind `json:"kind"`
}

// Service describes a desired systemd unit state.
type Service struct {
	Name     string `json:"name"`
	Enable   string `json:"enable,omitempty"` // "", enabled, disabled, masked
	Active   string `json:"active,omitempty"` // "", active, inactive, any
	Reason   string `json:"reason"`
	Optional bool   `json:"optional,omitempty"`
	Restart  bool   `json:"restart,omitempty"`
	Reload   bool   `json:"reload,omitempty"`
	Critical bool   `json:"critical,omitempty"`
}

// NFTTable is one nftables table plus the unit that restores it at boot.
type NFTTable struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	Content        []byte `json:"-"`
	ServiceName    string `json:"service_name"`
	ServicePath    string `json:"service_path"`
	ServiceContent []byte `json:"-"`
	Reason         string `json:"reason"`
	Sandbox        bool   `json:"sandbox,omitempty"`
}

// Sandbox is a rendered sandbox service.
type Sandbox struct {
	Name                string `json:"name"`
	UnitName            string `json:"unit_name"`
	UnitPath            string `json:"unit_path"`
	UnitContent         []byte `json:"-"`
	ConfigPath          string `json:"config_path"`
	ConfigJSON          []byte `json:"-"`
	ProfilePath         string `json:"profile_path,omitempty"`
	ProfileName         string `json:"profile_name,omitempty"`
	ProfileContent      []byte `json:"-"`
	AppArmorMode        string `json:"apparmor_mode,omitempty"` // enforce, complain, off
	Landlock            bool   `json:"landlock,omitempty"`
	Network             string `json:"network"`
	AppArmorUnsupported bool   `json:"apparmor_unsupported,omitempty"`
	LandlockUnsupported bool   `json:"landlock_unsupported,omitempty"`
	SeccompUnsupported  bool   `json:"seccomp_unsupported,omitempty"`
	Reason              string `json:"reason"`
}

// Sysctl is one runtime kernel setting.
type Sysctl struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Desired is the complete rendered state for a policy.
type Desired struct {
	Artifacts      []Artifact       `json:"artifacts"`
	Services       []Service        `json:"services"`
	Sandboxes      []Sandbox        `json:"sandboxes"`
	NFT            []NFTTable       `json:"nft"`
	Sysctls        []Sysctl         `json:"sysctls"`
	Packages       []string         `json:"packages"`
	Warnings       []policy.Warning `json:"warnings"`
	Notes          []string         `json:"notes"`
	SSHManaged     bool             `json:"ssh_managed"`
	AuditManaged   bool             `json:"audit_managed"`
	DNSManaged     bool             `json:"dns_managed"`
	UpdatesManaged bool             `json:"updates_managed"`
}

// Options supplies host facts and policy.
type Options struct {
	Policy *policy.Policy

	SSHDInstalled    bool
	AppArmorEnabled  bool
	SeccompSupported bool
	LandlockABI      int
	SysctlExists     func(string) bool
	PathExists       func(string) bool
	PackageInstalled func(string) bool
	UserID           func(string) (int, bool)
}

// Render computes all desired files and service states.
func Render(p *policy.Policy, opts Options) (*Desired, error) {
	if p == nil {
		return nil, fmt.Errorf("nil policy")
	}
	d := &Desired{Warnings: append([]policy.Warning{}, p.Warnings()...)}
	d.Notes = append(d.Notes, fmt.Sprintf("role %s, public interface %s", p.Role, orNone(p.PublicInterface)))

	mainNFT, err := renderFirewall(p)
	if err != nil {
		return nil, err
	}
	d.NFT = append(d.NFT, mainNFT)
	d.Artifacts = append(d.Artifacts, nftArtifacts(mainNFT)...)
	d.Services = append(d.Services, Service{
		Name: mainNFT.ServiceName, Enable: "enabled", Active: "active",
		Reason: "load the policy firewall at boot and now", Critical: true,
	})

	if p.SSHHardeningEnabled() && (p.Exposure.SSH != policy.ExposureDisabled || opts.SSHDInstalled) {
		sshArtifact := renderSSHD(p)
		d.Artifacts = append(d.Artifacts, sshArtifact)
		d.SSHManaged = true
		if !serviceDesired(p, "ssh") && !serviceDesired(p, "sshd") {
			d.Services = append(d.Services, Service{
				Name: "ssh", Reload: true, Reason: "apply hardened SSH settings without dropping live sessions",
				Optional: true, Critical: true,
			})
		}
		d.Packages = append(d.Packages, "openssh-server")
	}

	if p.SysctlEnabled() {
		art, sysctls := renderSysctl(p, opts.SysctlExists)
		d.Artifacts = append(d.Artifacts, art)
		d.Sysctls = append(d.Sysctls, sysctls...)
	}

	if p.Privacy.DNS == "local-resolver" {
		d.Artifacts = append(d.Artifacts, renderResolved(p))
		d.DNSManaged = true
		d.Packages = append(d.Packages, "systemd-resolved")
		d.Services = append(d.Services, Service{
			Name: "systemd-resolved", Enable: "enabled", Active: "active", Restart: true,
			Reason: "apply the local resolver and privacy settings", Optional: true,
		})
	}

	if p.AuditEnabled() {
		d.Artifacts = append(d.Artifacts, renderAuditRules(opts.PathExists))
		d.AuditManaged = true
		d.Packages = append(d.Packages, "auditd")
		d.Services = append(d.Services, Service{
			Name: "auditd", Enable: "enabled", Active: "active",
			Reason: "load the audit baseline", Optional: true,
		})
	}

	if p.Unattended() {
		d.Artifacts = append(d.Artifacts, renderUnattended(p))
		d.UpdatesManaged = true
		d.Packages = append(d.Packages, "unattended-upgrades")
		d.Services = append(d.Services, Service{
			Name: "unattended-upgrades", Enable: "enabled", Active: "any",
			Reason: "install security updates automatically", Optional: true,
		})
	}

	d.Artifacts = append(d.Artifacts, renderJournald(p))
	d.Services = append(d.Services, Service{
		Name: "systemd-journald", Active: "active", Restart: true,
		Reason: "apply journal retention limits", Optional: true,
	})

	for _, name := range p.SandboxNames() {
		sb, err := renderSandbox(p, name, p.Sandbox[name], opts, d)
		if err != nil {
			return nil, err
		}
		d.Sandboxes = append(d.Sandboxes, sb)
		d.Artifacts = append(d.Artifacts, sandboxArtifacts(sb)...)
		d.Services = append(d.Services, Service{
			Name: sb.UnitName, Enable: "enabled", Active: "active",
			Reason: "run " + name + " inside its sandbox", Critical: true,
		})
		if sb.AppArmorMode == "enforce" || sb.AppArmorMode == "complain" {
			d.Packages = append(d.Packages, "apparmor", "apparmor-utils")
		}
	}

	sandboxNFT, err := renderSandboxFirewall(p, opts)
	if err != nil {
		return nil, err
	}
	if sandboxNFT != nil {
		d.NFT = append(d.NFT, *sandboxNFT)
		d.Artifacts = append(d.Artifacts, nftArtifacts(*sandboxNFT)...)
		d.Services = append(d.Services, Service{
			Name: sandboxNFT.ServiceName, Enable: "enabled", Active: "active",
			Reason: "apply sandbox egress policy", Critical: true,
		})
	}

	if p.Privacy.Telemetry == "deny" {
		for _, name := range telemetryServices {
			d.Services = append(d.Services, Service{
				Name: name, Enable: "masked", Active: "inactive", Optional: true,
				Reason: "telemetry is denied by policy",
			})
		}
	}

	for _, name := range p.ServiceNames() {
		state := p.Services[name]
		svc := Service{Name: name, Reason: "policy services." + name + " = " + state, Critical: isSSHService(name)}
		switch state {
		case "enabled":
			svc.Enable, svc.Active = "enabled", "active"
		case "disabled":
			svc.Enable, svc.Active = "disabled", "inactive"
		case "masked":
			svc.Enable, svc.Active = "masked", "inactive"
		}
		d.Services = append(d.Services, svc)
	}

	d.Packages = append(d.Packages, "nftables", "iproute2")
	d.Packages = dedupeSorted(d.Packages)
	d.Artifacts = sortArtifacts(d.Artifacts)
	d.Services = dedupeServices(d.Services)
	d.Sysctls = dedupeSysctls(d.Sysctls)

	if len(d.Sandboxes) > 0 && !opts.SeccompSupported {
		for i := range d.Sandboxes {
			d.Sandboxes[i].SeccompUnsupported = true
		}
		d.Warnings = append(d.Warnings, policy.Warning{
			Field: "sandbox.syscall_filter", Message: "seccomp is unavailable; system call filtering will be omitted",
		})
	}

	return d, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func serviceDesired(p *policy.Policy, name string) bool {
	state, ok := p.Services[name]
	return ok && (state == "enabled" || state == "disabled" || state == "masked")
}

func isSSHService(name string) bool { return name == "ssh" || name == "sshd" }

var telemetryServices = []string{
	"popularity-contest",
	"whoopsie",
	"apport",
	"avahi-daemon",
	"kerneloops",
	"cups-browsed",
}

func header(section string) string {
	return "# Managed by obsidian (" + section + "). Do not edit.\n" +
		"# Changes are detected as drift and replaced from the policy.\n"
}

func sortArtifacts(in []Artifact) []Artifact {
	sort.Slice(in, func(i, j int) bool { return in[i].Path < in[j].Path })
	return in
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func dedupeServices(in []Service) []Service {
	seen := map[string]int{}
	var out []Service
	for _, svc := range in {
		if idx, ok := seen[svc.Name]; ok {
			// A policy entry for a feature service wins over the implicit
			// default, but keep reload/restart flags from the implicit one.
			prev := out[idx]
			if svc.Enable != "" {
				prev.Enable = svc.Enable
			}
			if svc.Active != "" {
				prev.Active = svc.Active
			}
			prev.Restart = prev.Restart || svc.Restart
			prev.Reload = prev.Reload || svc.Reload
			prev.Critical = prev.Critical || svc.Critical
			if svc.Reason != "" {
				prev.Reason = svc.Reason
			}
			out[idx] = prev
			continue
		}
		seen[svc.Name] = len(out)
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func dedupeSysctls(in []Sysctl) []Sysctl {
	seen := map[string]bool{}
	var out []Sysctl
	for _, s := range in {
		if seen[s.Key] {
			continue
		}
		seen[s.Key] = true
		out = append(out, s)
	}
	return out
}

func quoteNftString(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
