// Package policy parses and validates the obscure policy file.
//
// The policy is deliberately small. Unknown keys are errors: a typo in a
// security policy must never silently weaken the host.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Roles supported by the toolkit. The role is descriptive; it never silently
// changes the policy. It is used for validation and human-facing advice.
const (
	RoleWebServer   = "web-server"
	RoleSSHBastion  = "ssh-bastion"
	RoleWorkstation = "workstation"
	RoleCustom      = "custom"
)

// Exposure modes.
const (
	ExposureDisabled  = "disabled"
	ExposureLoopback  = "loopback"
	ExposureAdminOnly = "admin-only"
	ExposurePublic    = "public"
)

// Policy is the complete declarative security and privacy policy.
type Policy struct {
	Role            string             `toml:"role"`
	PublicInterface string             `toml:"public_interface"`
	Exposure        Exposure           `toml:"exposure"`
	Admin           Admin              `toml:"admin"`
	Privacy         Privacy            `toml:"privacy"`
	Services        map[string]string  `toml:"services"`
	Sandbox         map[string]Sandbox `toml:"sandbox"`
	Updates         Updates            `toml:"updates"`
	Audit           Audit              `toml:"audit"`
	Hardening       Hardening          `toml:"hardening"`

	// Path and digest are not part of the file format.
	Path   string `toml:"-"`
	Digest string `toml:"-"`
}

// Exposure declares which network services may be reached, and by whom.
type Exposure struct {
	SSH   string `toml:"ssh"`
	HTTPS string `toml:"https"`
	HTTP  string `toml:"http"`
	SMTP  string `toml:"smtp"`
	DNS   string `toml:"dns"`
	NTP   string `toml:"ntp"`
}

// Admin describes the administrative access path.
type Admin struct {
	SourceCIDRs        []string `toml:"source_cidrs"`
	Interfaces         []string `toml:"interfaces"`
	SSHPort            int      `toml:"ssh_port"`
	PasswordAuth       bool     `toml:"password_auth"`
	RootLogin          string   `toml:"root_login"`
	AllowTCPForwarding bool     `toml:"allow_tcp_forwarding"`
}

// Privacy describes local data handling.
type Privacy struct {
	Telemetry        string   `toml:"telemetry"`
	DNS              string   `toml:"dns"`
	DNSServers       []string `toml:"dns_servers"`
	DNSOverTLS       string   `toml:"dns_over_tls"`
	LogRetentionDays int      `toml:"log_retention_days"`
	LogMaxMB         int      `toml:"log_max_mb"`
}

// Sandbox describes a service isolated with systemd, AppArmor and/or Landlock.
type Sandbox struct {
	Binary        string   `toml:"binary"`
	RunAs         string   `toml:"run_as"`
	Group         string   `toml:"group"`
	Args          []string `toml:"args"`
	ReadWrite     []string `toml:"read_write"`
	ReadOnly      []string `toml:"read_only"`
	Network       string   `toml:"network"`
	AppArmor      string   `toml:"apparmor"`
	Landlock      string   `toml:"landlock"`
	Restart       string   `toml:"restart"`
	SyscallFilter string   `toml:"syscall_filter"`
}

// Updates describes unattended security updates.
type Updates struct {
	Unattended *bool  `toml:"unattended"`
	AutoReboot bool   `toml:"auto_reboot"`
	RebootTime string `toml:"reboot_time"`
}

// Audit describes the auditd baseline.
type Audit struct {
	Enabled *bool `toml:"enabled"`
}

// Hardening describes the systemd/sysctl/SSH baseline.
type Hardening struct {
	Sysctl *bool `toml:"sysctl"`
	SSH    *bool `toml:"ssh"`
}

// Warning is a policy concern that does not prevent planning but must be
// shown to the operator. With --strict, warnings are fatal.
type Warning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (w Warning) String() string { return w.Field + ": " + w.Message }

var (
	serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+$`)
	sandboxNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	ifaceRE       = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	hostnameRE    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	timeRE        = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// Load reads, parses and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Path = path
	sum := sha256.Sum256(data)
	p.Digest = hex.EncodeToString(sum[:])
	return p, nil
}

// Parse parses policy bytes, applies defaults and validates the result.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	md, err := toml.Decode(string(data), &p)
	if err != nil {
		return nil, fmt.Errorf("parse TOML: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("unknown policy key(s): %s", strings.Join(keys, ", "))
	}
	p.applyDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func boolValue(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (p *Policy) applyDefaults() {
	if p.Exposure.SSH == "" {
		p.Exposure.SSH = ExposureDisabled
	}
	if p.Exposure.HTTPS == "" {
		p.Exposure.HTTPS = ExposureDisabled
	}
	if p.Exposure.HTTP == "" {
		p.Exposure.HTTP = ExposureDisabled
	}
	if p.Exposure.SMTP == "" {
		p.Exposure.SMTP = ExposureDisabled
	}
	if p.Exposure.DNS == "" {
		p.Exposure.DNS = ExposureDisabled
	}
	if p.Exposure.NTP == "" {
		p.Exposure.NTP = ExposureDisabled
	}
	if p.Admin.SSHPort == 0 {
		p.Admin.SSHPort = 22
	}
	if p.Admin.RootLogin == "" {
		p.Admin.RootLogin = "no"
	}
	if p.Privacy.Telemetry == "" {
		p.Privacy.Telemetry = "deny"
	}
	if p.Privacy.DNS == "" {
		p.Privacy.DNS = "system"
	}
	if p.Privacy.DNSOverTLS == "" {
		p.Privacy.DNSOverTLS = "opportunistic"
	}
	if p.Privacy.LogRetentionDays == 0 {
		p.Privacy.LogRetentionDays = 30
	}
	if p.Privacy.LogMaxMB == 0 {
		p.Privacy.LogMaxMB = 500
	}
	if p.Updates.RebootTime == "" {
		p.Updates.RebootTime = "03:30"
	}
	for name, sb := range p.Sandbox {
		if sb.Network == "" {
			sb.Network = "none"
		}
		if sb.AppArmor == "" {
			sb.AppArmor = "auto"
		}
		if sb.Landlock == "" {
			sb.Landlock = "auto"
		}
		if sb.Restart == "" {
			sb.Restart = "on-failure"
		}
		if sb.SyscallFilter == "" {
			sb.SyscallFilter = "@system-service"
		}
		p.Sandbox[name] = sb
	}
}

// Validate checks the policy for correctness and internal consistency.
func (p *Policy) Validate() error {
	if p.Role == "" {
		return fmt.Errorf("role is required (one of %s, %s, %s, %s)", RoleWebServer, RoleSSHBastion, RoleWorkstation, RoleCustom)
	}
	switch p.Role {
	case RoleWebServer, RoleSSHBastion, RoleWorkstation, RoleCustom:
	default:
		return fmt.Errorf("role %q is not one of %s, %s, %s, %s", p.Role, RoleWebServer, RoleSSHBastion, RoleWorkstation, RoleCustom)
	}
	if p.PublicInterface != "" && !ifaceRE.MatchString(p.PublicInterface) {
		return fmt.Errorf("public_interface %q is not a valid interface name", p.PublicInterface)
	}
	for field, mode := range map[string]string{
		"exposure.ssh": p.Exposure.SSH, "exposure.https": p.Exposure.HTTPS,
		"exposure.http": p.Exposure.HTTP, "exposure.smtp": p.Exposure.SMTP,
		"exposure.dns": p.Exposure.DNS, "exposure.ntp": p.Exposure.NTP,
	} {
		if !validExposure(mode) {
			return fmt.Errorf("%s = %q: must be one of %s, %s, %s, %s", field, mode, ExposureDisabled, ExposureLoopback, ExposureAdminOnly, ExposurePublic)
		}
	}
	if p.Admin.SSHPort < 1 || p.Admin.SSHPort > 65535 {
		return fmt.Errorf("admin.ssh_port %d is outside 1-65535", p.Admin.SSHPort)
	}
	switch p.Admin.RootLogin {
	case "no", "prohibit-password", "yes":
	default:
		return fmt.Errorf("admin.root_login = %q: must be no, prohibit-password or yes", p.Admin.RootLogin)
	}
	for i, raw := range p.Admin.SourceCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("admin.source_cidrs[%d] = %q: %w", i, raw, err)
		}
	}
	for i, iface := range p.Admin.Interfaces {
		if !ifaceRE.MatchString(iface) {
			return fmt.Errorf("admin.interfaces[%d] = %q is not a valid interface name", i, iface)
		}
	}
	if p.requiresAdminCIDRs() && len(p.Admin.SourceCIDRs) == 0 {
		return fmt.Errorf("admin.source_cidrs is required because an exposure is admin-only")
	}
	if p.requiresInterface() && p.PublicInterface == "" && len(p.Admin.Interfaces) == 0 {
		return fmt.Errorf("public_interface is required because an exposure is public or admin-only")
	}
	for field, mode := range map[string]string{
		"exposure.https": p.Exposure.HTTPS, "exposure.http": p.Exposure.HTTP,
		"exposure.smtp": p.Exposure.SMTP, "exposure.dns": p.Exposure.DNS,
		"exposure.ntp": p.Exposure.NTP, "exposure.ssh": p.Exposure.SSH,
	} {
		if mode == ExposurePublic && p.PublicInterface == "" {
			return fmt.Errorf("%s = public requires public_interface", field)
		}
	}
	if p.Privacy.DNS == "local-resolver" {
		if state, ok := p.Services["systemd-resolved"]; ok && state != "enabled" {
			return fmt.Errorf("privacy.dns = local-resolver conflicts with services.systemd-resolved = %q", state)
		}
	}
	if p.Privacy.Telemetry != "deny" && p.Privacy.Telemetry != "allow" {
		return fmt.Errorf("privacy.telemetry = %q: must be deny or allow", p.Privacy.Telemetry)
	}
	switch p.Privacy.DNS {
	case "system", "local-resolver":
	default:
		return fmt.Errorf("privacy.dns = %q: must be system or local-resolver", p.Privacy.DNS)
	}
	switch p.Privacy.DNSOverTLS {
	case "yes", "no", "opportunistic":
	default:
		return fmt.Errorf("privacy.dns_over_tls = %q: must be yes, no or opportunistic", p.Privacy.DNSOverTLS)
	}
	for i, srv := range p.Privacy.DNSServers {
		if err := validateDNSServer(srv); err != nil {
			return fmt.Errorf("privacy.dns_servers[%d] = %q: %w", i, srv, err)
		}
	}
	if p.Privacy.LogRetentionDays < 1 || p.Privacy.LogRetentionDays > 3650 {
		return fmt.Errorf("privacy.log_retention_days %d is outside 1-3650", p.Privacy.LogRetentionDays)
	}
	if p.Privacy.LogMaxMB < 16 || p.Privacy.LogMaxMB > 1048576 {
		return fmt.Errorf("privacy.log_max_mb %d is outside 16-1048576", p.Privacy.LogMaxMB)
	}
	if p.Updates.AutoReboot && !timeRE.MatchString(p.Updates.RebootTime) {
		return fmt.Errorf("updates.reboot_time = %q: must be HH:MM", p.Updates.RebootTime)
	}
	for name, state := range p.Services {
		if !serviceNameRE.MatchString(name) {
			return fmt.Errorf("services.%s: invalid service name", name)
		}
		switch state {
		case "enabled", "disabled", "masked":
		default:
			return fmt.Errorf("services.%s = %q: must be enabled, disabled or masked", name, state)
		}
	}
	for name, sb := range p.Sandbox {
		if !sandboxNameRE.MatchString(name) {
			return fmt.Errorf("sandbox.%s: name must match %s", name, sandboxNameRE)
		}
		if err := validateSandbox(name, sb); err != nil {
			return err
		}
	}
	seenUsers := map[string]string{}
	for _, name := range p.SandboxNames() {
		user := p.Sandbox[name].RunAs
		if prev, ok := seenUsers[user]; ok {
			return fmt.Errorf("sandbox.%s.run_as = %q is already used by sandbox.%s: each sandbox needs its own user for egress isolation", name, user, prev)
		}
		seenUsers[user] = name
	}
	return nil
}

func validExposure(s string) bool {
	switch s {
	case ExposureDisabled, ExposureLoopback, ExposureAdminOnly, ExposurePublic:
		return true
	}
	return false
}

func (p *Policy) requiresAdminCIDRs() bool {
	for _, m := range p.Exposures() {
		if m == ExposureAdminOnly {
			return true
		}
	}
	return false
}

func (p *Policy) requiresInterface() bool {
	for _, m := range p.Exposures() {
		if m == ExposurePublic || m == ExposureAdminOnly {
			return true
		}
	}
	return false
}

// Exposures returns every exposure mode in a stable order.
func (p *Policy) Exposures() []string {
	return []string{p.Exposure.SSH, p.Exposure.HTTPS, p.Exposure.HTTP, p.Exposure.SMTP, p.Exposure.DNS, p.Exposure.NTP}
}

// Warnings returns advisory findings. They are not errors, but --strict turns
// them into errors.
func (p *Policy) Warnings() []Warning {
	var out []Warning
	add := func(field, format string, args ...any) {
		out = append(out, Warning{Field: field, Message: fmt.Sprintf(format, args...)})
	}
	if p.Role == RoleWebServer && p.Exposure.HTTPS == ExposureDisabled {
		add("exposure.https", "role is web-server but HTTPS exposure is disabled")
	}
	if p.Role == RoleSSHBastion && p.Exposure.SSH == ExposureDisabled {
		add("exposure.ssh", "role is ssh-bastion but SSH exposure is disabled")
	}
	if p.Exposure.HTTP == ExposurePublic && p.Exposure.HTTPS != ExposurePublic {
		add("exposure.http", "HTTP is public while HTTPS is not; credentials and content may travel in clear text")
	}
	if p.Exposure.SSH == ExposurePublic {
		add("exposure.ssh", "SSH is exposed to the internet; admin-only is strongly preferred")
	}
	if p.Admin.PasswordAuth {
		add("admin.password_auth", "password authentication is enabled; public-key authentication is safer")
	}
	if p.Admin.RootLogin == "yes" {
		add("admin.root_login", "direct root login is enabled")
	}
	for _, cidr := range p.Admin.SourceCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err == nil && prefix.Bits() == 0 {
			add("admin.source_cidrs", "%s allows every address, so SSH is effectively public", cidr)
		}
	}
	if p.Privacy.Telemetry == "allow" {
		add("privacy.telemetry", "telemetry is allowed; the toolkit will not mask reporting services")
	}
	if p.Privacy.DNS == "local-resolver" && len(p.Privacy.DNSServers) == 0 {
		add("privacy.dns_servers", "local resolver will use DHCP-provided upstreams; set dns_servers for a fixed privacy policy")
	}
	if p.Privacy.DNS == "local-resolver" && p.Privacy.DNSOverTLS != "no" {
		for _, srv := range p.Privacy.DNSServers {
			if !strings.Contains(srv, "#") {
				add("privacy.dns_servers", "DNS server %q has no #hostname; strict DNS-over-TLS certificate validation is not possible", srv)
			}
		}
	}
	for name, sb := range p.Sandbox {
		field := "sandbox." + name
		if sb.RunAs == "root" {
			add(field+".run_as", "sandbox runs as root, which defeats its purpose")
		}
		for _, rw := range sb.ReadWrite {
			for _, ro := range sb.ReadOnly {
				if rw == ro {
					add(field, "%s is both read_write and read_only; read_write wins", rw)
				}
			}
		}
		if sb.Network == "outbound" {
			add(field+".network", "outbound networking is unrestricted; outbound-https is safer")
		}
		for _, path := range append(append([]string{}, sb.ReadWrite...), sb.ReadOnly...) {
			if path == "/" {
				add(field, "path / grants the sandbox the whole filesystem")
			}
		}
	}
	return out
}

func validateSandbox(name string, sb Sandbox) error {
	field := "sandbox." + name
	if sb.Binary == "" {
		return fmt.Errorf("%s.binary is required", field)
	}
	if !strings.HasPrefix(sb.Binary, "/") {
		return fmt.Errorf("%s.binary %q must be an absolute path", field, sb.Binary)
	}
	if strings.Contains(sb.Binary, "..") {
		return fmt.Errorf("%s.binary %q must not contain ..", field, sb.Binary)
	}
	if strings.ContainsAny(sb.Binary, " \t\n\r\x00") {
		return fmt.Errorf("%s.binary %q must not contain whitespace or control characters", field, sb.Binary)
	}
	if sb.RunAs == "" {
		return fmt.Errorf("%s.run_as is required", field)
	}
	if sb.RunAs == "root" {
		return fmt.Errorf("%s.run_as = root: a sandbox must not run as root", field)
	}
	if !serviceNameRE.MatchString(sb.RunAs) {
		return fmt.Errorf("%s.run_as %q is not a valid user name", field, sb.RunAs)
	}
	if sb.Group != "" && !serviceNameRE.MatchString(sb.Group) {
		return fmt.Errorf("%s.group %q is not a valid group name", field, sb.Group)
	}
	for _, a := range sb.Args {
		if strings.ContainsAny(a, "\n\r\x00") {
			return fmt.Errorf("%s.args contains a control character", field)
		}
	}
	for _, list := range []struct {
		name string
		vals []string
	}{{"read_write", sb.ReadWrite}, {"read_only", sb.ReadOnly}} {
		for i, path := range list.vals {
			if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
				return fmt.Errorf("%s.%s[%d] = %q: must be an absolute, clean path", field, list.name, i, path)
			}
			if path == "/" {
				return fmt.Errorf("%s.%s[%d] = /: refusing to grant the whole filesystem", field, list.name, i)
			}
			if strings.ContainsAny(path, " \t\n\r\x00") {
				return fmt.Errorf("%s.%s[%d] = %q: must not contain whitespace or control characters", field, list.name, i, path)
			}
		}
	}
	switch sb.Network {
	case "none", "loopback", "outbound", "outbound-https":
	default:
		return fmt.Errorf("%s.network = %q: must be none, loopback, outbound or outbound-https", field, sb.Network)
	}
	switch sb.AppArmor {
	case "auto", "enforce", "complain", "off":
	default:
		return fmt.Errorf("%s.apparmor = %q: must be auto, enforce, complain or off", field, sb.AppArmor)
	}
	switch sb.Landlock {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("%s.landlock = %q: must be auto, on or off", field, sb.Landlock)
	}
	switch sb.Restart {
	case "no", "on-failure", "always":
	default:
		return fmt.Errorf("%s.restart = %q: must be no, on-failure or always", field, sb.Restart)
	}
	if sb.SyscallFilter == "" {
		return fmt.Errorf("%s.syscall_filter must not be empty; use \"none\" to disable", field)
	}
	if strings.ContainsAny(sb.SyscallFilter, "\n\r\x00") {
		return fmt.Errorf("%s.syscall_filter contains a control character", field)
	}
	return nil
}

func validateDNSServer(s string) error {
	addr, host, _ := strings.Cut(strings.TrimSpace(s), "#")
	if _, err := netip.ParseAddr(addr); err != nil {
		return fmt.Errorf("not an IP address: %w", err)
	}
	if host != "" && !hostnameRE.MatchString(host) {
		return fmt.Errorf("invalid DoT hostname %q", host)
	}
	return nil
}

// AdminInterfaces returns the interfaces on which administrative access is
// accepted. It defaults to the public interface.
func (p *Policy) AdminInterfaces() []string {
	if len(p.Admin.Interfaces) > 0 {
		return append([]string{}, p.Admin.Interfaces...)
	}
	if p.PublicInterface != "" {
		return []string{p.PublicInterface}
	}
	return nil
}

// AdminPrefixes returns validated, de-duplicated admin CIDRs.
func (p *Policy) AdminPrefixes() []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, raw := range p.Admin.SourceCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	return out
}

// Unattended reports whether unattended security updates are enabled.
func (p *Policy) Unattended() bool { return boolValue(p.Updates.Unattended, true) }

// AuditEnabled reports whether the auditd baseline is enabled.
func (p *Policy) AuditEnabled() bool { return boolValue(p.Audit.Enabled, true) }

// SysctlEnabled reports whether the sysctl baseline is enabled.
func (p *Policy) SysctlEnabled() bool { return boolValue(p.Hardening.Sysctl, true) }

// SSHHardeningEnabled reports whether the SSH baseline is enabled.
func (p *Policy) SSHHardeningEnabled() bool { return boolValue(p.Hardening.SSH, true) }

// ServiceNames returns policy-managed service names in stable order.
func (p *Policy) ServiceNames() []string {
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SandboxNames returns sandbox names in stable order.
func (p *Policy) SandboxNames() []string {
	names := make([]string, 0, len(p.Sandbox))
	for name := range p.Sandbox {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// HasPublicExposure reports whether any exposure is public.
func (p *Policy) HasPublicExposure() bool {
	for _, m := range p.Exposures() {
		if m == ExposurePublic {
			return true
		}
	}
	return false
}
