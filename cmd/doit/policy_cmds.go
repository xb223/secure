package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/policy"
	"github.com/obscure-toolkit/obscure/internal/render"
	"github.com/obscure-toolkit/obscure/internal/system"
)

//go:embed default-policy.toml
var defaultPolicy []byte

func cmdInit(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := g.config
	force := false
	fs.StringVar(&path, "path", path, "where to write the policy")
	fs.BoolVar(&force, "force", false, "overwrite an existing policy")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit init:", err)
		return 2
	}
	if _, err := os.Stat(path); err == nil && !force {
		fmt.Fprintf(stderr, "doit: %s already exists (use --force to overwrite)\n", path)
		return 1
	}
	if strings.HasPrefix(path, "/etc/") && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "doit: writing to /etc requires root (try: sudo doit init)")
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintln(stderr, "doit:", err)
		return 1
	}
	if err := os.WriteFile(path, defaultPolicy, 0o644); err != nil {
		fmt.Fprintln(stderr, "doit:", err)
		return 1
	}
	fmt.Fprintf(o.w, "wrote %s\nnext: edit it, then run sudo doit plan\n", path)
	return 0
}

func cmdCheck(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit check:", err)
		return 2
	}
	p, ok := loadPolicy(g, stderr)
	if !ok {
		return 1
	}
	if g.json {
		payload := struct {
			Path     string           `json:"path"`
			Digest   string           `json:"digest"`
			Role     string           `json:"role"`
			Warnings []policy.Warning `json:"warnings,omitempty"`
			Valid    bool             `json:"valid"`
		}{p.Path, p.Digest, p.Role, p.Warnings(), true}
		if g.strict && len(p.Warnings()) > 0 {
			payload.Valid = false
			o.emitJSON(payload)
			return 1
		}
		return o.emitJSON(payload)
	}
	o.printf("%s %s\n", o.ok("valid:"), p.Path)
	o.printf("  role: %s, public interface: %s\n", p.Role, orDash(p.PublicInterface))
	o.printf("  exposure: %s\n", strings.Join(p.Exposures(), ", "))
	if len(p.Admin.SourceCIDRs) > 0 {
		o.printf("  admin source CIDRs: %s\n", strings.Join(p.Admin.SourceCIDRs, ", "))
	}
	if names := p.SandboxNames(); len(names) > 0 {
		o.printf("  sandboxes: %s\n", strings.Join(names, ", "))
	}
	warnings := p.Warnings()
	o.warnings(warnings)
	if g.strict && len(warnings) > 0 {
		o.printf("%s %d warning(s) treated as errors by --strict\n", o.bad("error:"), len(warnings))
		return 1
	}
	return 0
}

func cmdRender(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	outDir := ""
	fs.StringVar(&outDir, "output", "", "write rendered files under this directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "obscure render:", err)
		return 2
	}
	p, ok := loadPolicy(g, stderr)
	if !ok {
		return 1
	}
	d, err := renderPolicy(p)
	if err != nil {
		fmt.Fprintln(stderr, "obscure render:", err)
		return 1
	}
	if g.json {
		return o.emitJSON(d)
	}
	if outDir != "" {
		if err := writeRendered(d, outDir); err != nil {
			fmt.Fprintln(stderr, "obscure render:", err)
			return 1
		}
		o.printf("rendered %d files under %s\n", len(d.Artifacts), outDir)
		return 0
	}
	o.printf("%s\n", o.bold("Rendered policy"))
	o.printf("  artifacts: %d\n  services: %d\n  nftables tables: %d\n  packages: %s\n",
		len(d.Artifacts), len(d.Services), len(d.NFT), joinComma(d.Packages))
	for _, art := range d.Artifacts {
		o.printf("\n%s %s\n", o.bold("# "+art.Path), o.dim("("+art.Reason+")"))
		o.printf("%s", string(art.Content))
	}
	o.warnings(d.Warnings)
	return 0
}

func renderPolicy(p *policy.Policy) (*render.Desired, error) {
	sys := system.New()
	return render.Render(p, render.Options{
		Policy:           p,
		SSHDInstalled:    sys.Exists("/usr/sbin/sshd"),
		AppArmorEnabled:  sys.AppArmorEnabled(),
		SeccompSupported: sys.SeccompSupported(),
		LandlockABI:      sys.LandlockABI(),
		PathExists:       sys.Exists,
		SysctlExists:     sys.SysctlExists,
		UserID: func(name string) (int, bool) {
			u, err := sys.LookupUser(name)
			if err != nil {
				return 0, false
			}
			return u.UID, true
		},
	})
}

func writeRendered(d *render.Desired, outDir string) error {
	for _, art := range d.Artifacts {
		rel := strings.TrimPrefix(filepath.Clean(art.Path), "/")
		if rel == "" || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("refusing to write unsafe path %q", art.Path)
		}
		path := filepath.Join(outDir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, art.Content, art.Mode.Perm()); err != nil {
			return err
		}
	}
	return nil
}

func cmdExplain(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit explain:", err)
		return 2
	}
	p, ok := loadPolicy(g, stderr)
	if !ok {
		return 1
	}
	d, err := renderPolicy(p)
	if err != nil {
		fmt.Fprintln(stderr, "doit explain:", err)
		return 1
	}
	if g.json {
		payload := map[string]any{
			"policy": p, "artifacts": d.Artifacts, "services": d.Services,
			"sandboxes": d.Sandboxes, "nft": d.NFT, "sysctls": d.Sysctls,
			"packages": d.Packages, "warnings": d.Warnings, "notes": d.Notes,
		}
		return o.emitJSON(payload)
	}
	o.printf("%s role %s on %s\n", o.bold("Policy:"), p.Role, orDash(p.PublicInterface))
	o.printf("\n%s\n", o.bold("Exposure"))
	for _, spec := range []struct{ name, mode string }{
		{"ssh", p.Exposure.SSH}, {"https", p.Exposure.HTTPS}, {"http", p.Exposure.HTTP},
		{"smtp", p.Exposure.SMTP}, {"dns", p.Exposure.DNS}, {"ntp", p.Exposure.NTP},
	} {
		o.printf("  %-6s %s\n", spec.name, explainMode(spec.mode))
	}
	o.printf("\n%s\n", o.bold("Administration"))
	o.printf("  SSH port %d, password auth %v, root login %s\n", p.Admin.SSHPort, p.Admin.PasswordAuth, p.Admin.RootLogin)
	o.printf("  source CIDRs: %s\n", joinComma(p.Admin.SourceCIDRs))
	o.printf("  admin interfaces: %s\n", joinComma(p.AdminInterfaces()))
	o.printf("\n%s\n", o.bold("Privacy"))
	o.printf("  telemetry: %s\n  DNS: %s\n  log retention: %d days (max %d MB)\n",
		p.Privacy.Telemetry, p.Privacy.DNS, p.Privacy.LogRetentionDays, p.Privacy.LogMaxMB)
	o.printf("\n%s\n", o.bold("Managed files"))
	for _, art := range d.Artifacts {
		o.printf("  %-55s %s\n", art.Path, o.dim(art.Reason))
	}
	o.printf("\n%s\n", o.bold("Services"))
	for _, svc := range d.Services {
		o.printf("  %-30s enable=%-8s active=%-8s %s\n", svc.Name, orDash(svc.Enable), orDash(svc.Active), svc.Reason)
	}
	if len(d.Sandboxes) > 0 {
		o.printf("\n%s\n", o.bold("Sandboxes"))
		for _, sb := range d.Sandboxes {
			o.printf("  %-12s user=%-10s apparmor=%-8s landlock=%v network=%s\n",
				sb.Name, sb.UnitName, sb.AppArmorMode, sb.Landlock, sb.Network)
		}
	}
	o.printf("\n%s\n", o.bold("Packages"))
	o.printf("  %s\n", joinComma(d.Packages))
	for _, note := range d.Notes {
		o.printf("\n%s %s\n", o.dim("note:"), note)
	}
	o.warnings(d.Warnings)
	return 0
}

func explainMode(mode string) string {
	switch mode {
	case policy.ExposureDisabled:
		return "disabled (no accept rule; local listeners still show drift)"
	case policy.ExposureLoopback:
		return "loopback only"
	case policy.ExposureAdminOnly:
		return "admin-only (source CIDRs on admin interfaces)"
	case policy.ExposurePublic:
		return "public (public interface only)"
	}
	return mode
}
