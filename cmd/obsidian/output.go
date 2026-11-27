package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/engine"
	"github.com/obsidian-toolkit/obsidian/internal/policy"
)

type output struct {
	w       io.Writer
	json    bool
	color   bool
	verbose bool
}

func newOutput(w io.Writer, g *globals) *output {
	color := !g.noColor && os.Getenv("NO_COLOR") == "" && isTerminal(w)
	return &output{w: w, json: g.json, color: color, verbose: g.verbose}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (o *output) paint(code, s string) string {
	if !o.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (o *output) ok(s string) string   { return o.paint("32", s) }
func (o *output) warn(s string) string { return o.paint("33", s) }
func (o *output) bad(s string) string  { return o.paint("31", s) }
func (o *output) dim(s string) string  { return o.paint("2", s) }
func (o *output) bold(s string) string { return o.paint("1", s) }

func (o *output) printf(format string, args ...any) { fmt.Fprintf(o.w, format, args...) }

func (o *output) emitJSON(v any) int {
	enc := json.NewEncoder(o.w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "obsidian:", err)
		return 1
	}
	return 0
}

func (o *output) warnings(warnings []policy.Warning) {
	for _, w := range warnings {
		o.printf("%s %s\n", o.warn("warning:"), w.String())
	}
}

func (o *output) plan(p *engine.Plan, showDiff bool) {
	if len(p.Changes) == 0 {
		o.printf("%s host already matches the policy\n", o.ok("ok:"))
	} else {
		o.printf("%s %d change(s), scope %s\n", o.bold("Plan:"), len(p.Changes), scopeLabel(p.Scope))
		for _, c := range p.Changes {
			risk := o.ok("safe")
			switch c.Risk {
			case engine.RiskAttention:
				risk = o.warn("attention")
			case engine.RiskLockout:
				risk = o.bad("lockout")
			}
			oldNew := ""
			if c.Old != "" || c.New != "" {
				oldNew = fmt.Sprintf(" (%s -> %s)", orDash(c.Old), orDash(c.New))
			}
			o.printf("  %s %-8s %-12s %s%s\n    %s\n",
				risk, c.Action, c.Kind, c.Target, oldNew, o.dim(c.Reason))
			if showDiff && c.Diff != "" {
				for _, line := range strings.Split(strings.TrimRight(c.Diff, "\n"), "\n") {
					o.printf("    %s\n", colorDiff(o, line))
				}
			}
		}
	}
	if len(p.Packages) > 0 {
		o.printf("\n%s %s\n", o.bold("Packages to install:"), strings.Join(p.Packages, ", "))
	}
	o.warnings(p.Warnings)
	o.lockout(p.Lockout)
	for _, e := range p.Errors {
		o.printf("%s %s\n", o.bad("error:"), e)
	}
}

func colorDiff(o *output, line string) string {
	switch {
	case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
		return o.bold(line)
	case strings.HasPrefix(line, "+"):
		return o.ok(line)
	case strings.HasPrefix(line, "-"):
		return o.bad(line)
	}
	return line
}

func (o *output) lockout(l engine.LockoutReport) {
	if !l.Remote {
		return
	}
	o.printf("\n%s SSH session from %s (server port %d)\n", o.bold("Remote session:"), orDash(l.ClientIP), l.SessionPort)
	if l.Risky {
		o.printf("  %s the policy change may end this session:\n", o.bad("lockout risk:"))
		for _, reason := range l.Reasons {
			o.printf("    - %s\n", reason)
		}
		if l.Allowed {
			o.printf("  %s\n", o.warn("continuing because --allow-lockout was given"))
		}
	}
}

func scopeLabel(s engine.Scope) string {
	if s.IsFull() {
		return "full policy"
	}
	if s.Sandbox == "" {
		return "all sandboxes"
	}
	return "sandbox " + s.Sandbox
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (o *output) checks(r *engine.VerifyResult) {
	drift := r.Drift()
	shown := 0
	sections := map[string]bool{}
	for _, c := range r.Checks {
		if c.Status == engine.CheckOK && !o.verbose {
			continue
		}
		shown++
		sections[c.Section] = true
		status := o.ok("ok")
		switch c.Status {
		case engine.CheckDrift:
			status = o.bad("drift")
		case engine.CheckWarn:
			status = o.warn("warn")
		case engine.CheckSkip:
			status = o.dim("skip")
		}
		detail := ""
		if c.Expected != "" || c.Actual != "" {
			detail = fmt.Sprintf(" expected %s, got %s", orDash(c.Expected), orDash(c.Actual))
		}
		if c.Detail != "" {
			detail += " - " + c.Detail
		}
		o.printf("%s %-14s %s%s\n", status, c.Section, c.Target, detail)
	}
	if shown == 0 {
		o.printf("%s all %d checks match the policy\n", o.ok("ok:"), len(r.Checks))
	} else if drift == 0 {
		o.printf("\n%s %d check(s) need attention, no drift\n", o.warn("warn:"), shown)
	} else {
		o.printf("\n%s %d drift item(s)\n", o.bad("drift:"), drift)
	}
	o.warnings(r.Warnings)
}

func (o *output) statusJSON(v any) { _ = o.emitJSON(v) }

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
