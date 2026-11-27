package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/engine"
)

func cmdPlan(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit plan:", err)
		return 2
	}
	if !requireRoot(g, stderr, "plan") {
		return 1
	}
	p, ok := loadPolicy(g, stderr)
	if !ok {
		return 1
	}
	e := newEngine(g, o.w, stderr)
	plan, err := e.Plan(ctx, p, scopeFrom(g), g.allowLockout)
	if err != nil {
		fmt.Fprintln(stderr, "doit plan:", err)
		return 1
	}
	if g.json {
		o.emitJSON(plan)
	} else {
		o.plan(plan, true)
	}
	if plan.HasErrors() {
		return 1
	}
	return 0
}

func cmdApply(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit apply:", err)
		return 2
	}
	if !requireRoot(g, stderr, "apply") {
		return 1
	}
	p, ok := loadPolicy(g, stderr)
	if !ok {
		return 1
	}
	e := newEngine(g, o.w, stderr)
	plan, err := e.Plan(ctx, p, scopeFrom(g), g.allowLockout)
	if err != nil {
		fmt.Fprintln(stderr, "doit apply:", err)
		return 1
	}
	if g.json && !g.dryRun {
		// Keep JSON output machine-readable; human progress goes to stderr.
		e.Out = stderr
	}
	if !g.json {
		o.plan(plan, true)
	}
	if plan.HasErrors() {
		if g.json {
			o.emitJSON(plan)
		}
		fmt.Fprintln(stderr, "doit: refusing to apply until the errors above are resolved")
		return 1
	}
	if !plan.HasChanges() {
		if g.json {
			o.emitJSON(plan)
		} else {
			o.printf("%s nothing to do\n", o.ok("ok:"))
		}
		return 0
	}
	if g.dryRun {
		if g.json {
			o.emitJSON(plan)
		} else {
			o.printf("\n%s\n", o.dim("dry run: no changes made"))
		}
		return 0
	}
	if !g.yes {
		if !confirm(fmt.Sprintf("Apply %d change(s) to this host?", len(plan.Changes))) {
			o.printf("aborted\n")
			return 1
		}
	}
	result, err := e.Apply(ctx, p, scopeFrom(g), g.timeout, g.allowLockout, plan.Fingerprint())
	if g.json {
		if result != nil {
			o.emitJSON(result)
		}
		if err != nil {
			fmt.Fprintln(stderr, "doit apply:", err)
			return 1
		}
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "doit apply:", err)
		return 1
	}
	if result.RolledBack {
		o.printf("%s transaction %s was rolled back; the host is unchanged\n", o.warn("failed:"), result.TransactionID)
		return 1
	}
	o.printf("%s transaction %s committed (%d change(s))\n", o.ok("ok:"), result.TransactionID, result.Changes)
	if result.Checks != nil && result.Checks.Drift() > 0 {
		o.checks(result.Checks)
		return 1
	}
	return 0
}

func confirm(prompt string) bool {
	if !isTerminal(os.Stdin) && !isTerminal(os.Stdout) {
		fmt.Fprintln(os.Stderr, "doit: refusing to prompt without a terminal (use --yes to confirm non-interactively)")
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func cmdVerify(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer, driftOnly bool) int {
	name := "verify"
	if driftOnly {
		name = "drift"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "doit %s: %v\n", name, err)
		return 2
	}
	if !requireRoot(g, stderr, name) {
		return 1
	}
	p, ok := loadPolicy(g, stderr)
	if !ok {
		return 1
	}
	e := newEngine(g, o.w, stderr)
	result, err := e.Verify(ctx, p, scopeFrom(g))
	if err != nil {
		fmt.Fprintf(stderr, "doit %s: %v\n", name, err)
		return 1
	}
	if driftOnly {
		filtered := *result
		filtered.Checks = nil
		for _, c := range result.Checks {
			if c.Status == engine.CheckDrift {
				filtered.Checks = append(filtered.Checks, c)
			}
		}
		result = &filtered
	}
	if g.json {
		o.emitJSON(result)
	} else {
		o.checks(result)
	}
	return exitCode(true, result.Drift())
}

type statusReport struct {
	PolicyPath    string                      `json:"policy_path,omitempty"`
	PolicyHash    string                      `json:"policy_hash,omitempty"`
	LastApply     string                      `json:"last_apply,omitempty"`
	LastScope     string                      `json:"last_scope,omitempty"`
	Transaction   string                      `json:"transaction,omitempty"`
	ManagedFiles  int                         `json:"managed_files"`
	ManagedUnits  int                         `json:"managed_units"`
	ManagedNFT    int                         `json:"managed_nft_tables"`
	ManagedSvcs   int                         `json:"managed_services"`
	Sandboxes     []string                    `json:"sandboxes,omitempty"`
	Transactions  []engine.TransactionSummary `json:"transactions,omitempty"`
	Checks        *engine.VerifyResult        `json:"checks,omitempty"`
	StateModified bool                        `json:"state_present"`
}

func cmdStatus(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addGlobalFlags(fs, g)
	verify := false
	fs.BoolVar(&verify, "verify", false, "also compare the live host to the policy")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit status:", err)
		return 2
	}
	if !requireRoot(g, stderr, "status") {
		return 1
	}
	e := newEngine(g, o.w, stderr)
	st, err := e.LoadState()
	if err != nil {
		fmt.Fprintln(stderr, "doit status:", err)
		return 1
	}
	txns, err := e.ListTransactions()
	if err != nil {
		fmt.Fprintln(stderr, "doit status:", err)
		return 1
	}
	report := statusReport{
		PolicyPath: st.PolicyPath, PolicyHash: st.PolicyHash, LastScope: st.LastScope,
		Transaction: st.Transaction, ManagedFiles: len(st.Files), ManagedUnits: len(st.Units),
		ManagedNFT: len(st.NFT), ManagedSvcs: len(st.Services), Sandboxes: st.Sandboxes,
		StateModified: !st.LastApply.IsZero(),
	}
	if !st.LastApply.IsZero() {
		report.LastApply = st.LastApply.Format("2006-01-02 15:04:05 MST")
	}
	for i := 0; i < len(txns) && i < 10; i++ {
		report.Transactions = append(report.Transactions, txns[i])
	}
	if verify {
		p, ok := loadPolicy(g, stderr)
		if !ok {
			return 1
		}
		result, err := e.Verify(ctx, p, scopeFrom(g))
		if err != nil {
			fmt.Fprintln(stderr, "doit status:", err)
			return 1
		}
		report.Checks = result
	}
	if g.json {
		o.emitJSON(report)
		return 0
	}
	if !report.StateModified {
		o.printf("%s doit has not applied a policy on this host\n", o.warn("status:"))
	} else {
		o.printf("%s applied %s (scope %s, transaction %s)\n", o.bold("Policy:"), report.LastApply, orDash(report.LastScope), orDash(report.Transaction))
		o.printf("  source: %s\n", orDash(report.PolicyPath))
		o.printf("  digest: %s\n", orDash(report.PolicyHash))
	}
	o.printf("  managed: %d files, %d units, %d services, %d nftables tables\n",
		report.ManagedFiles, report.ManagedUnits, report.ManagedSvcs, report.ManagedNFT)
	if len(report.Sandboxes) > 0 {
		o.printf("  sandboxes: %s\n", strings.Join(report.Sandboxes, ", "))
	}
	if len(report.Transactions) > 0 {
		o.printf("\n%s\n", o.bold("Recent transactions"))
		for _, txn := range report.Transactions {
			o.printf("  %s  %-10s %-16s %d change(s)\n", txn.Created.Format("2006-01-02 15:04"), txn.Status, scopeLabel(txn.Scope), txn.Changes)
		}
	}
	if report.Checks != nil {
		o.printf("\n")
		o.checks(report.Checks)
	}
	return 0
}

func cmdIsolate(ctx context.Context, g *globals, o *output, args []string, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: doit isolate NAME [flags]")
		return 2
	}
	g.sandbox = args[0]
	return cmdApply(ctx, g, o, args[1:], stderr)
}
