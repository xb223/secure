// Command obscure is a policy-driven Debian security and privacy toolkit.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/engine"
	"github.com/obscure-toolkit/obscure/internal/policy"
	"github.com/obscure-toolkit/obscure/internal/system"
)

var version = "0.1.0"

const defaultConfigPath = "/etc/obscure/policy.toml"

type globals struct {
	config        string
	json          bool
	noColor       bool
	verbose       bool
	strict        bool
	yes           bool
	dryRun        bool
	allowLockout  bool
	allowDegraded bool
	noPackages    bool
	sandbox       string
	timeout       int
}

func main() {
	ctx := context.Background()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	g := &globals{config: defaultConfigPath, timeout: int(engine.WatchdogTimeout.Seconds())}
	global := flag.NewFlagSet("obscure", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	addGlobalFlags(global, g)
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printHelp(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "doit:", err)
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		printHelp(stdout)
		return 0
	}
	command := rest[0]
	cmdArgs := rest[1:]

	switch command {
	case "help", "-h", "--help":
		printHelp(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "obscure %s\n", version)
		return 0
	case "__watchdog":
		return cmdWatchdog(cmdArgs, stderr)
	}

	out := newOutput(stdout, g)
	switch command {
	case "init":
		return cmdInit(ctx, g, out, cmdArgs, stderr)
	case "check":
		return cmdCheck(ctx, g, out, cmdArgs, stderr)
	case "plan":
		return cmdPlan(ctx, g, out, cmdArgs, stderr)
	case "apply":
		return cmdApply(ctx, g, out, cmdArgs, stderr)
	case "verify":
		return cmdVerify(ctx, g, out, cmdArgs, stderr, false)
	case "drift":
		return cmdVerify(ctx, g, out, cmdArgs, stderr, true)
	case "status":
		return cmdStatus(ctx, g, out, cmdArgs, stderr)
	case "rollback":
		return cmdRollback(ctx, g, out, cmdArgs, stderr)
	case "isolate":
		return cmdIsolate(ctx, g, out, cmdArgs, stderr)
	case "render":
		return cmdRender(ctx, g, out, cmdArgs, stderr)
	case "explain":
		return cmdExplain(ctx, g, out, cmdArgs, stderr)
	case "sandbox-run":
		return cmdSandboxRun(cmdArgs, stderr)
	default:
		fmt.Fprintf(stderr, "doit: unknown command %q (try obscure help)\n", command)
		return 2
	}
}

func addGlobalFlags(fs *flag.FlagSet, g *globals) {
	fs.StringVar(&g.config, "config", g.config, "policy file")
	fs.BoolVar(&g.json, "json", false, "machine-readable output")
	fs.BoolVar(&g.noColor, "no-color", false, "disable color")
	fs.BoolVar(&g.verbose, "verbose", false, "show every command and check")
	fs.BoolVar(&g.strict, "strict", false, "treat policy warnings as errors")
	fs.BoolVar(&g.yes, "yes", false, "do not ask for confirmation")
	fs.BoolVar(&g.dryRun, "dry-run", false, "show the plan without changing the host")
	fs.BoolVar(&g.allowLockout, "allow-lockout", false, "permit changes that may end the current SSH session")
	fs.BoolVar(&g.allowDegraded, "allow-degraded", false, "continue when a requested isolation feature is unavailable")
	fs.BoolVar(&g.noPackages, "no-packages", false, "never install packages")
	fs.StringVar(&g.sandbox, "sandbox", "", "limit the operation to one sandbox")
	fs.IntVar(&g.timeout, "timeout", g.timeout, "watchdog grace period in seconds")
}

func newEngine(g *globals, stdout, stderr io.Writer) *engine.Engine {
	return &engine.Engine{
		Sys: system.New(), ConfigPath: g.config,
		StateDir: engine.DefaultStateDir, RunDir: engine.DefaultRunDir,
		AllowDegraded: g.allowDegraded, NoPackages: g.noPackages, Strict: g.strict,
		Verbose: g.verbose, Out: stdout, Err: stderr,
	}
}

func loadPolicy(g *globals, stderr io.Writer) (*policy.Policy, bool) {
	p, err := policy.Load(g.config)
	if err != nil {
		fmt.Fprintln(stderr, "doit:", err)
		return nil, false
	}
	return p, true
}

func requireRoot(g *globals, stderr io.Writer, command string) bool {
	if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "doit: %s requires root (try: sudo doit %s)\n", command, command)
		return false
	}
	return true
}

func scopeFrom(g *globals) engine.Scope {
	if g.sandbox != "" {
		return engine.SandboxScope(g.sandbox)
	}
	return engine.FullScope()
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `obscure - policy-driven Debian security and privacy toolkit

Usage:
  obscure [global flags] <command> [command flags]

Commands:
  init        write a starter policy to /etc/obscure/policy.toml
  check       parse and validate the policy, with warnings
  plan        show every change apply would make
  apply       apply the policy transactionally, with rollback on failure
  verify      compare the live host to the policy
  drift       show only drift found by verify
  status      show applied state and recent transactions
  rollback    restore a previous transaction
  isolate     apply only one sandbox (same as apply --sandbox NAME)
  render      render managed files without touching the host
  explain     explain what the policy asks for and why
  version     print the version
  help        show this help

Global flags:
  --config PATH        policy file (default /etc/obscure/policy.toml)
  --json               machine-readable output
  --no-color           disable color
  --verbose            show details
  --strict             treat policy warnings as errors
  --yes                do not ask for confirmation
  --dry-run            plan only, never change the host
  --allow-lockout      permit changes that may end the current SSH session
  --allow-degraded     continue when isolation features are unavailable
  --no-packages        never install packages
  --sandbox NAME       limit plan/apply/verify to one sandbox
  --timeout SECONDS    watchdog grace period (default 120)

The toolkit refuses to apply a firewall or SSH change that could lock out
the SSH session it is running in, unless --allow-lockout is given.
`)
}

// exitCode maps a boolean success and drift count to a process status.
func exitCode(ok bool, drift int) int {
	if !ok || drift > 0 {
		return 1
	}
	return 0
}

func joinComma(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
