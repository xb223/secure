package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/obscure-toolkit/obscure/internal/engine"
	"github.com/obscure-toolkit/obscure/internal/landlock"
	"github.com/obscure-toolkit/obscure/internal/sandbox"
)

// cmdSandboxRun applies Landlock rules and then replaces itself with the
// sandboxed service. It is invoked by generated systemd units.
func cmdSandboxRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sandbox-run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := ""
	fs.StringVar(&configPath, "config", "", "sandbox config file")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "doit sandbox-run:", err)
		return 2
	}
	if configPath == "" {
		fmt.Fprintln(stderr, "doit sandbox-run: --config is required")
		return 2
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "doit sandbox-run: refusing to run as root")
		return 1
	}
	cfg, err := sandbox.Load(configPath)
	if err != nil {
		fmt.Fprintln(stderr, "doit sandbox-run:", err)
		return 1
	}
	if landlock.DetectABI() == 0 {
		fmt.Fprintln(stderr, "doit sandbox-run: this kernel does not support Landlock")
		return 1
	}
	readOnly := append([]string{}, cfg.ImplicitReadOnly...)
	readOnly = append(readOnly, cfg.ReadOnly...)
	readOnly = append(readOnly, "/proc", "/sys", "/dev/urandom", "/dev/random", "/etc/localtime")
	readWrite := append([]string{}, cfg.ReadWrite...)
	readWrite = append(readWrite, "/dev/null", "/dev/zero", "/dev/shm", "/tmp")

	readOnly = existingPaths(readOnly, stderr)
	readWrite = existingPaths(readWrite, stderr)
	if err := landlock.Apply(readWrite, readOnly); err != nil {
		fmt.Fprintln(stderr, "doit sandbox-run:", err)
		return 1
	}
	argv := append([]string{cfg.Binary}, cfg.Args...)
	if err := syscall.Exec(cfg.Binary, argv, os.Environ()); err != nil {
		fmt.Fprintf(stderr, "doit sandbox-run: exec %s: %v\n", cfg.Binary, err)
		return 1
	}
	return 0
}

func existingPaths(paths []string, stderr io.Writer) []string {
	seen := map[string]bool{}
	var out []string
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if _, err := os.Stat(path); err != nil {
			fmt.Fprintf(stderr, "doit sandbox-run: skipping unavailable path %s: %v\n", path, err)
			continue
		}
		out = append(out, path)
	}
	return out
}

func cmdWatchdog(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("__watchdog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := ""
	timeout := 0
	fs.StringVar(&dir, "transaction-dir", "", "transaction directory")
	fs.IntVar(&timeout, "timeout", 0, "grace period in seconds")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, "obscure watchdog:", err)
		return 2
	}
	if dir == "" {
		fmt.Fprintln(stderr, "obscure watchdog: --transaction-dir is required")
		return 2
	}
	if err := engine.RunWatchdog(dir, timeout); err != nil {
		fmt.Fprintln(stderr, "obscure watchdog:", err)
		return 1
	}
	return 0
}
