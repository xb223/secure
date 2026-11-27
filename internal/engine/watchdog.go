package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/obscure-toolkit/obscure/internal/system"
)

const (
	// DefaultStateDir is where obscure keeps state and transactions.
	DefaultStateDir = "/var/lib/obscure"
	// DefaultRunDir is where the lock and temporary preflight files live.
	DefaultRunDir = "/run/obscure"
)

// startWatchdog launches a detached helper that rolls the transaction back if
// apply stops making progress. The returned function stops the helper.
func (e *Engine) startWatchdog(ctx context.Context, dir string, timeout int) func() {
	if timeout <= 0 {
		timeout = int(WatchdogTimeout / time.Second)
	}
	exe, err := os.Executable()
	if err != nil {
		e.logf("warning: cannot start watchdog: %v", err)
		return func() {}
	}
	logPath := filepath.Join(dir, "watchdog.log")
	logFile, err := os.OpenFile(e.Sys.Path(logPath), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		e.logf("warning: cannot start watchdog: %v", err)
		return func() {}
	}
	cmd := exec.Command(exe, "__watchdog", "--transaction-dir", dir, "--timeout", fmt.Sprintf("%d", timeout))
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		e.logf("warning: cannot start watchdog: %v", err)
		return func() {}
	}
	_ = e.touchHeartbeat(dir)

	stop := make(chan struct{})
	done := make(chan struct{})
	interval := time.Duration(timeout) * time.Second / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > 10*time.Second {
		interval = 10 * time.Second
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = e.touchHeartbeat(dir)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		logFile.Close()
	}
}

func (e *Engine) touchHeartbeat(dir string) error {
	return e.Sys.WriteFileRaw(filepath.Join(dir, "heartbeat"), []byte(e.Sys.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600)
}

// RunWatchdog is the detached helper entry point. It rolls the transaction back
// when the heartbeat goes stale, and exits when apply commits or rolls back.
func RunWatchdog(dir string, timeout int) error {
	if timeout <= 0 {
		timeout = int(WatchdogTimeout / time.Second)
	}
	sys := system.New()
	eng := &Engine{Sys: sys, StateDir: DefaultStateDir, RunDir: DefaultRunDir, Out: os.Stdout}
	m, err := eng.LoadManifest(dir)
	if err != nil {
		return err
	}
	deadline := time.Duration(timeout) * time.Second
	for {
		if m.Status != "pending" || sys.Exists(filepath.Join(dir, "committed")) || sys.Exists(filepath.Join(dir, "rolledback")) {
			return nil
		}
		beat := m.Created
		if info, err := sys.Stat(filepath.Join(dir, "heartbeat")); err == nil {
			beat = info.ModTime
		}
		if sys.Now().Sub(beat) > deadline {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			err := eng.RollbackTransaction(ctx, dir, fmt.Sprintf("watchdog: no progress for %s", deadline))
			cancel()
			return err
		}
		time.Sleep(time.Second)
	}
}
