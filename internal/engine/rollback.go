package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/obscure-toolkit/obscure/internal/system"
)

// Rollback restores a transaction by ID, or the newest committed transaction
// when id is empty.
func (e *Engine) Rollback(ctx context.Context, id string) (*Manifest, error) {
	if e.Sys.EUID() != 0 {
		return nil, fmt.Errorf("rollback requires root (try: sudo doit rollback)")
	}
	if err := e.ensureDirs(); err != nil {
		return nil, err
	}
	lock, err := system.AcquireLock(e.Sys.Path(filepath.Join(e.RunDir, "obscure.lock")))
	if err != nil {
		return nil, err
	}
	defer lock.Release()

	dir := ""
	if id == "" || id == "last" {
		list, err := e.ListTransactions()
		if err != nil {
			return nil, err
		}
		for _, txn := range list {
			if txn.Status == "committed" {
				dir = e.TransactionDir(txn.ID)
				break
			}
		}
		if dir == "" {
			return nil, fmt.Errorf("no committed transaction to roll back")
		}
	} else {
		dir = e.TransactionDir(id)
	}
	m, err := e.LoadManifest(dir)
	if err != nil {
		return nil, err
	}
	if m.Status == "rolled-back" {
		return m, fmt.Errorf("transaction %s was already rolled back", m.ID)
	}
	if err := e.RollbackTransaction(ctx, dir, "requested by operator"); err != nil {
		return nil, err
	}
	return e.LoadManifest(dir)
}

// RollbackTransaction restores every snapshot in a transaction manifest. It is
// safe to call after a partial apply; missing pieces are skipped.
func (e *Engine) RollbackTransaction(ctx context.Context, dir, reason string) error {
	m, err := e.LoadManifest(dir)
	if err != nil {
		return err
	}
	e.logf("rolling back transaction %s: %s", m.ID, reason)

	// Stop managed units and restore their original enablement before unit
	// files disappear.
	for _, snap := range m.Services {
		if err := e.restoreService(ctx, snap.Name, snap.Origin); err != nil {
			e.logf("rollback: service %s: %v", snap.Name, err)
		}
	}

	for _, snap := range m.Files {
		if err := e.restoreFile(dir, snap); err != nil {
			e.logf("rollback: file %s: %v", snap.Path, err)
		}
	}
	for i := len(m.Dirs) - 1; i >= 0; i-- {
		if err := e.Sys.Remove(m.Dirs[i]); err != nil && !os.IsNotExist(err) {
			e.logf("rollback: keeping non-empty directory %s", m.Dirs[i])
		}
	}

	_ = e.daemonReload(ctx)
	restoredSSH := false
	for _, snap := range m.Files {
		if strings.HasPrefix(snap.Path, "/etc/ssh/") {
			restoredSSH = true
		}
	}
	if restoredSSH {
		if err := e.reloadSSH(ctx); err != nil {
			e.logf("rollback: sshd was not reloaded: %v", err)
		}
	}
	e.restoreAppArmor(ctx, m)
	e.restoreNFT(ctx, dir, m)
	e.restoreSysctls(ctx, m)

	m.Status = "rolled-back"
	m.Reason = reason
	if err := e.writeManifest(dir, m); err != nil {
		return err
	}
	_ = e.Sys.WriteFileRaw(filepath.Join(dir, "rolledback"), []byte(m.ID+"\n"), 0o600)
	e.logf("transaction %s rolled back", m.ID)
	return nil
}

func (e *Engine) restoreFile(dir string, snap FileSnapshot) error {
	if !snap.Existed {
		if e.Sys.Exists(snap.Path) {
			if err := e.Sys.Remove(snap.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	}
	if snap.IsSymlink {
		_ = e.Sys.Remove(snap.Path)
		return e.Sys.Symlink(snap.LinkTarget, snap.Path)
	}
	data, err := e.Sys.ReadFile(blobPath(dir, snap.Blob))
	if err != nil {
		return err
	}
	if err := e.Sys.WriteFileOwned(snap.Path, data, os.FileMode(snap.Mode), snap.UID, snap.GID); err != nil {
		return err
	}
	return nil
}

func blobPath(dir, blob string) string {
	if blob == "" {
		return ""
	}
	if strings.HasPrefix(blob, "files/") {
		return filepath.Join(dir, blob)
	}
	return filepath.Join(dir, "files", blob)
}

func (e *Engine) restoreNFT(ctx context.Context, dir string, m *Manifest) {
	for _, snap := range m.NFT {
		parts := strings.Fields(snap.Table)
		if len(parts) != 2 {
			continue
		}
		if !snap.Existed {
			_ = e.deleteNFT(ctx, snap.Table)
			continue
		}
		data, err := e.Sys.ReadFile(blobPath(dir, snap.Blob))
		if err != nil {
			e.logf("rollback: nft %s: %v", snap.Table, err)
			continue
		}
		// The snapshot is a plain table declaration. Remove the current table
		// first so the old chains replace, rather than merge with, the new ones.
		_ = e.deleteNFT(ctx, snap.Table)
		if res := e.Sys.Runner.RunInput(ctx, data, "nft", "-f", "-"); !res.Success() {
			e.logf("rollback: nft %s: %s", snap.Table, res.Error())
		}
	}
}

func (e *Engine) restoreSysctls(ctx context.Context, m *Manifest) {
	keys := make([]string, 0, len(m.Sysctls))
	for key := range m.Sysctls {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := m.Sysctls[key]
		if value == "" {
			continue
		}
		if res := e.Sys.Runner.Run(ctx, "sysctl", "-w", key+"="+value); !res.Success() {
			e.logf("rollback: sysctl %s: %s", key, res.Error())
		}
	}
}

func (e *Engine) restoreAppArmor(ctx context.Context, m *Manifest) {
	names := make([]string, 0, len(m.AppArmor))
	for name := range m.AppArmor {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		mode := m.AppArmor[name]
		path := filepath.Join("/etc/apparmor.d", name)
		if mode == "" {
			if e.Sys.Exists(path) && e.commandExists("apparmor_parser") {
				if res := e.Sys.Runner.Run(ctx, "apparmor_parser", "-R", path); !res.Success() {
					e.logf("rollback: unload AppArmor %s: %s", name, res.Error())
				}
			}
			continue
		}
		if !e.commandExists("apparmor_parser") || !e.Sys.Exists(path) {
			continue
		}
		if res := e.Sys.Runner.Run(ctx, "apparmor_parser", "-r", path); !res.Success() {
			e.logf("rollback: reload AppArmor %s: %s", name, res.Error())
			continue
		}
		tool := "aa-enforce"
		if mode == "complain" {
			tool = "aa-complain"
		}
		_ = e.Sys.Runner.Run(ctx, tool, name)
	}
}

// WatchdogTimeout is the default grace period for a hung apply.
const WatchdogTimeout = 120 * time.Second

func (e *Engine) heartbeatPath(dir string) string { return filepath.Join(dir, "heartbeat") }
