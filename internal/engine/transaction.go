package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/obsidian-toolkit/obsidian/internal/policy"
	"github.com/obsidian-toolkit/obsidian/internal/render"
	"github.com/obsidian-toolkit/obsidian/internal/system"
)

const txnVersion = 1

// FileSnapshot is the state of one file before apply.
type FileSnapshot struct {
	Path       string `json:"path"`
	Existed    bool   `json:"existed"`
	IsSymlink  bool   `json:"is_symlink,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	Blob       string `json:"blob,omitempty"`
	Mode       uint32 `json:"mode,omitempty"`
	UID        int    `json:"uid,omitempty"`
	GID        int    `json:"gid,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

// ServiceSnapshot is the state of one unit before apply.
type ServiceSnapshot struct {
	Name   string        `json:"name"`
	Origin ServiceOrigin `json:"origin"`
}

// NFTSnapshot is one nftables table before apply.
type NFTSnapshot struct {
	Table   string `json:"table"`
	Existed bool   `json:"existed"`
	Blob    string `json:"blob,omitempty"`
}

// Manifest records everything needed to undo a transaction.
type Manifest struct {
	Version    int               `json:"version"`
	ID         string            `json:"id"`
	Created    time.Time         `json:"created"`
	PolicyPath string            `json:"policy_path"`
	PolicyHash string            `json:"policy_hash"`
	Scope      Scope             `json:"scope"`
	Hostname   string            `json:"hostname"`
	Status     string            `json:"status"`
	Reason     string            `json:"reason,omitempty"`
	Files      []FileSnapshot    `json:"files"`
	Dirs       []string          `json:"dirs,omitempty"`
	Services   []ServiceSnapshot `json:"services"`
	NFT        []NFTSnapshot     `json:"nft"`
	Sysctls    map[string]string `json:"sysctls,omitempty"`
	AppArmor   map[string]string `json:"apparmor,omitempty"`
	Packages   []string          `json:"packages,omitempty"`
	Changes    int               `json:"changes"`
}

// TransactionDir returns the directory for a transaction.
func (e *Engine) TransactionDir(id string) string { return filepath.Join(e.TransactionsDir(), id) }

func (e *Engine) newTransaction(policyHash string, scope Scope, changes int) (string, *Manifest, error) {
	if err := e.ensureDirs(); err != nil {
		return "", nil, err
	}
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return "", nil, err
	}
	id := e.Sys.Now().Format("20060102T150405") + "-" + hex.EncodeToString(suffix)
	dir := e.TransactionDir(id)
	if err := e.Sys.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return "", nil, err
	}
	m := &Manifest{
		Version: txnVersion, ID: id, Created: e.Sys.Now(), PolicyPath: e.ConfigPath,
		PolicyHash: policyHash, Scope: scope, Hostname: e.Sys.Hostname(),
		Status: "pending", Changes: changes, Sysctls: map[string]string{}, AppArmor: map[string]string{},
	}
	return dir, m, nil
}

func (e *Engine) writeManifest(dir string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return e.Sys.WriteFileAtomic(filepath.Join(dir, "manifest.json"), data, 0o600, false)
}

// LoadManifest reads a transaction manifest.
func (e *Engine) LoadManifest(dir string) (*Manifest, error) {
	data, err := e.Sys.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.Version != txnVersion {
		return nil, fmt.Errorf("transaction version %d is not supported", m.Version)
	}
	if m.Sysctls == nil {
		m.Sysctls = map[string]string{}
	}
	if m.AppArmor == nil {
		m.AppArmor = map[string]string{}
	}
	return &m, nil
}

// TransactionSummary is a row for rollback --list.
type TransactionSummary struct {
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	Status   string    `json:"status"`
	Scope    Scope     `json:"scope"`
	Changes  int       `json:"changes"`
	Hostname string    `json:"hostname"`
}

// ListTransactions lists transactions, newest first.
func (e *Engine) ListTransactions() ([]TransactionSummary, error) {
	entries, err := e.Sys.ReadDir(e.TransactionsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return []TransactionSummary{}, nil
		}
		return nil, err
	}
	out := []TransactionSummary{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		m, err := e.LoadManifest(filepath.Join(e.TransactionsDir(), entry.Name()))
		if err != nil {
			continue
		}
		out = append(out, TransactionSummary{ID: m.ID, Created: m.Created, Status: m.Status, Scope: m.Scope, Changes: m.Changes, Hostname: m.Hostname})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func (e *Engine) snapshot(ctx context.Context, p *policy.Policy, d *render.Desired, st *State, scope Scope, dir string, m *Manifest) error {
	files := map[string]bool{}
	addFile := func(path string, force bool) error {
		if files[path] || (!force && !inScope(path, scope)) {
			return nil
		}
		files[path] = true
		if err := e.snapshotFileErr(dir, path, &m.Files, &m.Dirs); err != nil {
			return err
		}
		return nil
	}
	for _, art := range d.Artifacts {
		if err := addFile(art.Path, false); err != nil {
			return err
		}
	}
	for path := range st.Files {
		if err := addFile(path, false); err != nil {
			return err
		}
	}
	if err := addFile(e.StatePath(), true); err != nil {
		return err
	}

	svcs := map[string]bool{}
	addSvc := func(name string) {
		if svcs[name] || !serviceInScope(name, scope) {
			return
		}
		svcs[name] = true
		live := e.serviceState(ctx, name)
		m.Services = append(m.Services, ServiceSnapshot{Name: name, Origin: originFromLive(live)})
	}
	for _, svc := range d.Services {
		addSvc(svc.Name)
	}
	for name := range st.Services {
		addSvc(name)
	}

	nfts := map[string]bool{}
	addNFT := func(table string) {
		if nfts[table] || !tableNameInScope(table, scope) {
			return
		}
		nfts[table] = true
		snap := NFTSnapshot{Table: table}
		parts := strings.Fields(table)
		if len(parts) == 2 {
			res := e.Sys.Runner.Run(ctx, "nft", "list", "table", parts[0], parts[1])
			if res.Success() {
				snap.Existed = true
				snap.Blob = "nft-" + sanitize(parts[1]) + ".nft"
				if err := e.Sys.WriteFileRaw(filepath.Join(dir, "files", snap.Blob), res.Stdout, 0o600); err != nil {
					return
				}
			}
		}
		m.NFT = append(m.NFT, snap)
	}
	for _, table := range d.NFT {
		addNFT(table.Name)
	}
	for table := range st.NFT {
		addNFT(table)
	}

	for _, s := range d.Sysctls {
		v, _ := e.Sys.SysctlValue(s.Key)
		m.Sysctls[s.Key] = v
	}
	modes, _ := e.appArmorModes(ctx)
	for _, sb := range d.Sandboxes {
		if sb.AppArmorMode != "off" {
			m.AppArmor[sb.ProfileName] = modes[sb.ProfileName]
		}
	}
	for name := range st.AppArmor {
		if _, ok := m.AppArmor[name]; !ok {
			m.AppArmor[name] = modes[name]
		}
	}
	m.Dirs = dedupeStrings(m.Dirs)
	return nil
}

func (e *Engine) snapshotFile(dir, path string) (FileSnapshot, []string, error) {
	var out []FileSnapshot
	var dirs []string
	if err := e.snapshotFileErr(dir, path, &out, &dirs); err != nil {
		return FileSnapshot{}, nil, err
	}
	if len(out) == 0 {
		return FileSnapshot{Path: path}, dirs, nil
	}
	return out[0], dirs, nil
}

func (e *Engine) snapshotFileErr(dir, path string, out *[]FileSnapshot, dirs *[]string) error {
	for _, existing := range *out {
		if existing.Path == path {
			return nil
		}
	}
	info, err := e.Sys.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			*out = append(*out, FileSnapshot{Path: path})
			*dirs = append(*dirs, missingDirs(e.Sys, path)...)
			return nil
		}
		return fmt.Errorf("snapshot %s: %w", path, err)
	}
	if info.IsDir {
		return fmt.Errorf("snapshot %s: path is a directory", path)
	}
	snap := FileSnapshot{Path: path, Existed: true, Mode: uint32(info.Mode.Perm()), UID: info.UID, GID: info.GID}
	if info.IsSymlink {
		snap.IsSymlink = true
		snap.LinkTarget = info.LinkTarget
		*out = append(*out, snap)
		*dirs = append(*dirs, missingDirs(e.Sys, path)...)
		return nil
	}
	data, err := e.Sys.ReadFile(path)
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", path, err)
	}
	snap.SHA256 = system.SHA256(data)
	snap.Blob = "files/" + snap.SHA256
	if err := e.Sys.WriteFileRaw(filepath.Join(dir, "files", snap.SHA256), data, 0o600); err != nil {
		return err
	}
	*out = append(*out, snap)
	*dirs = append(*dirs, missingDirs(e.Sys, path)...)
	return nil
}

func missingDirs(sys *system.System, path string) []string {
	var out []string
	dir := filepath.Dir(path)
	for dir != "/" && dir != "." {
		if sys.Exists(dir) {
			break
		}
		out = append([]string{dir}, out...)
		dir = filepath.Dir(dir)
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
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

func sanitize(s string) string {
	return strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(s)
}

// Fingerprint identifies the exact plan an operator confirmed. Apply refuses
// to run if a fresh plan no longer matches.
func (p *Plan) Fingerprint() string { return planFingerprint(p) }

func planFingerprint(plan *Plan) string {
	payload := struct {
		PolicyHash string
		Scope      Scope
		Changes    []Change
		Packages   []string
		Errors     []string
	}{plan.PolicyHash, plan.Scope, plan.Changes, plan.Packages, plan.Errors}
	data, _ := json.Marshal(payload)
	return system.SHA256(data)
}
