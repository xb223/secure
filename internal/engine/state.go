// Package engine plans, applies, verifies and rolls back policy changes.
package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/obsidian-toolkit/obsidian/internal/system"
)

const stateVersion = 1

// ServiceOrigin records the state of a unit before obsidian first managed it.
type ServiceOrigin struct {
	Exists  bool   `json:"exists"`
	Enabled string `json:"enabled,omitempty"`
	Active  bool   `json:"active"`
	Masked  bool   `json:"masked"`
}

// State is the durable record of what obsidian manages. It is used to detect
// orphans and to restore service state when a service leaves the policy.
type State struct {
	Version     int                      `json:"version"`
	PolicyPath  string                   `json:"policy_path,omitempty"`
	PolicyHash  string                   `json:"policy_hash,omitempty"`
	LastApply   time.Time                `json:"last_apply,omitempty"`
	LastScope   string                   `json:"last_scope,omitempty"`
	Transaction string                   `json:"transaction,omitempty"`
	Files       map[string]string        `json:"files,omitempty"`
	Units       []string                 `json:"units,omitempty"`
	AppArmor    map[string]string        `json:"apparmor,omitempty"`
	Services    map[string]ServiceOrigin `json:"services,omitempty"`
	NFT         map[string]string        `json:"nft,omitempty"`
	Sandboxes   []string                 `json:"sandboxes,omitempty"`
}

func newState() *State {
	return &State{
		Version: stateVersion, Files: map[string]string{}, AppArmor: map[string]string{},
		Services: map[string]ServiceOrigin{}, NFT: map[string]string{},
	}
}

// StatePath returns the state file path.
func (e *Engine) StatePath() string { return filepath.Join(e.StateDir, "state.json") }

// LoadState reads state.json. A missing file is an empty state.
func (e *Engine) LoadState() (*State, error) {
	data, err := e.Sys.ReadFile(e.StatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return newState(), nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", e.StatePath(), err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("state version %d is not supported (want %d)", st.Version, stateVersion)
	}
	if st.Files == nil {
		st.Files = map[string]string{}
	}
	if st.AppArmor == nil {
		st.AppArmor = map[string]string{}
	}
	if st.Services == nil {
		st.Services = map[string]ServiceOrigin{}
	}
	if st.NFT == nil {
		st.NFT = map[string]string{}
	}
	return &st, nil
}

// WriteState atomically writes state.json with root-only permissions.
func (e *Engine) WriteState(st *State) error {
	st.Version = stateVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := e.Sys.MkdirAll(e.StateDir, 0o700); err != nil {
		return err
	}
	return e.Sys.WriteFileAtomic(e.StatePath(), data, 0o600, false)
}

func (e *Engine) ensureDirs() error {
	for _, dir := range []string{e.StateDir, e.TransactionsDir(), e.RunDir} {
		if err := e.Sys.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) TransactionsDir() string { return filepath.Join(e.StateDir, "transactions") }

func stateDigest(st *State) string {
	data, _ := json.Marshal(st)
	return system.SHA256(data)
}
