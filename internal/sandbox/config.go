// Package sandbox contains the runtime side of obscure sandboxes. The
// sandbox-run command is a small, unprivileged wrapper that applies Landlock
// filesystem rules and then execs the service binary.
package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is written by the renderer and read by sandbox-run.
type Config struct {
	Name             string   `json:"name"`
	Binary           string   `json:"binary"`
	Args             []string `json:"args,omitempty"`
	ReadWrite        []string `json:"read_write,omitempty"`
	ReadOnly         []string `json:"read_only,omitempty"`
	ImplicitReadOnly []string `json:"implicit_read_only,omitempty"`
}

// Load reads a sandbox config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse sandbox config: %w", err)
	}
	if c.Binary == "" || c.Name == "" {
		return Config{}, fmt.Errorf("sandbox config is missing name or binary")
	}
	return c, nil
}
