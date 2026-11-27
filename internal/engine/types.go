package engine

import (
	"io"
	"time"

	"github.com/obscure-toolkit/obscure/internal/policy"
	"github.com/obscure-toolkit/obscure/internal/render"
	"github.com/obscure-toolkit/obscure/internal/system"
)

// Scope limits an operation to the full policy or to sandboxes.
type Scope struct {
	Kind    string `json:"kind"` // full or sandbox
	Sandbox string `json:"sandbox,omitempty"`
}

// FullScope is the normal policy scope.
func FullScope() Scope { return Scope{Kind: "full"} }

// SandboxScope limits work to all sandboxes, or one named sandbox.
func SandboxScope(name string) Scope { return Scope{Kind: "sandbox", Sandbox: name} }

func (s Scope) IsFull() bool { return s.Kind == "" || s.Kind == "full" }

// Engine owns policy operations. Dirs are injectable for tests.
type Engine struct {
	Sys           *system.System
	ConfigPath    string
	StateDir      string
	RunDir        string
	AllowDegraded bool
	NoPackages    bool
	Strict        bool
	NoWatchdog    bool
	Verbose       bool
	Out           io.Writer
	Err           io.Writer
}

// Change is one planned mutation.
type Change struct {
	Order  int    `json:"order"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Action string `json:"action"`
	Reason string `json:"reason"`
	Risk   string `json:"risk"`
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
	Diff   string `json:"diff,omitempty"`
}

// Risk levels.
const (
	RiskSafe      = "safe"
	RiskAttention = "attention"
	RiskLockout   = "lockout"
)

// Plan is a complete, read-only description of the work apply would do.
type Plan struct {
	Policy     *policy.Policy   `json:"-"`
	Desired    *render.Desired  `json:"desired,omitempty"`
	State      *State           `json:"-"`
	Scope      Scope            `json:"scope"`
	Changes    []Change         `json:"changes"`
	Warnings   []policy.Warning `json:"warnings,omitempty"`
	Errors     []string         `json:"errors,omitempty"`
	Packages   []string         `json:"packages,omitempty"`
	Lockout    LockoutReport    `json:"lockout"`
	Checks     *VerifyResult    `json:"checks,omitempty"`
	PolicyPath string           `json:"policy_path"`
	PolicyHash string           `json:"policy_hash"`
	Generated  time.Time        `json:"generated"`
}

// HasChanges reports whether apply would do anything.
func (p *Plan) HasChanges() bool { return len(p.Changes) > 0 }

// HasErrors reports whether the plan is unsafe or invalid.
func (p *Plan) HasErrors() bool { return len(p.Errors) > 0 }

// LockoutReport explains SSH reachability risk.
type LockoutReport struct {
	Remote      bool     `json:"remote"`
	ClientIP    string   `json:"client_ip,omitempty"`
	Source      string   `json:"source,omitempty"`
	Risky       bool     `json:"risky"`
	Allowed     bool     `json:"allowed"`
	Reasons     []string `json:"reasons,omitempty"`
	SessionPort int      `json:"session_port,omitempty"`
	PolicyPort  int      `json:"policy_port,omitempty"`
}

// Check status values.
const (
	CheckOK    = "ok"
	CheckDrift = "drift"
	CheckWarn  = "warn"
	CheckSkip  = "skip"
)

// Check is one verification result.
type Check struct {
	ID       string `json:"id"`
	Section  string `json:"section"`
	Target   string `json:"target"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// VerifyResult is the outcome of comparing the live host to policy.
type VerifyResult struct {
	PolicyPath string           `json:"policy_path"`
	PolicyHash string           `json:"policy_hash"`
	Checks     []Check          `json:"checks"`
	Warnings   []policy.Warning `json:"warnings,omitempty"`
	Scope      Scope            `json:"scope"`
	CheckedAt  time.Time        `json:"checked_at"`
}

// Drift returns the number of drift checks.
func (r *VerifyResult) Drift() int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == CheckDrift {
			n++
		}
	}
	return n
}

// WarningsCount returns the number of warning checks.
func (r *VerifyResult) WarningsCount() int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == CheckWarn {
			n++
		}
	}
	return n
}

// OK reports whether the host matches policy.
func (r *VerifyResult) OK() bool { return r.Drift() == 0 }
