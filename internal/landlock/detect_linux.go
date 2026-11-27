//go:build linux

// Package landlock detects and applies Linux Landlock filesystem rules.
package landlock

import "syscall"

const (
	sysCreateRuleset = 444
	sysRestrictSelf  = 446

	createRulesetVersion = 1
)

// DetectABI returns the kernel Landlock ABI version, or 0 if unsupported.
func DetectABI() int {
	abi, _, errno := syscall.Syscall(sysCreateRuleset, 0, 0, createRulesetVersion)
	if errno != 0 {
		return 0
	}
	return int(abi)
}
