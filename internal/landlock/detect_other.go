//go:build !linux

// Package landlock detects and applies Linux Landlock filesystem rules.
package landlock

// DetectABI returns 0 on platforms without Landlock.
func DetectABI() int { return 0 }
