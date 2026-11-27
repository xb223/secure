//go:build !linux

package landlock

import "fmt"

// Apply is unavailable outside Linux.
func Apply(readWrite, readOnly []string) error {
	return fmt.Errorf("Landlock is only available on Linux")
}
