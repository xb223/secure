//go:build linux || darwin

package system

import (
	"io/fs"
	"syscall"
)

func statOwner(fi fs.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
