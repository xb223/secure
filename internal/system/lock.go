package system

import (
	"fmt"
	"os"
	"syscall"
)

// Lock is an exclusive advisory lock protecting a state-mutating operation.
type Lock struct {
	file *os.File
}

// AcquireLock takes an exclusive non-blocking lock. The lock is released by
// the kernel if the process dies.
func AcquireLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another obsidian operation is running (lock %s)", path)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return &Lock{file: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	cerr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return cerr
}
