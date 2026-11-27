//go:build linux

package landlock

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	sysAddRule      = 445
	prSetNoNewPrivs = 38
	oPath           = 0x200000

	accessExecute    = 1 << 0
	accessWriteFile  = 1 << 1
	accessReadFile   = 1 << 2
	accessReadDir    = 1 << 3
	accessRemoveDir  = 1 << 4
	accessRemoveFile = 1 << 5
	accessMakeChar   = 1 << 6
	accessMakeDir    = 1 << 7
	accessMakeReg    = 1 << 8
	accessMakeSock   = 1 << 9
	accessMakeFifo   = 1 << 10
	accessMakeBlock  = 1 << 11
	accessMakeSym    = 1 << 12
	accessRefer      = 1 << 13
	accessTruncate   = 1 << 14
	accessIoctlDev   = 1 << 15
)

type rulesetAttr struct {
	HandledAccessFS uint64
}

type pathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
	_             int32
}

func handledAccess(abi int) uint64 {
	access := uint64(accessExecute | accessWriteFile | accessReadFile | accessReadDir |
		accessRemoveDir | accessRemoveFile | accessMakeChar | accessMakeDir |
		accessMakeReg | accessMakeSock | accessMakeFifo | accessMakeBlock | accessMakeSym)
	if abi >= 2 {
		access |= accessRefer
	}
	if abi >= 3 {
		access |= accessTruncate
	}
	if abi >= 4 {
		access |= accessIoctlDev
	}
	return access
}

// Apply installs a Landlock ruleset for the current process and all future
// children. Read-only paths may be read and executed; read-write paths may also
// be modified. The caller must already be unprivileged or drop privileges
// before calling Apply.
func Apply(readWrite, readOnly []string) error {
	abi := DetectABI()
	if abi == 0 {
		return fmt.Errorf("Landlock is not supported by this kernel")
	}
	handled := handledAccess(abi)
	attr := rulesetAttr{HandledAccessFS: handled}
	fd, _, errno := syscall.Syscall(sysCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	rulesetFD := int(fd)
	defer syscall.Close(rulesetFD)

	roAccess := uint64(accessExecute | accessReadFile | accessReadDir)
	rwAccess := handled
	for _, path := range readOnly {
		if err := addPathRule(rulesetFD, path, roAccess); err != nil {
			return err
		}
	}
	for _, path := range readWrite {
		if err := addPathRule(rulesetFD, path, rwAccess); err != nil {
			return err
		}
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}
	if _, _, errno := syscall.Syscall(sysRestrictSelf, uintptr(rulesetFD), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

func addPathRule(rulesetFD int, path string, access uint64) error {
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer syscall.Close(fd)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		// Rights that only apply to directories are rejected for files.
		access &= accessExecute | accessReadFile | accessWriteFile | accessTruncate | accessIoctlDev
	}
	rule := pathBeneathAttr{AllowedAccess: access, ParentFD: int32(fd)}
	if _, _, errno := syscall.Syscall6(sysAddRule, uintptr(rulesetFD), 1,
		uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %w", path, errno)
	}
	return nil
}
