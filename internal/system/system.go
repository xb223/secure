// Package system provides the small, testable seam between obsidian and the
// host: file operations, command execution, host facts and session detection.
package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/obsidian-toolkit/obsidian/internal/landlock"
)

// Result is the outcome of an external command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

// Success reports whether the command exited zero.
func (r Result) Success() bool { return r.Err == nil && r.ExitCode == 0 }

// Output returns trimmed stdout.
func (r Result) Output() string { return strings.TrimSpace(string(r.Stdout)) }

// Error returns a compact, human-readable command failure.
func (r Result) Error() string {
	msg := strings.TrimSpace(string(r.Stderr))
	if msg == "" {
		msg = strings.TrimSpace(string(r.Stdout))
	}
	if msg == "" && r.Err != nil {
		msg = r.Err.Error()
	}
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", r.ExitCode)
	}
	return msg
}

// Runner executes external commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) Result
	RunInput(ctx context.Context, input []byte, name string, args ...string) Result
	LookPath(name string) (string, error)
}

// LocalRunner runs commands on the host.
type LocalRunner struct{}

// Run implements Runner.
func (LocalRunner) Run(ctx context.Context, name string, args ...string) Result {
	return run(ctx, nil, name, args...)
}

// RunInput implements Runner.
func (LocalRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) Result {
	return run(ctx, input, name, args...)
}

// LookPath implements Runner.
func (LocalRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func run(ctx context.Context, input []byte, name string, args ...string) Result {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(),
		"LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none")
	if input != nil {
		cmd.Stdin = strings.NewReader(string(input))
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: []byte(stdout.String()), Stderr: []byte(stderr.String()), Err: err}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			res.ExitCode = exit.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}
	return res
}

// FileInfo is a portable snapshot of file metadata.
type FileInfo struct {
	Mode       fs.FileMode
	UID        int
	GID        int
	Size       int64
	IsDir      bool
	IsSymlink  bool
	LinkTarget string
	ModTime    time.Time
}

// User is a local account entry.
type User struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// Group is a local group entry.
type Group struct {
	Name string
	GID  int
}

// System is the host seam. The zero value is not usable; call New.
type System struct {
	Root   string
	Runner Runner

	NowFn              func() time.Time
	HostnameFn         func() (string, error)
	EnvFn              func(string) string
	EUIDFn             func() int
	InterfaceExistsFn  func(string) (bool, error)
	AppArmorEnabledFn  func() bool
	CgroupV2Fn         func() bool
	SeccompSupportedFn func() bool
	LandlockABIFn      func() int
	AncestorCommsFn    func(int) ([]string, error)
	AncestorEnvFn      func(int) map[string]string
}

// New returns a System rooted at /. Tests replace Root and Runner and, when
// needed, the fact functions.
func New() *System {
	s := &System{Root: "/", Runner: LocalRunner{}}
	s.NowFn = time.Now
	s.HostnameFn = os.Hostname
	s.EnvFn = os.Getenv
	s.EUIDFn = os.Geteuid
	s.InterfaceExistsFn = func(name string) (bool, error) {
		_, err := net.InterfaceByName(name)
		if err == nil {
			return true, nil
		}
		if strings.Contains(err.Error(), "no such network interface") {
			return false, nil
		}
		return false, err
	}
	s.AppArmorEnabledFn = func() bool {
		data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
		return err == nil && strings.HasPrefix(strings.TrimSpace(string(data)), "Y")
	}
	s.CgroupV2Fn = func() bool {
		_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
		return err == nil
	}
	s.SeccompSupportedFn = func() bool {
		_, err := os.Stat("/proc/sys/kernel/seccomp/actions_avail")
		return err == nil
	}
	s.LandlockABIFn = landlock.DetectABI
	s.AncestorCommsFn = ancestorComms
	s.AncestorEnvFn = ancestorEnv
	return s
}

// Path maps an absolute policy path into the (possibly test) root.
func (s *System) Path(path string) string {
	if s.Root == "" || s.Root == "/" {
		return path
	}
	return filepath.Join(s.Root, filepath.Clean("/"+path))
}

// ReadFile reads a host file.
func (s *System) ReadFile(path string) ([]byte, error) { return os.ReadFile(s.Path(path)) }

// ReadFileString reads a host file as text.
func (s *System) ReadFileString(path string) (string, error) {
	data, err := s.ReadFile(path)
	return string(data), err
}

// Stat follows symlinks.
func (s *System) Stat(path string) (FileInfo, error) {
	fi, err := os.Stat(s.Path(path))
	if err != nil {
		return FileInfo{}, err
	}
	return toInfo(fi), nil
}

// Lstat does not follow symlinks.
func (s *System) Lstat(path string) (FileInfo, error) {
	fi, err := os.Lstat(s.Path(path))
	if err != nil {
		return FileInfo{}, err
	}
	info := toInfo(fi)
	if fi.Mode()&os.ModeSymlink != 0 {
		info.IsSymlink = true
		info.LinkTarget, _ = os.Readlink(s.Path(path))
	}
	return info, nil
}

func toInfo(fi fs.FileInfo) FileInfo {
	info := FileInfo{Mode: fi.Mode().Perm(), Size: fi.Size(), IsDir: fi.IsDir(), ModTime: fi.ModTime()}
	info.UID, info.GID = statOwner(fi)
	return info
}

// Exists reports whether a path exists.
func (s *System) Exists(path string) bool {
	_, err := os.Lstat(s.Path(path))
	return err == nil
}

// IsDir reports whether path is a directory.
func (s *System) IsDir(path string) bool {
	fi, err := os.Stat(s.Path(path))
	return err == nil && fi.IsDir()
}

// ReadDir lists directory entries.
func (s *System) ReadDir(path string) ([]os.DirEntry, error) { return os.ReadDir(s.Path(path)) }

// Readlink reads a symlink target.
func (s *System) Readlink(path string) (string, error) { return os.Readlink(s.Path(path)) }

// MkdirAll creates a directory hierarchy.
func (s *System) MkdirAll(path string, mode fs.FileMode) error {
	return os.MkdirAll(s.Path(path), mode)
}

// Remove removes a file or empty directory.
func (s *System) Remove(path string) error { return os.Remove(s.Path(path)) }

// Rename renames a host path.
func (s *System) Rename(oldPath, newPath string) error {
	return os.Rename(s.Path(oldPath), s.Path(newPath))
}

// Symlink creates a symlink at path.
func (s *System) Symlink(target, path string) error { return os.Symlink(target, s.Path(path)) }

// Chmod changes permissions.
func (s *System) Chmod(path string, mode fs.FileMode) error { return os.Chmod(s.Path(path), mode) }

// EnsureParentDirs creates missing parents and returns the directories it
// created, outermost first. The caller records them for rollback.
func (s *System) EnsureParentDirs(path string) ([]string, error) {
	dir := filepath.Dir(path)
	var missing []string
	for {
		if s.Exists(dir) {
			break
		}
		missing = append([]string{dir}, missing...)
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	if len(missing) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(s.Path(missing[len(missing)-1]), 0o755); err != nil {
		return nil, err
	}
	return missing, nil
}

// WriteFileAtomic replaces path atomically. When preserve is true the existing
// mode and ownership are retained; otherwise mode is used.
func (s *System) WriteFileAtomic(path string, data []byte, mode fs.FileMode, preserve bool) error {
	real := s.Path(path)
	dir := filepath.Dir(real)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	uid, gid := -1, -1
	perm := mode.Perm()
	if preserve {
		if fi, err := os.Stat(real); err == nil {
			perm = fi.Mode().Perm()
			uid, gid = statOwner(fi)
		}
	}
	if s.EUIDFn() != 0 {
		uid, gid = -1, -1
	}
	tmp, err := os.CreateTemp(dir, ".obsidian-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if uid >= 0 {
		if err := os.Chown(tmpName, uid, gid); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, real); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Chown changes ownership when running as root.
func (s *System) Chown(path string, uid, gid int) error {
	if s.EUIDFn() != 0 || uid < 0 {
		return nil
	}
	return os.Chown(s.Path(path), uid, gid)
}

// WriteFileOwned atomically writes a file and sets its ownership.
func (s *System) WriteFileOwned(path string, data []byte, mode fs.FileMode, uid, gid int) error {
	if err := s.WriteFileAtomic(path, data, mode, false); err != nil {
		return err
	}
	return s.Chown(path, uid, gid)
}

// WriteFileRaw writes a file without atomic replacement (used for transaction
// blobs in a directory obsidian owns).
func (s *System) WriteFileRaw(path string, data []byte, mode fs.FileMode) error {
	real := s.Path(path)
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		return err
	}
	return os.WriteFile(real, data, mode)
}

// RemoveAll removes a path recursively.
func (s *System) RemoveAll(path string) error { return os.RemoveAll(s.Path(path)) }

// Hostname returns the host name.
func (s *System) Hostname() string {
	h, err := s.HostnameFn()
	if err != nil {
		return "unknown"
	}
	return h
}

// Env reads an environment variable.
func (s *System) Env(name string) string { return s.EnvFn(name) }

// EUID returns the effective user ID.
func (s *System) EUID() int { return s.EUIDFn() }

// Now returns the current time.
func (s *System) Now() time.Time { return s.NowFn() }

// InterfaceExists reports whether a network interface exists.
func (s *System) InterfaceExists(name string) (bool, error) { return s.InterfaceExistsFn(name) }

// AppArmorEnabled reports whether AppArmor is enabled in the kernel.
func (s *System) AppArmorEnabled() bool { return s.AppArmorEnabledFn() }

// CgroupV2 reports whether the unified cgroup hierarchy is available.
func (s *System) CgroupV2() bool { return s.CgroupV2Fn() }

// SeccompSupported reports whether the kernel exposes seccomp.
func (s *System) SeccompSupported() bool { return s.SeccompSupportedFn() }

// LandlockABI returns the supported Landlock ABI (0 when unavailable).
func (s *System) LandlockABI() int { return s.LandlockABIFn() }

// LookupUser resolves a local account.
func (s *System) LookupUser(name string) (User, error) {
	data, err := s.ReadFile("/etc/passwd")
	if err != nil {
		return User{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[0] != name {
			continue
		}
		uid, err1 := strconv.Atoi(fields[2])
		gid, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil {
			return User{}, fmt.Errorf("malformed passwd entry for %s", name)
		}
		return User{Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]}, nil
	}
	return User{}, fmt.Errorf("user %q does not exist", name)
}

// LookupGroup resolves a local group.
func (s *System) LookupGroup(name string) (Group, error) {
	data, err := s.ReadFile("/etc/group")
	if err != nil {
		return Group{}, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		gid, err := strconv.Atoi(fields[2])
		if err != nil {
			return Group{}, fmt.Errorf("malformed group entry for %s", name)
		}
		return Group{Name: fields[0], GID: gid}, nil
	}
	return Group{}, fmt.Errorf("group %q does not exist", name)
}

// SysctlExists reports whether a kernel sysctl is exposed.
func (s *System) SysctlExists(key string) bool {
	return s.Exists("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
}

// SysctlValue reads a kernel sysctl.
func (s *System) SysctlValue(key string) (string, error) {
	data, err := s.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(string(data)), " "), nil
}

// SHA256 returns the hex digest of data.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256File returns the digest of a file.
func (s *System) SHA256File(path string) (string, error) {
	data, err := s.ReadFile(path)
	if err != nil {
		return "", err
	}
	return SHA256(data), nil
}

// SSHSession describes the SSH session obsidian is running inside, if any.
type SSHSession struct {
	Remote     bool
	ClientIP   netip.Addr
	ServerPort int
	Source     string
}

// Session inspects environment variables and the process ancestry.
func (s *System) Session() SSHSession {
	if conn := s.Env("SSH_CONNECTION"); conn != "" {
		if sess, ok := parseSSHConnection(conn); ok {
			sess.Source = "SSH_CONNECTION"
			return sess
		}
	}
	if client := s.Env("SSH_CLIENT"); client != "" {
		if sess, ok := parseSSHClient(client); ok {
			sess.Source = "SSH_CLIENT"
			return sess
		}
	}
	// sudo resets the environment, but root can read the environment of its
	// ancestors. This keeps client-address detection working under sudo.
	if s.AncestorEnvFn != nil {
		env := s.AncestorEnvFn(os.Getpid())
		if conn := env["SSH_CONNECTION"]; conn != "" {
			if sess, ok := parseSSHConnection(conn); ok {
				sess.Source = "SSH_CONNECTION (parent)"
				return sess
			}
		}
		if client := env["SSH_CLIENT"]; client != "" {
			if sess, ok := parseSSHClient(client); ok {
				sess.Source = "SSH_CLIENT (parent)"
				return sess
			}
		}
	}
	comms, err := s.AncestorCommsFn(os.Getpid())
	if err == nil {
		for _, comm := range comms {
			if comm == "sshd" || strings.HasPrefix(comm, "sshd-") {
				return SSHSession{Remote: true, Source: "process ancestry"}
			}
		}
	}
	return SSHSession{}
}

func parseSSHClient(value string) (SSHSession, bool) {
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return SSHSession{}, false
	}
	sess := SSHSession{Remote: true}
	if ip, err := netip.ParseAddr(fields[0]); err == nil {
		sess.ClientIP = ip
	}
	sess.ServerPort, _ = strconv.Atoi(fields[2])
	return sess, true
}

func parseSSHConnection(value string) (SSHSession, bool) {
	fields := strings.Fields(value)
	if len(fields) < 4 {
		return SSHSession{}, false
	}
	ip, err := netip.ParseAddr(fields[0])
	if err != nil {
		return SSHSession{}, false
	}
	port, _ := strconv.Atoi(fields[3])
	return SSHSession{Remote: true, ClientIP: ip, ServerPort: port}, true
}

func ancestorEnv(pid int) map[string]string {
	out := map[string]string{}
	for i := 0; i < 16 && pid > 1; i++ {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
		if err == nil {
			for _, kv := range strings.Split(string(data), "\x00") {
				if key, value, ok := strings.Cut(kv, "="); ok {
					if _, exists := out[key]; !exists {
						out[key] = value
					}
				}
			}
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			break
		}
		parent := 0
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
				break
			}
		}
		if parent <= 1 {
			break
		}
		pid = parent
	}
	return out
}

func ancestorComms(pid int) ([]string, error) {
	var out []string
	for i := 0; i < 16 && pid > 1; i++ {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			return out, err
		}
		out = append(out, strings.TrimSpace(string(comm)))
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return out, err
		}
		parent := 0
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
				break
			}
		}
		if parent <= 1 {
			break
		}
		pid = parent
	}
	return out, nil
}
