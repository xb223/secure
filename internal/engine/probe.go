package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/obsidian-toolkit/obsidian/internal/system"
)

// sshdBin finds sshd even when /usr/sbin is not on PATH.
func (e *Engine) sshdBin() string {
	if _, err := e.Sys.Runner.LookPath("sshd"); err == nil {
		return "sshd"
	}
	if e.Sys.Exists("/usr/sbin/sshd") {
		return "/usr/sbin/sshd"
	}
	return ""
}

func (e *Engine) sshdEffective(ctx context.Context) map[string]string {
	bin := e.sshdBin()
	if bin == "" {
		return map[string]string{}
	}
	res := e.Sys.Runner.Run(ctx, bin, "-T")
	out := map[string]string{}
	if !res.Success() {
		return out
	}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[strings.ToLower(fields[0])] = strings.Join(fields[1:], " ")
		}
	}
	return out
}

type liveService struct {
	Exists        bool
	LoadState     string
	UnitFileState string
	ActiveState   string
}

func (e *Engine) serviceState(ctx context.Context, name string) liveService {
	// Do not use --value: systemd prints properties in alphabetical order,
	// not in the order they were requested, so values must be matched by key.
	res := e.Sys.Runner.Run(ctx, "systemctl", "show", "--no-pager",
		"-p", "LoadState", "-p", "UnitFileState", "-p", "ActiveState", name)
	if !res.Success() {
		return liveService{}
	}
	svc := liveService{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "LoadState":
			svc.LoadState = value
		case "UnitFileState":
			svc.UnitFileState = value
		case "ActiveState":
			svc.ActiveState = value
		}
	}
	svc.Exists = svc.LoadState != "" && svc.LoadState != "not-found"
	return svc
}

func serviceEnabled(state string) bool {
	switch state {
	case "enabled", "enabled-runtime", "static", "indirect", "generated", "alias":
		return true
	}
	return false
}

func serviceCanEnable(state string) bool {
	switch state {
	case "static", "indirect", "generated", "alias":
		return false
	}
	return true
}

func serviceMatches(svc liveService, want ServiceOrigin) bool {
	if !want.Exists {
		return !svc.Exists || (svc.ActiveState != "active" && svc.UnitFileState != "enabled" && svc.UnitFileState != "masked")
	}
	if !svc.Exists {
		return false
	}
	if want.Masked != (svc.UnitFileState == "masked") {
		return false
	}
	if want.Active != (svc.ActiveState == "active") {
		return false
	}
	return want.Enabled == svc.UnitFileState
}

func originFromLive(svc liveService) ServiceOrigin {
	return ServiceOrigin{
		Exists: svc.Exists, Enabled: svc.UnitFileState,
		Active: svc.ActiveState == "active", Masked: svc.UnitFileState == "masked",
	}
}

// nftCanonical returns a stable JSON representation of a table, with volatile
// handles removed.
func (e *Engine) nftCanonical(ctx context.Context, table string) (string, error) {
	parts := strings.Fields(table)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid nft table %q", table)
	}
	res := e.Sys.Runner.Run(ctx, "nft", "-j", "list", "table", parts[0], parts[1])
	if !res.Success() {
		return "", fmt.Errorf("nft list table %s: %s", table, res.Error())
	}
	var v any
	if err := json.Unmarshal(res.Stdout, &v); err != nil {
		return "", fmt.Errorf("parse nft JSON: %w", err)
	}
	stripVolatile(v)
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return system.SHA256(data), nil
}

func stripVolatile(v any) {
	switch x := v.(type) {
	case map[string]any:
		delete(x, "handle")
		delete(x, "index")
		delete(x, "metainfo")
		for _, child := range x {
			stripVolatile(child)
		}
	case []any:
		for _, child := range x {
			stripVolatile(child)
		}
	}
}

func (e *Engine) packageInstalled(ctx context.Context, name string) (bool, bool) {
	res := e.Sys.Runner.Run(ctx, "dpkg-query", "-W", "-f=${Status}", name)
	if !res.Success() {
		return false, false
	}
	return strings.Contains(string(res.Stdout), "install ok installed"), true
}

func (e *Engine) currentSysctl(key string) string {
	v, err := e.Sys.SysctlValue(key)
	if err != nil {
		return ""
	}
	return v
}

func parseKeyValue(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[fields[0]] = strings.Join(fields[1:], " ")
		}
	}
	return out
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
