package render

import (
	"fmt"
	"strings"

	"github.com/obscure-toolkit/obscure/internal/policy"
)

const sysctlPath = "/etc/sysctl.d/99-zz-obscure.conf"

type sysctlDefault struct {
	key, value, reason string
}

var sysctlBaseline = []sysctlDefault{
	{"kernel.kptr_restrict", "2", "hide kernel pointers from unprivileged users"},
	{"kernel.dmesg_restrict", "1", "restrict the kernel log to privileged users"},
	{"kernel.yama.ptrace_scope", "2", "restrict ptrace to descendants"},
	{"kernel.unprivileged_bpf_disabled", "2", "block unprivileged BPF permanently"},
	{"kernel.perf_event_paranoid", "3", "restrict performance monitoring"},
	{"kernel.kexec_load_disabled", "1", "disable loading a replacement kernel"},
	{"kernel.randomize_va_space", "2", "full address space randomization"},
	{"fs.protected_hardlinks", "1", "prevent hardlink attacks in sticky directories"},
	{"fs.protected_symlinks", "1", "prevent symlink attacks in sticky directories"},
	{"fs.protected_fifos", "2", "prevent FIFO attacks in world-writable directories"},
	{"fs.protected_regular", "2", "prevent regular-file attacks in world-writable directories"},
	{"fs.suid_dumpable", "0", "never dump setuid process memory"},
	{"net.core.bpf_jit_harden", "2", "harden the BPF JIT"},
	{"net.ipv4.conf.all.rp_filter", "2", "loose reverse-path filtering"},
	{"net.ipv4.conf.default.rp_filter", "2", "loose reverse-path filtering for new interfaces"},
	{"net.ipv4.conf.all.accept_redirects", "0", "ignore ICMP redirects"},
	{"net.ipv4.conf.default.accept_redirects", "0", "ignore ICMP redirects on new interfaces"},
	{"net.ipv4.conf.all.secure_redirects", "0", "ignore secure ICMP redirects"},
	{"net.ipv4.conf.all.send_redirects", "0", "do not send ICMP redirects"},
	{"net.ipv4.conf.default.send_redirects", "0", "do not send ICMP redirects on new interfaces"},
	{"net.ipv4.conf.all.accept_source_route", "0", "ignore IPv4 source routing"},
	{"net.ipv4.conf.default.accept_source_route", "0", "ignore IPv4 source routing on new interfaces"},
	{"net.ipv6.conf.all.accept_redirects", "0", "ignore IPv6 redirects"},
	{"net.ipv6.conf.default.accept_redirects", "0", "ignore IPv6 redirects on new interfaces"},
	{"net.ipv6.conf.all.accept_source_route", "0", "ignore IPv6 source routing"},
	{"net.ipv6.conf.default.accept_source_route", "0", "ignore IPv6 source routing on new interfaces"},
	{"net.ipv4.tcp_syncookies", "1", "resist SYN floods"},
	{"net.ipv4.tcp_rfc1337", "1", "avoid TIME_WAIT assassination"},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "1", "ignore broadcast ICMP echo"},
	{"net.ipv4.icmp_ignore_bogus_error_responses", "1", "ignore bogus ICMP errors"},
	{"net.ipv4.conf.all.log_martians", "1", "log packets with impossible addresses"},
	{"net.ipv4.conf.default.log_martians", "1", "log martians on new interfaces"},
	{"net.ipv4.ip_forward", "0", "do not forward IPv4 packets"},
	{"net.ipv6.conf.all.forwarding", "0", "do not forward IPv6 packets"},
}

func renderSysctl(p *policy.Policy, exists func(string) bool) (Artifact, []Sysctl) {
	var b strings.Builder
	b.WriteString(header("sysctl"))
	b.WriteString("# Applied with sysctl --system. Unsupported keys are omitted so the same\n")
	b.WriteString("# policy can be used across kernel versions.\n")
	var sysctls []Sysctl
	for _, def := range sysctlBaseline {
		if exists != nil && !exists(def.key) {
			continue
		}
		fmt.Fprintf(&b, "\n# %s\n%s = %s\n", def.reason, def.key, def.value)
		sysctls = append(sysctls, Sysctl{Key: def.key, Value: def.value, Reason: def.reason})
	}
	return Artifact{
		Path: sysctlPath, Content: []byte(b.String()), Mode: 0o644,
		Reason: "kernel and network hardening baseline", Section: "hardening", Kind: KindConfig,
	}, sysctls
}
