package hostprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/humanethq/sandbox-check/internal/model"
)

var dangerousCapNames = map[uint]struct {
	name string
	sev  model.Severity
}{
	1:  {"CAP_DAC_OVERRIDE", model.SeverityMedium},
	2:  {"CAP_DAC_READ_SEARCH", model.SeverityHigh},
	6:  {"CAP_SETGID", model.SeverityMedium},
	7:  {"CAP_SETUID", model.SeverityMedium},
	8:  {"CAP_SETPCAP", model.SeverityMedium},
	12: {"CAP_NET_ADMIN", model.SeverityCritical},
	13: {"CAP_NET_RAW", model.SeverityMedium},
	16: {"CAP_SYS_MODULE", model.SeverityCritical},
	17: {"CAP_SYS_RAWIO", model.SeverityCritical},
	18: {"CAP_SYS_CHROOT", model.SeverityMedium},
	19: {"CAP_SYS_PTRACE", model.SeverityHigh},
	21: {"CAP_SYS_ADMIN", model.SeverityCritical},
	25: {"CAP_SYS_TIME", model.SeverityLow},
	38: {"CAP_PERFMON", model.SeverityHigh},
	39: {"CAP_BPF", model.SeverityHigh},
}

// DecodeCapabilities parses a Linux /proc/self/status CapEff hex bitmask into dangerous capability names.
func DecodeCapabilities(hexMask string) ([]string, error) {
	cleaned := strings.TrimSpace(hexMask)
	if cleaned == "" {
		return nil, nil
	}
	val, err := strconv.ParseUint(cleaned, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid capability hex mask %q: %w", hexMask, err)
	}
	var found []string
	for bit := uint(0); bit < 64; bit++ {
		if (val & (uint64(1) << bit)) != 0 {
			if info, ok := dangerousCapNames[bit]; ok {
				found = append(found, info.name)
			}
		}
	}
	return found, nil
}

// InspectEnvSecrets audits env key names for direct raw credential presence without logging secret values.
func InspectEnvSecrets(environ []string) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       "env_secret_exposure",
		Category: model.CategorySecrets,
		Severity: model.SeverityHigh,
		Target:   "process environment",
		Expected: "zero raw API keys/secrets in guest env (phantom tokens or secretless proxy preferred)",
	}

	var rawKeys []string
	var phantomKeys []string

	for _, entry := range environ {
		k, v, found := strings.Cut(entry, "=")
		if !found || strings.TrimSpace(v) == "" {
			continue
		}
		if !looksSensitiveEnvKey(k) {
			continue
		}
		if isPhantomValue(v) {
			phantomKeys = append(phantomKeys, k)
		} else {
			rawKeys = append(rawKeys, k)
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if len(rawKeys) > 0 {
		res.Status = model.StatusFail
		res.Observed = fmt.Sprintf("%d_raw_secret_vars", len(rawKeys))
		res.Detail = fmt.Sprintf("raw secret-named env vars accessible inside sandbox: [%s] (values redacted; phantom_vars=%d)", strings.Join(rawKeys, ", "), len(phantomKeys))
		return res
	}
	if len(phantomKeys) > 0 {
		res.Status = model.StatusPass
		res.Observed = "phantom_tokens_only"
		res.Detail = fmt.Sprintf("only placeholder/phantom tokens present (%s); zero raw secrets exposed in env", strings.Join(phantomKeys, ", "))
		return res
	}
	res.Status = model.StatusPass
	res.Observed = "no_secret_vars"
	res.Detail = "no sensitive credential variables found in environment"
	return res
}

func isPhantomValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	return strings.HasPrefix(trimmed, "phm_") ||
		strings.HasPrefix(trimmed, "phantom_") ||
		strings.HasPrefix(trimmed, "vault:") ||
		strings.HasPrefix(trimmed, "op://")
}

func looksSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return false
	}
	ignoreSuffixes := []string{"_LIMIT", "_TOKENS", "_TOKEN_LIMIT", "_URL_PUBLIC", "_PUBLIC_KEY", "_FILE", "_PATH", "_TIMEOUT", "_DISABLED"}
	for _, suf := range ignoreSuffixes {
		if strings.HasSuffix(upper, suf) && !strings.Contains(upper, "DATABASE_URL") {
			return false
		}
	}
	switch upper {
	case "SSH_AUTH_SOCK", "XDG_RUNTIME_DIR", "LS_COLORS", "LESS_TERMCAP_MB", "HOME", "PATH", "PWD", "TERM", "USER":
		return false
	}
	patterns := []string{
		"_API_KEY", "_SECRET_KEY", "_ACCESS_KEY", "SECRET_ACCESS_KEY",
		"_PRIVATE_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD",
		"DATABASE_URL", "OPENAI_KEY", "ANTHROPIC_KEY", "STRIPE_KEY",
		"AWS_SESSION_TOKEN", "GITHUB_PAT",
	}
	for _, pat := range patterns {
		if strings.Contains(upper, pat) || strings.HasSuffix(upper, pat) {
			return true
		}
	}
	return upper == "PASSWORD" || upper == "API_KEY" || upper == "SECRET" || upper == "TOKEN" || strings.HasSuffix(upper, "_PASS")
}

// InspectCgroupV2Dir inspects a cgroup v2 directory for unbounded memory, PID, or CPU limits.
func InspectCgroupV2Dir(dir string) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       "cgroup_v2_limits",
		Category: model.CategoryLimits,
		Severity: model.SeverityHigh,
		Target:   dir,
		Expected: "bounded memory.max and pids.max (and cpu.max recommended)",
	}

	memRaw, memErr := readTrimmed(filepath.Join(dir, "memory.max"))
	pidsRaw, pidsErr := readTrimmed(filepath.Join(dir, "pids.max"))
	cpuRaw, cpuErr := readTrimmed(filepath.Join(dir, "cpu.max"))

	if memErr != nil && pidsErr != nil && cpuErr != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusSkip
		res.Observed = "no_cgroup_v2_files"
		res.Detail = fmt.Sprintf("could not read cgroup v2 files in %s", dir)
		return res
	}

	var unbounded []string
	if memErr == nil && (memRaw == "max" || memRaw == "") {
		unbounded = append(unbounded, "memory.max=max")
	}
	if pidsErr == nil && (pidsRaw == "max" || pidsRaw == "") {
		unbounded = append(unbounded, "pids.max=max")
	}

	cpuNote := cpuRaw
	if strings.HasPrefix(cpuRaw, "max ") {
		cpuNote = cpuRaw + " (unthrottled CPU)"
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if len(unbounded) > 0 {
		res.Status = model.StatusFail
		res.Observed = strings.Join(unbounded, ",")
		res.Detail = fmt.Sprintf("unbounded cgroup v2 limits [%s]; memory.max=%q pids.max=%q cpu.max=%q", strings.Join(unbounded, ", "), memRaw, pidsRaw, cpuNote)
		return res
	}

	res.Status = model.StatusPass
	res.Observed = "bounded"
	res.Detail = fmt.Sprintf("memory.max=%q pids.max=%q cpu.max=%q", memRaw, pidsRaw, cpuNote)
	return res
}

func resolveCurrentCgroupV2Dir() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if strings.HasPrefix(line, "0::") {
				rel := strings.TrimPrefix(line, "0::")
				rel = strings.TrimPrefix(rel, "/")
				cand := filepath.Join("/sys/fs/cgroup", rel)
				if _, stErr := os.Stat(filepath.Join(cand, "memory.max")); stErr == nil {
					return cand
				}
			}
		}
	}
	return "/sys/fs/cgroup"
}

func RunAll(root string) ([]model.ProbeResult, string, string) {
	if root == "" {
		root = "/"
	}
	var results []model.ProbeResult
	detectedRuntime := detectRuntimeName(root)
	pid1Name, _ := readTrimmed(filepath.Join(root, "proc", "1", "comm"))

	if runtime.GOOS != "linux" {
		results = append(results, model.ProbeResult{
			ID:       "linux_kernel_surface",
			Category: model.CategoryRuntime,
			Severity: model.SeverityInfo,
			Status:   model.StatusSkip,
			Target:   runtime.GOOS,
			Expected: "Linux container or microVM guest kernel inspection",
			Observed: "non_linux_host",
			Detail:   fmt.Sprintf("running on %s/%s; Linux /proc, capabilities, and cgroup checks skipped", runtime.GOOS, runtime.GOARCH),
		})
		results = append(results, InspectEnvSecrets(os.Environ()))
		return results, detectedRuntime, pid1Name
	}

	isVM := strings.HasPrefix(detectedRuntime, "firecracker") || strings.HasPrefix(detectedRuntime, "vm_")

	// 1. Capabilities, UID & Seccomp status
	results = append(results, inspectProcSelfStatus(filepath.Join(root, "proc", "self", "status"), isVM))
	if statusBytes, err := os.ReadFile(filepath.Join(root, "proc", "self", "status")); err == nil {
		results = append(results, InspectSeccompStatus(string(statusBytes), isVM))
	}

	// 1b. /proc/mounts host socket / bind mount / writable cgroup check
	if mountsBytes, err := os.ReadFile(filepath.Join(root, "proc", "mounts")); err == nil {
		results = append(results, InspectMountsContent(string(mountsBytes), isVM))
	}

	// 1c. Writable host kernel escape triggers (/proc/sysrq-trigger, /proc/kcore)
	results = append(results, inspectKernelTriggerPaths(root, isVM))

	// 2. Host sockets & sensitive device exposure
	results = append(results, inspectSocketAndDevicePaths(root, isVM)...)

	// 3. Cgroup v2 / Hypervisor hardware resource bounds
	if isVM {
		if memBytes, err := os.ReadFile(filepath.Join(root, "proc", "meminfo")); err == nil {
			results = append(results, InspectVMMeminfo(string(memBytes), runtime.NumCPU()))
		} else {
			results = append(results, InspectCgroupV2Dir(resolveCurrentCgroupV2Dir()))
		}
	} else {
		results = append(results, InspectCgroupV2Dir(resolveCurrentCgroupV2Dir()))
	}

	// 4. Environment secret exposure (key names only)
	results = append(results, InspectEnvSecrets(os.Environ()))

	return results, detectedRuntime, pid1Name
}

func inspectSocketAndDevicePaths(root string, isVM bool) []model.ProbeResult {
	socketChecks := []struct {
		id   string
		path string
		sev  model.Severity
	}{
		{"host_docker_socket", filepath.Join(root, "var", "run", "docker.sock"), model.SeverityCritical},
		{"host_containerd_socket", filepath.Join(root, "run", "containerd", "containerd.sock"), model.SeverityCritical},
		{"host_crio_socket", filepath.Join(root, "run", "crio", "crio.sock"), model.SeverityCritical},
		{"host_dev_kvm", filepath.Join(root, "dev", "kvm"), model.SeverityHigh},
		{"host_dev_mem", filepath.Join(root, "dev", "mem"), model.SeverityCritical},
	}
	out := make([]model.ProbeResult, 0, len(socketChecks))
	for _, sc := range socketChecks {
		start := time.Now()
		_, err := os.Stat(sc.path)
		r := model.ProbeResult{
			ID:         sc.id,
			Category:   model.CategoryRuntime,
			Severity:   sc.sev,
			Target:     sc.path,
			Expected:   "absent or inaccessible inside sandbox",
			DurationMs: time.Since(start).Milliseconds(),
		}
		if err == nil {
			if sc.id == "host_dev_mem" && isVM {
				r.Status = model.StatusPass
				r.Severity = model.SeverityInfo
				r.Observed = "guest_only_memory"
				r.Detail = "guest /dev/mem only maps isolated microVM guest RAM (host physical memory protected by hypervisor)"
			} else {
				r.Status = model.StatusFail
				r.Observed = "present"
				r.Detail = fmt.Sprintf("sensitive host device/socket %s exists inside sandbox", sc.path)
			}
		} else {
			r.Status = model.StatusPass
			r.Observed = "absent"
			r.Detail = err.Error()
		}
		out = append(out, r)
	}
	return out
}

func InspectVMMeminfo(meminfoContent string, cpus int) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       "vm_hardware_resource_bounds",
		Category: model.CategoryLimits,
		Severity: model.SeverityInfo,
		Target:   "/proc/meminfo",
		Expected: "guest VM memory/vCPU physically bounded by hypervisor (plus host-side jailer cgroups)",
	}
	var memKB int64
	for _, line := range strings.Split(meminfoContent, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					memKB = v
				}
			}
			break
		}
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if memKB <= 0 {
		res.Status = model.StatusSkip
		res.Observed = "unreadable_memtotal"
		res.Detail = "could not parse MemTotal from /proc/meminfo"
		return res
	}
	memMiB := memKB / 1024
	res.Status = model.StatusPass
	res.Observed = fmt.Sprintf("vm_%dmib_%dvcpu", memMiB, cpus)
	res.Detail = fmt.Sprintf("guest MemTotal=%d MiB, vCPUs=%d (physical ceiling enforced by hypervisor)", memMiB, cpus)
	return res
}

func inspectProcSelfStatus(statusPath string, isVM bool) model.ProbeResult {
	start := time.Now()
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return model.ProbeResult{
			ID:         "linux_capabilities_and_seccomp",
			Category:   model.CategoryRuntime,
			Severity:   model.SeverityHigh,
			Status:     model.StatusSkip,
			Target:     statusPath,
			Expected:   "minimal capabilities (zero dangerous caps) and seccomp filtering enabled",
			Observed:   "unreadable",
			Detail:     err.Error(),
			DurationMs: time.Since(start).Milliseconds(),
		}
	}
	r := inspectProcSelfStatusContent(statusPath, string(data), isVM)
	r.DurationMs = time.Since(start).Milliseconds()
	return r
}

func inspectProcSelfStatusContent(statusPath, content string, isVM bool) model.ProbeResult {
	res := model.ProbeResult{
		ID:       "linux_capabilities_and_seccomp",
		Category: model.CategoryRuntime,
		Severity: model.SeverityHigh,
		Target:   statusPath,
		Expected: "minimal capabilities (zero dangerous caps) in shared-kernel containers, or hypervisor isolation in microVMs",
	}

	var capEff, noNewPrivs, seccomp string
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "CapEff":
			capEff = strings.TrimSpace(v)
		case "NoNewPrivs":
			noNewPrivs = strings.TrimSpace(v)
		case "Seccomp":
			seccomp = strings.TrimSpace(v)
		}
	}

	if isVM {
		res.Status = model.StatusPass
		res.Severity = model.SeverityInfo
		res.Observed = "isolated_guest_kernel"
		res.Detail = fmt.Sprintf("inside isolated microVM guest kernel (guest CapEff=%s NoNewPrivs=%s Seccomp=%s uid=%d); host kernel separated by hypervisor", capEff, noNewPrivs, seccomp, os.Getuid())
		return res
	}

	caps, capErr := DecodeCapabilities(capEff)
	if capErr != nil {
		res.Status = model.StatusWarn
		res.Observed = "parse_error"
		res.Detail = capErr.Error()
		return res
	}

	if len(caps) > 0 {
		for _, c := range caps {
			if c == "CAP_SYS_ADMIN" || c == "CAP_SYS_MODULE" || c == "CAP_NET_ADMIN" || c == "CAP_SYS_RAWIO" {
				res.Severity = model.SeverityCritical
			}
		}
		res.Status = model.StatusFail
		res.Observed = fmt.Sprintf("dangerous_caps=%d", len(caps))
		res.Detail = fmt.Sprintf("CapEff=%s exposes [%s] NoNewPrivs=%s Seccomp=%s uid=%d", capEff, strings.Join(caps, ", "), noNewPrivs, seccomp, os.Getuid())
		return res
	}

	res.Status = model.StatusPass
	res.Observed = "minimal_caps"
	res.Detail = fmt.Sprintf("zero dangerous caps in CapEff=%s NoNewPrivs=%s Seccomp=%s uid=%d", capEff, noNewPrivs, seccomp, os.Getuid())
	return res
}

func detectRuntimeName(root string) string {
	return detectRuntimeNameForOS(runtime.GOOS, root)
}

func detectRuntimeNameForOS(goos, root string) string {
	if goos != "linux" {
		return goos + "_host"
	}
	if _, err := os.Stat(filepath.Join(root, ".dockerenv")); err == nil {
		return "docker_container"
	}
	if cg, err := os.ReadFile(filepath.Join(root, "proc", "1", "cgroup")); err == nil {
		text := string(cg)
		switch {
		case strings.Contains(text, "docker"):
			return "docker_container"
		case strings.Contains(text, "kubepods"):
			return "kubernetes_pod"
		case strings.Contains(text, "containerd"):
			return "containerd_container"
		}
	}
	if cmdline, err := os.ReadFile(filepath.Join(root, "proc", "cmdline")); err == nil {
		cl := string(cmdline)
		if strings.Contains(cl, "firecracker") || strings.Contains(cl, "virtio_mmio") {
			return "firecracker_microvm"
		}
		if strings.Contains(cl, "reboot=k") && (strings.Contains(cl, "root=/dev/vda") || strings.Contains(cl, "pci=off")) {
			if _, mmioErr := os.Stat(filepath.Join(root, "sys", "bus", "platform", "drivers", "virtio-mmio")); mmioErr == nil {
				return "firecracker_microvm"
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "sys", "devices", "platform", "virtio-mmio.0")); err == nil {
		return "firecracker_microvm"
	}
	if dmi, err := os.ReadFile(filepath.Join(root, "sys", "class", "dmi", "id", "product_name")); err == nil {
		name := strings.TrimSpace(string(dmi))
		if name != "" {
			return "vm_" + strings.ToLower(strings.ReplaceAll(name, " ", "_"))
		}
	}
	return "linux_unknown"
}

func InspectMountsContent(content string, isVM bool) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       "proc_mounts_exposure",
		Category: model.CategoryRuntime,
		Severity: model.SeverityHigh,
		Target:   "/proc/mounts",
		Expected: "no host runtime sockets, host home bind mounts, or rw shared cgroup mounts",
	}

	var risky []string
	var critical bool

	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		src, target, fstype, opts := fields[0], fields[1], fields[2], fields[3]

		// Socket or host runtime exposure inside mounts
		for _, sock := range []string{"docker.sock", "containerd.sock", "crio.sock"} {
			if strings.Contains(src, sock) || strings.Contains(target, sock) {
				critical = true
				risky = append(risky, fmt.Sprintf("%s->%s", src, target))
			}
		}

		// Host macOS/Linux user tree bind mounts
		if !isVM && (strings.Contains(target, "/Users/") || strings.HasPrefix(src, "/Users/")) {
			risky = append(risky, fmt.Sprintf("host_user_mount:%s", target))
		}

		// In shared-kernel containers, rw /sys/fs/cgroup widens cgroup escape surface;
		// inside a Firecracker/KVM guest kernel, /sys/fs/cgroup belongs solely to the guest kernel.
		if !isVM && target == "/sys/fs/cgroup" && (fstype == "cgroup2" || fstype == "cgroup" || fstype == "tmpfs") {
			for _, opt := range strings.Split(opts, ",") {
				if opt == "rw" {
					risky = append(risky, fmt.Sprintf("shared_cgroup_rw:%s(%s)", target, fstype))
					break
				}
			}
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if len(risky) > 0 {
		if critical {
			res.Severity = model.SeverityCritical
		}
		res.Status = model.StatusFail
		res.Observed = fmt.Sprintf("%d_risky_mounts", len(risky))
		res.Detail = fmt.Sprintf("exposed mounts detected: [%s]", strings.Join(risky, ", "))
		return res
	}

	res.Status = model.StatusPass
	res.Observed = "clean"
	if isVM {
		res.Detail = "no host socket/bind mounts visible; isolated guest kernel mounts"
	} else {
		res.Detail = "no risky host socket, user home, or rw shared cgroup mounts detected"
	}
	return res
}

func InspectSeccompStatus(statusContent string, isVM bool) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       "linux_seccomp_policy",
		Category: model.CategoryRuntime,
		Severity: model.SeverityHigh,
		Target:   "/proc/self/status",
		Expected: "seccomp filtering active in shared-kernel containers, or hypervisor hardware isolation in microVM",
	}

	var seccompVal, noNewPrivs string
	for _, line := range strings.Split(statusContent, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Seccomp":
			seccompVal = strings.TrimSpace(v)
		case "NoNewPrivs":
			noNewPrivs = strings.TrimSpace(v)
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if isVM {
		res.Status = model.StatusPass
		res.Severity = model.SeverityInfo
		res.Observed = "isolated_guest_kernel"
		res.Detail = fmt.Sprintf("inside isolated microVM guest kernel (Seccomp=%q NoNewPrivs=%q; syscall boundary is hypervisor/KVM)", seccompVal, noNewPrivs)
		return res
	}

	switch seccompVal {
	case "2", "1":
		res.Status = model.StatusPass
		res.Observed = "seccomp_mode_" + seccompVal
		res.Detail = fmt.Sprintf("Seccomp=%s (filtering active), NoNewPrivs=%s", seccompVal, noNewPrivs)
	case "0":
		res.Status = model.StatusFail
		res.Observed = "seccomp_disabled"
		res.Detail = fmt.Sprintf("Seccomp=0 (unfiltered host kernel syscalls exposed to shared container), NoNewPrivs=%s", noNewPrivs)
	default:
		res.Status = model.StatusSkip
		res.Observed = "seccomp_unknown"
		res.Detail = fmt.Sprintf("Seccomp field=%q NoNewPrivs=%q", seccompVal, noNewPrivs)
	}
	return res
}

func inspectKernelTriggerPaths(root string, isVM bool) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       "host_kernel_proc_sys_surface",
		Category: model.CategoryRuntime,
		Severity: model.SeverityCritical,
		Target:   "/proc/kcore, /proc/sysrq-trigger, /proc/sys/kernel/core_pattern",
		Expected: "not directly writable or readable from shared container",
	}

	if isVM {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusPass
		res.Severity = model.SeverityInfo
		res.Observed = "guest_only_kernel"
		res.Detail = "microVM guest kernel procfs/sysfs is VM-local"
		return res
	}

	var exposed []string
	kcorePath := filepath.Join(root, "proc", "kcore")
	if fi, stErr := os.Stat(kcorePath); stErr == nil && (fi.Mode()&os.ModeCharDevice == 0) {
		if f, err := os.Open(kcorePath); err == nil {
			var hdr [16]byte
			n, _ := f.Read(hdr[:])
			_ = f.Close()
			if n > 0 {
				exposed = append(exposed, fmt.Sprintf("/proc/kcore:readable(%dB)", n))
			}
		}
	}
	for _, p := range []string{
		filepath.Join(root, "proc", "sysrq-trigger"),
		filepath.Join(root, "proc", "sys", "kernel", "core_pattern"),
		filepath.Join(root, "sys", "kernel", "uevent_helper"),
	} {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
			exposed = append(exposed, p+":writable")
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if len(exposed) > 0 {
		res.Status = model.StatusFail
		res.Observed = fmt.Sprintf("%d_exposed_kernel_paths", len(exposed))
		res.Detail = fmt.Sprintf("host kernel surface accessible: [%s]", strings.Join(exposed, ", "))
		return res
	}
	res.Status = model.StatusPass
	res.Observed = "blocked"
	res.Detail = "/proc/kcore, /proc/sysrq-trigger, core_pattern, uevent_helper are masked/read-only"
	return res
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
