package hostprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/humanethq/sandbox-check/internal/model"
)

func TestDecodeDangerousCapabilities(t *testing.T) {
	// CapEff 000001ffffffffff corresponds to broad root container capabilities including CAP_SYS_ADMIN (bit 21) & CAP_NET_ADMIN (bit 12)
	caps, err := DecodeCapabilities("000001ffffffffff")
	if err != nil {
		t.Fatalf("DecodeCapabilities: %v", err)
	}
	foundSysAdmin := false
	foundNetAdmin := false
	for _, c := range caps {
		if c == "CAP_SYS_ADMIN" {
			foundSysAdmin = true
		}
		if c == "CAP_NET_ADMIN" {
			foundNetAdmin = true
		}
	}
	if !foundSysAdmin || !foundNetAdmin {
		t.Fatalf("expected CAP_SYS_ADMIN and CAP_NET_ADMIN, got %v", caps)
	}

	none, err := DecodeCapabilities("0000000000000000")
	if err != nil {
		t.Fatalf("DecodeCapabilities(0): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected 0 caps, got %v", none)
	}
}

func TestClassifyEnvSecretsRedactsAllValues(t *testing.T) {
	secretVal := "sk-live-SUPERSECRETVALUE_NEVER_APPEAR_987654321"
	phantomVal := "phantom_0123456789abcdef0123456789abcdef0123456789abcdef"

	res := InspectEnvSecrets([]string{
		"PATH=/usr/bin",
		"OPENAI_API_KEY=" + secretVal,
		"STRIPE_SECRET_KEY=" + phantomVal,
		"MY_RAW_PASS=hunter2secret",
	})

	if res.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL for raw OPENAI_API_KEY + MY_RAW_PASS", res.Status)
	}
	if strings.Contains(res.Observed, secretVal) || strings.Contains(res.Detail, secretVal) ||
		strings.Contains(res.Observed, "hunter2secret") || strings.Contains(res.Detail, "hunter2secret") ||
		strings.Contains(res.Observed, phantomVal) || strings.Contains(res.Detail, phantomVal) {
		t.Fatal("secret or phantom value leaked into ProbeResult!")
	}
	if !strings.Contains(res.Detail, "OPENAI_API_KEY") {
		t.Fatalf("expected secret key name OPENAI_API_KEY in detail, got %q", res.Detail)
	}
}

func TestClassifyEnvSecretsPhantomOnlyPasses(t *testing.T) {
	res := InspectEnvSecrets([]string{
		"PATH=/usr/bin",
		"OPENAI_API_KEY=phantom_0123456789abcdef0123456789abcdef0123456789abcdef",
	})
	if res.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS when only phantom placeholder is injected (detail=%q)", res.Status, res.Detail)
	}
}

func TestCheckCgroupV2LimitsDetectsUnbounded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte("max\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := InspectCgroupV2Dir(dir)
	if res.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL for unbounded memory/pids/cpu", res.Status)
	}
}

func TestCheckCgroupV2LimitsBoundedPasses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("536870912\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte("256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("100000 100000\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := InspectCgroupV2Dir(dir)
	if res.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS (detail=%q)", res.Status, res.Detail)
	}
}

func TestInspectMountsDetectsDockerSockAndSharedCgroupRW(t *testing.T) {
	mounts := strings.Join([]string{
		"overlay / overlay rw,relatime 0 0",
		"tmpfs /var/run/docker.sock tmpfs rw,nosuid,nodev 0 0",
		"cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0",
	}, "\n")

	res := InspectMountsContent(mounts, false)
	if res.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL for docker.sock + rw cgroup in container (detail=%q)", res.Status, res.Detail)
	}
	if !strings.Contains(res.Detail, "docker.sock") {
		t.Fatalf("expected docker.sock mention, got %q", res.Detail)
	}
}

func TestInspectMountsSafeMicroVMAndROContainerPass(t *testing.T) {
	roContainer := strings.Join([]string{
		"overlay / overlay rw,relatime 0 0",
		"cgroup2 /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime 0 0",
	}, "\n")
	if res := InspectMountsContent(roContainer, false); res.Status != model.StatusPass {
		t.Fatalf("ro container status = %s, want PASS (detail=%q)", res.Status, res.Detail)
	}

	vmMounts := strings.Join([]string{
		"/dev/vda / ext4 rw,relatime 0 0",
		"cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0",
	}, "\n")
	if res := InspectMountsContent(vmMounts, true); res.Status != model.StatusPass {
		t.Fatalf("microvm status = %s, want PASS (detail=%q)", res.Status, res.Detail)
	}
}

func TestInspectSeccompStatus(t *testing.T) {
	unconfined := "Name:\tsh\nNoNewPrivs:\t0\nSeccomp:\t0\nCapEff:\t0000000000000000\n"
	if res := InspectSeccompStatus(unconfined, false); res.Status != model.StatusFail {
		t.Fatalf("unconfined container status = %s, want FAIL (detail=%q)", res.Status, res.Detail)
	}

	filtered := "Name:\tsh\nNoNewPrivs:\t1\nSeccomp:\t2\nCapEff:\t0000000000000000\n"
	if res := InspectSeccompStatus(filtered, false); res.Status != model.StatusPass {
		t.Fatalf("seccomp=2 container status = %s, want PASS (detail=%q)", res.Status, res.Detail)
	}
}

func TestInspectProcKcoreIgnoresEmptyMaskAndFlagsReadableELF(t *testing.T) {
	dir := t.TempDir()
	procDir := filepath.Join(dir, "proc")
	if err := os.MkdirAll(procDir, 0755); err != nil {
		t.Fatal(err)
	}
	kcorePath := filepath.Join(procDir, "kcore")

	// Empty file (simulating /dev/null mask returning 0 bytes EOF) must NOT fail.
	if err := os.WriteFile(kcorePath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if res := inspectKernelTriggerPaths(dir, false); res.Status != model.StatusPass {
		t.Fatalf("masked empty kcore status = %s, want PASS (detail=%q)", res.Status, res.Detail)
	}

	// Non-empty ELF header in /proc/kcore must FAIL critically.
	if err := os.WriteFile(kcorePath, []byte("\x7fELF\x02\x01\x01\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if res := inspectKernelTriggerPaths(dir, false); res.Status != model.StatusFail {
		t.Fatalf("readable ELF kcore status = %s, want FAIL (detail=%q)", res.Status, res.Detail)
	}
}

func TestDetectRuntimeNameIdentifiesFirecrackerMicroVM(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"proc/1", "sys/bus/platform/drivers/virtio-mmio"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "proc", "cmdline"), []byte("reboot=k panic=1 nomodule swiotlb=noforce root=/dev/vda rw\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := detectRuntimeNameForOS("linux", dir); got != "firecracker_microvm" {
		t.Fatalf("detectRuntimeNameForOS = %q, want firecracker_microvm", got)
	}
}

func TestInspectProcCapabilitiesMicroVMVsContainer(t *testing.T) {
	status := "Name:\tprobe\nNoNewPrivs:\t0\nSeccomp:\t0\nCapEff:\t000001ffffffffff\n"
	vmRes := inspectProcSelfStatusContent("/proc/self/status", status, true)
	if vmRes.Status != model.StatusPass {
		t.Fatalf("microVM caps status = %s, want PASS (detail=%q)", vmRes.Status, vmRes.Detail)
	}

	ctrRes := inspectProcSelfStatusContent("/proc/self/status", status, false)
	if ctrRes.Status != model.StatusFail {
		t.Fatalf("container full caps status = %s, want FAIL (detail=%q)", ctrRes.Status, ctrRes.Detail)
	}
}

func TestInspectVMMeminfoBounds(t *testing.T) {
	meminfo := "MemTotal:         248132 kB\nMemFree:          198400 kB\n"
	res := InspectVMMeminfo(meminfo, 1)
	if res.Status != model.StatusPass {
		t.Fatalf("InspectVMMeminfo status = %s, want PASS (detail=%q)", res.Status, res.Detail)
	}
	if !strings.Contains(res.Detail, "242 MiB") {
		t.Fatalf("expected 242 MiB in detail, got %q", res.Detail)
	}
}

func TestInspectSocketAndDevicePathsMicroVMDevMem(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"dev", "var/run"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "dev", "mem"), []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dev", "kvm"), []byte{}, 0600); err != nil {
		t.Fatal(err)
	}

	byID := func(res []model.ProbeResult) map[string]model.ProbeResult {
		m := make(map[string]model.ProbeResult, len(res))
		for _, r := range res {
			m[r.ID] = r
		}
		return m
	}

	// Inside a shared-kernel container (!isVM), both /dev/mem and /dev/kvm must fail.
	ctrMap := byID(inspectSocketAndDevicePaths(dir, false))
	if ctrMap["host_dev_mem"].Status != model.StatusFail {
		t.Fatalf("container host_dev_mem status = %s, want FAIL", ctrMap["host_dev_mem"].Status)
	}
	if ctrMap["host_dev_kvm"].Status != model.StatusFail {
		t.Fatalf("container host_dev_kvm status = %s, want FAIL", ctrMap["host_dev_kvm"].Status)
	}

	// Inside a microVM (isVM), guest /dev/mem maps guest RAM only (PASS/info), while /dev/kvm still fails.
	vmMap := byID(inspectSocketAndDevicePaths(dir, true))
	if vmMap["host_dev_mem"].Status != model.StatusPass || vmMap["host_dev_mem"].Observed != "guest_only_memory" {
		t.Fatalf("microVM host_dev_mem = (%s, %s), want (PASS, guest_only_memory)", vmMap["host_dev_mem"].Status, vmMap["host_dev_mem"].Observed)
	}
	if vmMap["host_dev_kvm"].Status != model.StatusFail {
		t.Fatalf("microVM host_dev_kvm status = %s, want FAIL when nested /dev/kvm exposed", vmMap["host_dev_kvm"].Status)
	}
}

func TestDetectRuntimeDoesNotMisclassifyCgroupV2ContainerOnCloudVMAsVM(t *testing.T) {
	// Simulate Podman/containerd container with --cgroupns=private (0::/), no /.dockerenv,
	// overlay root filesystem in /proc/mounts, and underlying cloud VM DMI readable under /sys.
	dir := t.TempDir()
	for _, sub := range []string{"proc/1", "sys/class/dmi/id"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "proc", "1", "cgroup"), []byte("0::/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proc", "mounts"), []byte("overlay / overlay rw,relatime,lowerdir=/var/lib/containers/storage/overlay/l/A,upperdir=/var/lib/containers/storage/overlay/1/diff 0 0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sys", "class", "dmi", "id", "product_name"), []byte("Virtual Machine\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := detectRuntimeNameForOS("linux", dir)
	if strings.HasPrefix(got, "vm_") || strings.HasPrefix(got, "firecracker") {
		t.Fatalf("cgroupv2 overlay container on cloud VM misclassified as %q (must stay container, not VM!)", got)
	}
}

func TestDetectRuntimeIdentifiesPodmanContainerenvAndPid1Environ(t *testing.T) {
	dirPodman := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirPodman, "run"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dirPodman, "sys/class/dmi/id"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirPodman, "run", ".containerenv"), []byte("engine=\"podman\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirPodman, "sys", "class", "dmi", "id", "product_name"), []byte("Google Compute Engine\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := detectRuntimeNameForOS("linux", dirPodman); got != "podman_container" {
		t.Fatalf("podman .containerenv = %q, want podman_container", got)
	}

	dirNspawn := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirNspawn, "proc/1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dirNspawn, "sys/class/dmi/id"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirNspawn, "proc", "1", "environ"), []byte("PATH=/usr/sbin\x00container=systemd-nspawn\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirNspawn, "sys", "class", "dmi", "id", "product_name"), []byte("Amazon EC2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := detectRuntimeNameForOS("linux", dirNspawn); got != "nspawn_container" {
		t.Fatalf("nspawn environ = %q, want nspawn_container", got)
	}
}

func TestCheckCgroupV2WarnsOnUnthrottledCPU(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("536870912\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte("256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := InspectCgroupV2Dir(dir)
	if res.Status != model.StatusWarn {
		t.Fatalf("status = %s, want WARN for bounded mem/pids + unthrottled cpu.max (detail=%q)", res.Status, res.Detail)
	}
	if res.Observed != "unthrottled_cpu" {
		t.Fatalf("observed = %q, want unthrottled_cpu", res.Observed)
	}
}

func TestCheckCgroupV1FallbackLimits(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"memory", "pids", "cpu"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Kernel unlimited memory in cgroup v1 is >= 1<<60 (~9223372036854771712).
	if err := os.WriteFile(filepath.Join(dir, "memory", "memory.limit_in_bytes"), []byte("9223372036854771712\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pids", "pids.max"), []byte("max\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu", "cpu.cfs_quota_us"), []byte("-1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	failRes := InspectCgroupV1Dir(dir)
	if failRes.Status != model.StatusFail {
		t.Fatalf("unbounded cgroup v1 status = %s, want FAIL (detail=%q)", failRes.Status, failRes.Detail)
	}

	if err := os.WriteFile(filepath.Join(dir, "memory", "memory.limit_in_bytes"), []byte("268435456\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pids", "pids.max"), []byte("128\n"), 0644); err != nil {
		t.Fatal(err)
	}
	warnRes := InspectCgroupV1Dir(dir)
	if warnRes.Status != model.StatusWarn {
		t.Fatalf("cgroup v1 with cpu.cfs_quota_us=-1 status = %s, want WARN (detail=%q)", warnRes.Status, warnRes.Detail)
	}

	if err := os.WriteFile(filepath.Join(dir, "cpu", "cpu.cfs_quota_us"), []byte("100000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	passRes := InspectCgroupV1Dir(dir)
	if passRes.Status != model.StatusPass {
		t.Fatalf("bounded cgroup v1 status = %s, want PASS (detail=%q)", passRes.Status, passRes.Detail)
	}
}

func TestInspectMountsDetectsLinuxHostBindsAndIgnoresTmpfs(t *testing.T) {
	riskyMounts := strings.Join([]string{
		"overlay / overlay rw,relatime 0 0",
		"/dev/nvme0n1p1 /home/developer ext4 rw,relatime 0 0",
		"tmpfs /root tmpfs rw,nosuid,nodev 0 0",
	}, "\n")
	res := InspectMountsContent(riskyMounts, false)
	if res.Status != model.StatusFail {
		t.Fatalf("linux /home bind mount status = %s, want FAIL (detail=%q)", res.Status, res.Detail)
	}

	tmpfsOnly := strings.Join([]string{
		"overlay / overlay rw,relatime 0 0",
		"tmpfs /home/sandbox tmpfs rw,nosuid,nodev,noexec 0 0",
		"tmpfs /root tmpfs rw,nosuid,nodev,noexec 0 0",
	}, "\n")
	if res := InspectMountsContent(tmpfsOnly, false); res.Status != model.StatusPass {
		t.Fatalf("read-only container tmpfs under /home or /root falsely failed: %s (detail=%q)", res.Status, res.Detail)
	}

	mountinfo := "412 411 259:1 /home/ubuntu/.aws /app/.aws ro,relatime - ext4 /dev/nvme0n1p1 rw\n"
	if bad := FindRiskyMountinfoEntries(mountinfo, false); len(bad) == 0 {
		t.Fatalf("expected /proc/self/mountinfo /home/ubuntu/.aws bind mount to be flagged")
	}
}
