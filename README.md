# ![Humanet sandbox-check](docs/head.png)

[![CI](https://github.com/humanethq/sandbox-check/actions/workflows/ci.yml/badge.svg)](https://github.com/humanethq/sandbox-check/actions/workflows/ci.yml) ![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A zero-dependency Go CLI that audits sandbox isolation **from inside** an AI agent runtime (container, Kubernetes pod, or microVM) — testing whether untrusted code can actually reach cloud metadata endpoints, bypass `HTTP_PROXY` (UDP DNS, raw TCP, or `CONNECT` tunneling), SSRF the proxy, hit host services, escape shared kernel surfaces, exhaust unbounded cgroups, or read raw API keys from its environment.

---

## The Problem

Most sandbox checklists run on the host (*"did we pass `--cap-drop=ALL`?"*). Inside real cloud VMs, container-hardening flags and `HTTP_PROXY` setups still routinely leak cloud IMDS (`169.254.169.254`), allow raw UDP:53 DNS tunneling, expose host services on the bridge gateway, permit HTTP `CONNECT` tunnels to localhost/IMDS, or pass raw secrets in process env vars.

**Humanet sandbox-check** tests common escape and exfiltration paths directly from inside the workload and **fails closed** with deterministic exit codes (`0` pass, `2` failure, `3` warnings/inconclusive).

---

## Quick Start

### Install precompiled binary (`v0.2.0`, SHA256-verified)

```bash
# Pinned release install (recommended)
curl -fsSL https://raw.githubusercontent.com/humanethq/sandbox-check/main/install.sh \
  | SANDBOX_CHECK_VERSION=v0.2.0 bash
```

To verify build provenance via GitHub Artifact Attestations (`gh` CLI required):

```bash
curl -fsSL https://raw.githubusercontent.com/humanethq/sandbox-check/main/install.sh \
  | SANDBOX_CHECK_VERSION=v0.2.0 SANDBOX_CHECK_VERIFY_ATTESTATION=1 bash
```

Or install from source (Go 1.22+):

```bash
go install github.com/humanethq/sandbox-check/cmd/sandbox-check@v0.2.0
```

### Run inside a sandbox

```bash
# Human-readable isolation audit report
sandbox-check

# Structured JSON report (for CI / automated harnesses)
sandbox-check --json

# Fail closed even on WARN results (treat HTTP 502 proxy errors or unthrottled CPU as exit 2)
sandbox-check --strict

# Assert cross-tenant isolation against another sandbox IP:port on the same host
sandbox-check --peer 10.244.0.15:8080

# Allow direct outbound TCP:443 when public internet access is intentional
sandbox-check --allow-public-net
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--json` | `false` | Emit structured JSON report (`tool`, `version`, `verdict`, `summary`, `probes`) |
| `--strict` | `false` | Exit `2` on `WARN` results (instead of exit `3`) |
| `--timeout` | `900ms` | Per-probe network dial timeout |
| `--gateway` | auto (`/proc/net/route`) | Override detected gateway IP for host service checks |
| `--peer` | `""` | Optional `ip:port` of another tenant/sandbox to assert L3 deny |
| `--external-ip` | `1.1.1.1` | Public IP used for direct raw TCP:443 / TCP:25 bypass checks |
| `--allow-public-net` | `false` | Do not fail direct outbound TCP:443 when public egress is intentional |
| `--version` | `false` | Print Humanet sandbox-check version and exit |

---

## Example Output

### CLI summary (hardened Docker container with default bridge)

```text
HUMANET SANDBOX-CHECK v0.2.0 — runtime=docker_container (linux/amd64) uid=65532 pid1="sandbox-check" gw="172.17.0.1" proxy_env=true
======================================================================================

[BASELINE]
  INFO baseline_network_posture         eth0                     routed_with_gateway+http_proxy

[CLOUD METADATA / IMDS]
  FAIL imds_aws_gcp_azure_v4            169.254.169.254:80/me... metadata_exposed_http_200 (CRITICAL)
       -> HTTP GET http://169.254.169.254:80/metadata/instance?api-version=2021-02-01 responded 200 (2129 bytes body omitted)

[PROXY BYPASS & DIRECT EGRESS]
  FAIL bypass_udp53_cloudflare          1.1.1.1:53/udp           dns_tunnel_bypass (CRITICAL)
  FAIL proxy_ssrf_imds_v4               http://169.254.169.2... proxy_ssrf_http_200 (CRITICAL)
  WARN proxy_ssrf_loopback_docker       http://127.0.0.1:2375... proxy_upstream_error_http_502 (CRITICAL)
  FAIL proxy_connect_imds_v4            CONNECT 169.254.169.... proxy_connect_tunnel_open (CRITICAL)
...
SUMMARY: total=40 pass=23 fail=15 warn=1 info=1 skip=0 (critical=7 high=7)
RESULT: ISOLATION GAPS DETECTED [verdict=fail] (exit code 2)
```

*(When `fail=0` and `warn>0`, `sandbox-check` explicitly outputs `RESULT: WARNINGS DETECTED / INCONCLUSIVE [verdict=warn] (exit code 3)`, never `"NO DETECTED LEAKS"`.)*

### JSON snippet (`--json`)

```json
{
  "tool": "sandbox-check",
  "version": "v0.2.0",
  "verdict": "fail",
  "summary": {
    "total": 40,
    "passed": 23,
    "failed": 15,
    "warned": 1,
    "info": 1,
    "skipped": 0,
    "critical_leaks": 7,
    "high_leaks": 7
  }
}
```

---

## What It Checks & Status Semantics

### 8 Probe Categories

| Category | Checks | Why it matters |
|---|---|---|
| **Baseline** (`INFO`) | `baseline_network_posture` | Records non-loopback IPs, gateway, DNS resolvers, and proxy env so offline sandboxes are not confused with firewalling. |
| **Cloud Metadata / IMDS** | `169.254.169.254` (AWS v1, IMDSv2 PUT token, Azure, GCP), ECS `169.254.170.2`, IPv6 `[fd00:ec2::254]`, Alibaba `100.100.100.200` | Connects directly (`Proxy: nil`, bypassing `HTTP_PROXY`). Never logs response bodies — only HTTP status and byte counts. |
| **Proxy Bypass & SSRF** | UDP:53 (`1.1.1.1`, `8.8.8.8`, verifying DNS `QR=1` vs raw echo), direct TCP:53/TCP:443; when `HTTP_PROXY` is set: multi-path IMDS HTTP SSRF, loopback `:2375` SSRF, and raw `CONNECT` tunnel probes to IMDS/loopback | Catches **"proxy theater"**: setting `HTTP_PROXY` while leaving raw sockets open, path-filtering only `/latest/meta-data/`, or permitting `CONNECT 169.254.169.254:80`. |
| **Host Gateway Services** | Auto gateway + `host.docker.internal` on ports `22`, `80`, `2375` (Docker), `4222` (NATS), `5432` (Postgres), `6379` (Redis), `9000` (MinIO), `10250` (Kubelet), `11434` (Ollama) | Bridge gateways frequently expose host daemons listening on `0.0.0.0` or bridge interfaces. |
| **Lateral RFC1918 & SMTP** | `10.0.0.1:80`, `172.16.0.1:80`, `172.17.0.1:80`, `192.168.1.1:80`, `100.64.0.1:80`, `1.1.1.1:25`, optional `--peer` | Verifies private network lateral deny and outbound SMTP port 25 blocking. |
| **Kernel, Caps & Mounts** | Runtime detection (Docker `.dockerenv`, Podman `.containerenv`, cgroup v1/v2, PID-1 `container=`, root `overlay`, Firecracker `virtio-mmio`, DMI fallback), `CapEff`, `Seccomp`, `NoNewPrivs`, `/proc/mounts` + `/proc/self/mountinfo` (sockets, host `/home`/`/Users`/`/root` binds, `rw /sys/fs/cgroup`), `/proc/kcore`, `/proc/sysrq-trigger`, `core_pattern`, `uevent_helper`, host sockets & `/dev/{kvm,mem}` | Prevents containers with private cgroup namespaces (`0::/`) on cloud VMs from being misclassified as VMs while accurately handling true dedicated Firecracker guest kernels. |
| **Resource Limits** | Cgroup v2 (`memory.max`, `pids.max`, `cpu.max`), cgroup v1 fallback (`memory.limit_in_bytes`, `pids.max`, `cpu.cfs_quota_us`), and microVM `/proc/meminfo` + vCPU bounds | Fails on unbounded memory or PIDs; emits `WARN` (`unthrottled_cpu`) when memory/PIDs are bounded yet CPU quota is `max`/`-1`. |
| **Environment Secrets** | Env key audit (`*_API_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `DATABASE_URL`, etc.) | Fails on raw secret values (always redacted); passes when only placeholder/phantom tokens (`phm_*`, `phantom_*`, `vault:*`, `op://*`) exist. |

### Statuses & Exit Codes

| Status | Meaning | Default Exit Code | `--strict` Exit Code |
|---|---|---:|---:|
| `PASS` | Blocked (`dropped_timeout`, `refused`, `unreachable`, `no_route`, `blocked_seccomp`), explicit proxy deny (`403`/`407`/`451`), absent socket, bounded limits, or no raw secrets | `0` | `0` |
| `WARN` | Ambiguous/partial risk (e.g. proxy returned `502`/`5xx` indicating upstream dial attempt, or bounded memory/PIDs with unthrottled `cpu.max`) | **`3`** (`verdict: "warn"`) | **`2`** |
| `FAIL` | Confirmed leak or missing boundary (open IMDS, DNS tunnel bypass, proxy SSRF `2xx`/`CONNECT`, reachable host service, dangerous caps, unbounded memory/PIDs, raw secret) | **`2`** (`verdict: "fail"`) | **`2`** |
| `INFO` / `SKIP` | Context record (`baseline_network_posture`) or platform N/A (`non_linux_host` on macOS) | `0` | `0` |

---

## Platform Support & Kubernetes Usage

| Platform | Network, IMDS, Proxy Bypass, Secrets | Kernel, Caps, Mounts, Cgroup Limits |
|---|---|---|
| **Linux** (`amd64`, `arm64`) | Supported | Supported (cgroup v2 + v1 fallback) |
| **macOS** (`amd64`, `arm64`) | Supported | `SKIP` (`non_linux_host`) — intended for running inside Linux containers/VMs |

### Ephemeral Kubernetes Pod check

Run a temporary SHA256-verified probe pod in the target namespace (`linux/amd64`):

```bash
kubectl run sandbox-check --rm -i --restart=Never --image=alpine:3.20 -- sh -ec '
  apk add -q --no-cache curl
  curl -fsSLO https://github.com/humanethq/sandbox-check/releases/download/v0.2.0/sandbox-check-linux-amd64
  curl -fsSLO https://github.com/humanethq/sandbox-check/releases/download/v0.2.0/checksums.txt
  grep "sandbox-check-linux-amd64" checksums.txt | sha256sum -c -
  chmod +x sandbox-check-linux-amd64 && ./sandbox-check-linux-amd64
'
```

Or copy the static Linux binary directly into any running pod or container:

```bash
kubectl cp ./sandbox-check-linux-amd64 my-pod:/tmp/sandbox-check
kubectl exec -it my-pod -- /tmp/sandbox-check --json
```

---

## Live Benchmark Snapshot (Cloud Linux KVM Host)

Executed sequentially on the same cloud Linux KVM host (`linux/amd64`, with live link-local cloud metadata on `169.254.169.254`). Full methodology, Docker commands, and captured JSON files are in [`benchmark/REPORT.md`](benchmark/REPORT.md).

| Configuration | Active Checks Passed | Fail | Warn | Crit / High | Key Findings |
|---|---:|---:|---:|---:|---|
| **Docker default** (`docker run`) | 23/35 (`+1 INFO`) | **12** | 0 | **2 / 9** | Cloud IMDS **HTTP 200** (`2129 B`), UDP:53 & TCP:443 open, host `:22`/`:80` open, 6 caps, `memory.max=max`, raw secret |
| **Docker + Naive `HTTP_PROXY`** | 23/37 (`+1 INFO`) | **13** | **1** | **5 / 8** | UDP:53 DNS tunnel bypasses proxy; **proxy SSRF returned Cloud IMDS HTTP 200** + loopback `502` warning |
| **Docker hardened** (`--cap-drop=ALL`, non-root, RO, cgroups) | 25/35 (`+1 INFO`) | **10** | 0 | **2 / 7** | Caps/cgroups fixed, **still leaks Cloud IMDS HTTP 200**, host `:22`/`:80`, UDP:53, TCP:443, and raw env secret |
| **Docker `--network=none`** (hardened) | 26/26 (`+1 INFO`) | **0** | 0 | **0 / 0** | Passes (`exit 0`), **because networking is completely disabled** (cannot call LLM APIs or fetch dependencies) |
| **[Frame](https://frame.humanet.dev) Firecracker microVM** (jailed microVM + host L3 drops + allowlisting proxy + placeholder token) | **37/37** (`+1 INFO`) | **0** | **0** | **0 / 0** | Passes with **allowlisted outbound HTTPS still working** (`HTTP 200`), isolated guest kernel, IMDS/RFC1918/UDP:53/TCP:25 dropped, proxy denied SSRF (`HTTP 403`), zero raw secrets |

---

## Limitations & Scope

- **`refused` vs `dropped_timeout`:** When a port is closed on a reachable IP, TCP returns `ECONNREFUSED` (`observed: "refused"` -> `PASS` since nothing answered), whereas a firewall/nftables drop times out (`observed: "dropped_timeout"`). An in-guest probe cannot prove from timing alone whether a silent drop came from nftables vs blackhole routing — inspect `observed` carefully alongside host rules.
- **Environment-only secret scope:** `env_secret_exposure` checks process environment variable names (and recognizes phantom prefixes like `phm_`/`phantom_`). Credentials stored on disk (`~/.aws`, `~/.kube`, Mounted secrets), Unix socket agents, or custom non-standard env names are out of scope.
- **Workload audit ≠ comprehensive pentest:** Passing all `sandbox-check` probes verifies common guest-observable misconfigurations; it does not prove absence of hypervisor/kernel CVEs, DNS-over-HTTPS abuse via allowlisted domains, or application vulnerabilities, and does not replace an independent penetration test.

---

> Built alongside [Humanet airgap-check](https://github.com/humanethq/airgap-check) and [Frame](https://frame.humanet.dev) by [Humanet](https://humanet.dev).

---

## Development

```bash
make test          # Run unit suite with -race
make vet           # Run go vet
make build         # Build local static binary into bin/sandbox-check
make release-bins  # Cross-compile linux/darwin amd64/arm64 + SHA256 checksums
```

## License

MIT — see [LICENSE](LICENSE).
