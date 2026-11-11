# ![Humanet sandbox-check](docs/head.png)

![Go 1.22+](https://img.shields.io/badge/go-1.22+-00ADD8.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A zero-dependency Go CLI that verifies isolation **from inside** an AI agent sandbox (container, pod, or microVM) — testing whether untrusted code can actually reach cloud metadata endpoints, bypass `HTTP_PROXY`, SSRF the proxy, talk to host services, escape via kernel surfaces/capabilities, exhaust host resources, or read raw API keys from its environment.

Most sandbox checklists run on the host ("did we pass `--cap-drop=ALL`?"). **Inside** a real cloud VM, default Docker bridges, naive `HTTP_PROXY` configurations, and container-hardening flags still routinely leak cloud IMDS, allow raw UDP DNS tunneling, expose host services on the bridge gateway, and hand raw credentials to untrusted code.

Unlike passive baseline-enumeration probes, **Humanet sandbox-check** actively tests common escape and exfiltration paths from inside the workload and **fails closed** with exit code `2` on any detected isolation gap (or `0` when all active checks pass).

---

## Install

Precompiled static binaries (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, verified via SHA256):

```bash
curl -fsSL https://raw.githubusercontent.com/humanethq/sandbox-check/main/install.sh | bash
```

Or build from source (Go 1.22+):

```bash
go install github.com/humanethq/sandbox-check/cmd/sandbox-check@latest
```

---

## Quick Usage

Run directly inside any container, Kubernetes pod, or microVM:

```bash
# Human-readable isolation check report (exit code 2 if any check fails, 0 if clean)
sandbox-check

# Machine-readable JSON report (for CI / automated harnesses)
sandbox-check --json

# Assert cross-tenant isolation against another sandbox IP:port on the same host
sandbox-check --peer 10.244.0.15:8080

# Intentional direct public HTTPS egress (only audit IMDS, host, lateral, runtime, limits, secrets)
sandbox-check --allow-public-net
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--json` | `false` | Emit structured JSON report to stdout |
| `--timeout` | `900ms` | Per-check network dial timeout |
| `--gateway` | auto (`/proc/net/route`) | Override detected gateway IP for host service checks |
| `--peer` | `""` | Optional `ip:port` of another tenant/sandbox to verify L3 deny |
| `--external-ip` | `1.1.1.1` | Public IP used to test direct raw TCP:443 / TCP:25 egress bypass |
| `--allow-public-net` | `false` | Do not fail direct outbound TCP:443 when public net is intentional |
| `--version` | `false` | Print Humanet sandbox-check version and exit |

---

## What It Checks (8 Categories)

Every run starts with a `baseline_network_posture` (`INFO`) check recording non-loopback interfaces, default gateway, resolvers, and proxy environment variables so empty/offline environments are never misread as "filtered".

| Category | Checks | Why it matters |
|---|---|---|
| **Cloud Metadata / IMDS** | `169.254.169.254:80` (AWS v1, AWS IMDSv2 PUT token, Azure `/metadata/instance?api-version=2021-02-01`, GCP `/computeMetadata/v1/`), ECS `169.254.170.2`, AWS IPv6 `[fd00:ec2::254]`, Alibaba `100.100.100.200` | Connects directly with `Proxy: nil` (ignoring `HTTP_PROXY`). Never logs or prints response bodies — only status codes and byte counts. |
| **Proxy Bypass & SSRF** | Direct UDP:53 (`1.1.1.1`, `8.8.8.8`), direct TCP:53, direct TCP:443; if `HTTP_PROXY`/`HTTPS_PROXY` is set, also checks proxy SSRF to IMDS IPv4 and `http://127.0.0.1:2375/_ping` | Catches **"proxy theater"**: setting `HTTP_PROXY` while leaving raw UDP/TCP open, or running a naive proxy that forwards requests to cloud IMDS or host loopback (`403/407/451` = `PASS`, `502` = `WARN`, `2xx` = `FAIL`). |
| **Host Gateway Services** | Auto-detected gateway + `host.docker.internal` across ports `22` (SSH), `80` (HTTP), `2375` (Docker), `4222` (NATS), `5432` (Postgres), `6379` (Redis), `9000` (MinIO), `10250` (Kubelet), `11434` (Ollama) | Bridge gateways frequently expose host daemons bound to `0.0.0.0` or bridge interfaces. |
| **Lateral RFC1918 & SMTP** | `10.0.0.1:80`, `172.16.0.1:80`, `172.17.0.1:80`, `192.168.1.1:80`, CGNAT `100.64.0.1:80`, SMTP `1.1.1.1:25`, optional `--peer` | Verifies private network lateral denial and anti-spam port 25 blocking. |
| **Kernel, Caps & Mounts** | `/proc/self/status` (`CapEff`, `Seccomp`, `NoNewPrivs`), `/proc/mounts` (runtime sockets, host home binds, rw shared cgroup v2), `/proc/kcore`, `/proc/sysrq-trigger`, `core_pattern`, `uevent_helper`, `/var/run/docker.sock`, `containerd.sock`, `crio.sock`, `/dev/kvm`, `/dev/mem` | Distinguishes shared-kernel containers from dedicated microVM guest kernels (`virtio-mmio` / DMI detection) so guest-local `devtmpfs`/`procfs` inside a hypervisor isn't misreported as host exposure while nested `/dev/kvm` still fails. |
| **Resource Limits** | Cgroup v2 `memory.max`, `pids.max`, `cpu.max` in containers; hypervisor `MemTotal` / vCPU ceiling (`/proc/meminfo`) in microVMs | Unbounded `memory.max=max` or `pids.max=max` allows trivial fork/OOM DoS against sibling workloads. |
| **Environment Secrets** | Scans env key names (`*_API_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `DATABASE_URL`, etc.) | Flags raw credential values in guest env (`FAIL`) while recognizing placeholder/phantom tokens (`phm_*`, `phantom_*`, `vault:*`, `op://*`) as `PASS`. Never outputs secret or phantom values. |

---

## Live Benchmark Snapshot (Cloud Linux KVM Host)

All 5 configurations were executed sequentially on the same cloud Linux KVM host (`linux/amd64`), comparing standard Docker setups against a jailed Firecracker microVM. Full methodology, Docker baseline commands/JSON outputs, and scope limits are in [`benchmark/REPORT.md`](benchmark/REPORT.md).

| Configuration | Active Checks Passed | Fail | Warn | Crit / High | Key Empirical Findings |
|---|---:|---:|---:|---:|---|
| **Docker default** (`docker run`) | 23/35 (`+1 INFO`) | **12** | 0 | **2 / 9** | Cloud IMDS **HTTP 200** (`2129 B`), UDP:53 & TCP:443 open, host `:22`/`:80` open, 6 caps, `memory.max=max`, raw secret |
| **Docker + Naive `HTTP_PROXY`** | 23/37 (`+1 INFO`) | **13** | **1** | **5 / 8** | UDP:53 DNS tunnel bypasses proxy; **proxy SSRF returned Cloud IMDS HTTP 200** + loopback `502` warning |
| **Docker hardened** (`--user 65532:65532 --cap-drop=ALL --security-opt=no-new-privileges --read-only --memory=256m --cpus=1 --pids-limit=128`) | 25/35 (`+1 INFO`) | **10** | 0 | **2 / 7** | Caps/cgroups fixed, **still leaks Cloud IMDS HTTP 200**, host `:22`/`:80`, UDP:53, TCP:443, and raw env secret |
| **Docker `--network=none`** (hardened) | 26/26 (`+1 INFO`) | **0** | 0 | **0 / 0** | Clean (`exit 0`), **at the cost of zero outbound network** (cannot reach LLM APIs or packages) |
| **[Frame](https://frame.humanet.dev) Firecracker microVM** (jailed microVM + host firewall + allowlisted egress proxy + placeholder token) | **37/37** (`+1 INFO`) | **0** | **0** | **0 / 0** | Isolated guest kernel with bounded CPU/RAM, host L3 drops on IMDS/gateway/RFC1918/UDP:53/TCP:25, proxy returned **403** on IMDS/loopback SSRF, allowlisted HTTPS check returned **HTTP 200** |

> **Result & Scope Notes:**
> - **About the `+1 INFO` baseline (`37/37` vs `38 total`):** Every `sandbox-check` run starts with one non-failing, non-passing `INFO` check (`baseline_network_posture`) that records whether a network interface, gateway, and proxy env exist so offline environments are never mistaken for filtered ones. In the Firecracker run above, `total=38` comprises `37 PASS`, `1 INFO` baseline, `0 FAIL`, and `0 WARN`.
> - **Not a substitute for independent security review:** `sandbox-check` verifies common workload-side misconfigurations from inside a sandbox. Passing all implemented checks does **not** guarantee "100% security" and does not replace an independent penetration test or host/hypervisor architecture audit. Operational host firewall rules, internal proxy mechanics, and provisioning internals for Frame are intentionally kept private.

> Built alongside [Humanet airgap-check](https://github.com/humanethq/airgap-check) and [Frame](https://frame.humanet.dev) by [Humanet](https://humanet.dev); `sandbox-check` is standalone, MIT-licensed, and requires nothing outside Go's standard library.

---

## Development

```bash
make test          # Run unit suite (or: go test -race -count=1 ./...)
make vet           # Run go vet
make build         # Build local static binary into bin/sandbox-check
make release-bins  # Cross-compile linux/darwin amd64/arm64 + SHA256 checksums
```

---

## License

MIT — see [LICENSE](LICENSE).
