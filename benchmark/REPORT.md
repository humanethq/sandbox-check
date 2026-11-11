# Benchmark Report — `Humanet sandbox-check v0.1.0` on Cloud Linux KVM Host

All runs below were executed sequentially on the **same cloud Linux KVM host** using the identical static `linux/amd64` binary so container defaults, container hardening flags, naive `HTTP_PROXY` configurations, `--network=none`, and a jailed Firecracker microVM could be compared side-by-side without synthetic mocks.

*(Note: The raw Docker JSON files in [`benchmark/raw/`](raw/) preserve `"tool": "sandbox-probe"` metadata recorded during capture before the project was renamed to `Humanet sandbox-check`.)*

- **Environment:** Cloud Linux VM with nested KVM (`linux/amd64`) and live link-local cloud metadata (`169.254.169.254`)
- **Compared runtimes:** Standard Docker containers vs jailed Firecracker microVM (dedicated guest kernel + host L3 firewalling + allowlisting egress proxy)
- **Public Docker baseline artifacts:** [`benchmark/raw/`](raw/) *(raw Firecracker host firewall rules, cgroup topologies, and internal addressing are withheld)*

---

## Summary Results

> Note: Every run starts with `1` `INFO` check (`baseline_network_posture`) recording interface, gateway, and proxy posture; it is informational (neither `PASS` nor `FAIL`). All remaining active checks report `PASS`, `FAIL`, or `WARN`.

| Profile | Exit | Total | Pass | Fail | Warn | Info | Crit / High | Raw Output |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| 1. Docker default | `2` | 36 | 23 | **12** | 0 | 1 | **2 / 9** | [`azure-docker-default.json`](raw/azure-docker-default.json) |
| 2. Docker + Naive `HTTP_PROXY` | `2` | 38 | 23 | **13** | **1** | 1 | **5 / 8** | [`azure-docker-proxy.json`](raw/azure-docker-proxy.json) |
| 3. Docker hardened (`--cap-drop=ALL`, non-root, RO, cgroups) | `2` | 36 | 25 | **10** | 0 | 1 | **2 / 7** | [`azure-docker-hardened.json`](raw/azure-docker-hardened.json) |
| 4. Docker `--network=none` + hardened | `0` | 27 | 26 | **0** | 0 | 1 | **0 / 0** | [`azure-docker-none.json`](raw/azure-docker-none.json) |
| 5. **[Frame](https://frame.humanet.dev) Firecracker microVM** (jailed microVM + host L3 drops + allowlisted proxy) | `0` | 38 | **37** | **0** | **0** | 1 | **0 / 0** | Redacted *(internal infra telemetry withheld)* |

---

## Reproducible Docker Baselines & Measured Breakdown

### 1. Docker Default

```bash
docker run --rm \
  -e OPENAI_API_KEY=sk-bench-dummy-key-never-real \
  -v "$PWD/bin/sandbox-check:/sandbox-check:ro" \
  ubuntu:24.04 /sandbox-check --json
```

**Measured findings (12 failures, 2 critical, 9 high, 1 medium):**
- **Cloud IMDS reachable directly (`critical`):** `GET http://169.254.169.254:80/metadata/instance?api-version=2021-02-01` returned **HTTP 200** (`2129` bytes body omitted); `PUT /latest/api/token` reached the IMDS listener (`HTTP 400`, `322` bytes).
- **Direct DNS tunneling & unproxied egress (`high`/`medium`):** UDP:53 to `1.1.1.1:53` and `8.8.8.8:53` both returned `121`-byte DNS answers; raw TCP:53 (`1.1.1.1:53`) and raw TCP:443 (`1.1.1.1:443`) succeeded.
- **Host gateway daemons exposed:** `172.17.0.1:22` and `172.17.0.1:80` both completed TCP handshakes (`rfc1918_172_17_0_1`, `host_172_17_0_1_ssh_22`, `host_172_17_0_1_http_80`).
- **Linux container surface & limits:** `uid=0`, `NoNewPrivs=0`, 6 dangerous effective capabilities (`CAP_DAC_OVERRIDE`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_RAW`, `CAP_SYS_CHROOT`), `memory.max="max"`, `cpu.max="max 100000"`.
- **Credential exposure:** raw `OPENAI_API_KEY` readable in process environment.

---

### 2. Docker + Naive `HTTP_PROXY` ("Proxy Theater")

A minimal forward HTTP/CONNECT proxy (`naive-proxy:8888`) was attached to a standard Docker bridge network (`sandbox-proxy-bench`), simulating the common pattern of routing agent traffic via `HTTP_PROXY` / `HTTPS_PROXY` without host-side L3 drops or destination filtering:

```bash
docker network create sandbox-proxy-bench
docker run -d --name naive-proxy --network sandbox-proxy-bench \
  -v "${tmpdir}/naive-proxy:/naive-proxy:ro" ubuntu:24.04 /naive-proxy

docker run --rm --network sandbox-proxy-bench \
  -e HTTP_PROXY=http://naive-proxy:8888 \
  -e HTTPS_PROXY=http://naive-proxy:8888 \
  -e OPENAI_API_KEY=sk-bench-dummy-key-never-real \
  -v "$PWD/bin/sandbox-check:/sandbox-check:ro" \
  ubuntu:24.04 /sandbox-check --json
```

**Measured findings (13 failures, 1 warning, 5 critical, 8 high):**
- **Every direct bypass remained open:** Ignoring `HTTP_PROXY`, direct UDP:53 DNS (`dns_tunnel_bypass`, upgraded to **`critical`** when proxy env is present), direct TCP:53, direct TCP:443, direct cloud IMDS **HTTP 200**, gateway `:22`/`:80`, and `172.17.0.1:80` all succeeded.
- **Naive proxy added SSRF (`critical`):** `proxy_ssrf_imds_v4` asked `http://naive-proxy:8888` to fetch `http://169.254.169.254/metadata/instance?api-version=2021-02-01` and the proxy returned **HTTP 200** (`2129` bytes) from the host side.
- **Unfiltered proxy loopback dial (`WARN`, `critical`):** `proxy_ssrf_loopback_docker` (`http://127.0.0.1:2375/_ping`) returned **HTTP 502** instead of an explicit `403`/`407`, showing the proxy attempted an upstream loopback dial rather than denying internal targets upfront.

---

### 3. Docker Hardened (Non-Root, Drop-All Caps, Read-Only Root, Cgroups)

```bash
docker run --rm \
  --user 65532:65532 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --memory=256m \
  --cpus=1 \
  --pids-limit=128 \
  -e OPENAI_API_KEY=sk-bench-dummy-key-never-real \
  -v "$PWD/bin/sandbox-check:/sandbox-check:ro" \
  ubuntu:24.04 /sandbox-check --json
```

**Measured findings (10 failures, 2 critical, 7 high, 1 medium):**
- **What hardening fixed:** `linux_capabilities_and_seccomp` (`minimal_caps`, `uid=65532`, `NoNewPrivs=1`, `Seccomp=2`) and `cgroup_v2_limits` (`memory.max="268435456"`, `pids.max="128"`, `cpu.max="100000 100000"`) both passed.
- **What remained broken:** Because Docker's default bridge and environment model were unchanged, **all 8 network failures** (including **Cloud IMDS HTTP 200**, host `:22`/`:80`, UDP:53 DNS, raw TCP:443) **and raw `OPENAI_API_KEY` env exposure still failed** identically to unhardened Docker.

---

### 4. Docker `--network=none` + Hardened

```bash
docker run --rm --network=none \
  --user 65532:65532 --cap-drop=ALL --security-opt=no-new-privileges \
  --read-only --memory=256m --cpus=1 --pids-limit=128 \
  -v "$PWD/bin/sandbox-check:/sandbox-check:ro" \
  ubuntu:24.04 /sandbox-check --json
```

**Measured findings (0 failures across 26 active checks + 1 INFO baseline, exit `0`):**
- Disconnecting networking entirely closes IMDS, proxy bypass, host gateway, and lateral network paths (`no_external_interface`).
- **Trade-off:** The sandbox has zero outbound connectivity (cannot reach LLM APIs, package registries, webhooks, or external SaaS). Note `27` total checks vs `36`/`38` because bridge-gateway and `HTTP_PROXY` checks do not apply when no interface or proxy exists.

---

### 5. Frame Firecracker MicroVM Summary (Allowlisted Egress + Placeholder Tokens)

On the same cloud KVM host, checks were executed inside a jailed [Frame](https://frame.humanet.dev) Firecracker microVM configured with hypervisor isolation, host-enforced L3 network isolation (`ip_forward=0` plus per-VM host firewall drops), an allowlisting HTTP/HTTPS proxy, and host-held credentials (placeholder token only inside the guest).

> Exact host firewall tables, jailer/cgroup configurations, proxy bind addresses/ports, subnetting, and token mechanisms are withheld to keep production defense internals private.

**Measured findings (37/37 active checks `PASS`, 0 failures, 0 warnings, 1 `INFO` baseline, exit `0`):**
- **Network + IMDS + Bypass (`PASS`):** All cloud IMDS endpoints (`169.254.169.254` AWS/Azure/GCP, IMDSv2 PUT, ECS `169.254.170.2`, IPv6 `[fd00:ec2::254]`, `100.100.100.200`), raw UDP:53 (`1.1.1.1`, `8.8.8.8`), raw TCP:53, raw TCP:443, host gateway ports (`22`, `80`, `2375`, `4222`, `5432`, `6379`, `9000`, `10250`, `11434`), RFC1918/CGNAT ranges, and TCP:25 timed out or were dropped before egress.
- **Proxy SSRF Explicitly Denied + Allowlisted HTTPS Preserved (`PASS`):**
  - `proxy_ssrf_imds_v4` (`http://169.254.169.254/...`): proxy explicitly returned **HTTP 403** (`proxy_denied_http_403`).
  - `proxy_ssrf_loopback_docker` (`http://127.0.0.1:2375/_ping`): proxy explicitly returned **HTTP 403** (`proxy_denied_http_403`).
  - Inside the same VM, an allowlisted HTTPS request routed through the proxy returned **HTTP 200**.
- **Runtime, Resource Bounds & Secrets (`PASS`):**
  - `detected_runtime="firecracker_microvm"` with dedicated guest kernel, bounded guest memory/vCPU limits, absent container runtime sockets and `/dev/kvm`, and placeholder env tokens only (`observed: "phantom_tokens_only"` — zero raw API keys visible in guest env).

---

## Limitations & Scope

1. **Single host / provider snapshot:** Measured on one Linux KVM cloud host with link-local cloud IMDS active on `169.254.169.254`. Different cloud providers, AWS IMDSv2-required hosts, Kubernetes CNI plugins (`NetworkPolicy` with Cilium/Calico), and local Docker Desktop environments behave differently.
2. **Workload-side check scope vs comprehensive security guarantees:** `Humanet sandbox-check` checks common misconfigurations observable from inside a workload. A `37/37` (`+1 INFO`, `0 FAIL`) run is **not** a guarantee of "100% security" and does **not** substitute for an independent penetration test or production architecture audit. Passing `sandbox-check` does not prove absence of hypervisor/kernel CVEs, speculative-execution side channels, DNS-over-HTTPS tunneling through an allowlisted domain, or application-level flaws.
3. **Why total check counts differ across runs:** Every run emits `1` `INFO` record (`baseline_network_posture`) that documents network shape and never counts as `PASS` or `FAIL`. Bridge-gateway and `HTTP_PROXY` SSRF checks execute only when a gateway or `HTTP_PROXY` env is present (`36` without proxy, `38` with proxy, `27` under `--network=none`).
4. **MicroVM kernel nodes (`/dev/mem`, `/proc/kcore`):** Inside a Firecracker VM, `/dev/mem` and `/proc/kcore` exist inside the guest kernel's own memory space (isolated from host RAM by KVM/EPT hardware). `sandbox-check` marks them `guest_only_memory` / `guest_only_kernel` when a microVM guest kernel (`virtio-mmio` / DMI) is detected, while still failing if nested `/dev/kvm` or host runtime sockets are exposed.
