package netprobe

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/humanethq/sandbox-check/internal/model"
)

type MetadataTarget struct {
	ID       string
	Label    string
	Address  string
	Path     string
	AltPaths []string
	Headers  map[string]string
	Method   string
	Severity model.Severity
}

type Options struct {
	Timeout         time.Duration
	GatewayOverride string
	PeerTarget      string
	ExternalIP      string
	AllowPublicNet  bool
}

// ParseProcNetRoute extracts the default IPv4 gateway (Destination == 00000000) from /proc/net/route.
func ParseProcNetRoute(r io.Reader) (string, string) {
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo == 1 {
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" && len(fields[2]) == 8 {
			raw, err := hex.DecodeString(fields[2])
			if err == nil && len(raw) == 4 && (raw[0]|raw[1]|raw[2]|raw[3]) != 0 {
				// /proc/net/route prints 32-bit little-endian hex on x86_64/arm64 Linux.
				ip := net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
				return ip, fields[0]
			}
		}
	}
	return "", ""
}

// DetectDefaultGateway inspects /proc/net/route on Linux.
func DetectDefaultGateway() (string, string) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }()
	return ParseProcNetRoute(f)
}

// ParseResolvConf parses nameserver entries from /etc/resolv.conf content.
func ParseResolvConf(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

func DetectResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	return ParseResolvConf(f)
}

func HasProxyEnv() bool {
	return FirstHTTPProxyURL() != ""
}

func FirstHTTPProxyURL() string {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// BuildDNSQuery builds a minimal RFC 1035 UDP DNS A query for domain.
func BuildDNSQuery(domain string) ([]byte, uint16, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, 0, errors.New("empty domain")
	}
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, 0, err
	}
	txID := binary.BigEndian.Uint16(idBuf[:])

	pkt := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(pkt[0:2], txID)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // Standard query, recursion desired
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT = 1

	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label %q", label)
		}
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0)                      // root label
	pkt = append(pkt, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
	return pkt, txID, nil
}

// ProbeMetadataHTTP tests reachability of a cloud IMDS endpoint without following proxies or exposing body contents.
func ProbeMetadataHTTP(ctx context.Context, target MetadataTarget, timeout time.Duration) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       target.ID,
		Category: model.CategoryMetadata,
		Severity: target.Severity,
		Target:   target.Address + target.Path,
		Expected: "blocked (drop, unreachable, or explicit proxy deny)",
	}

	// 1. Direct TCP socket dial bypassing any HTTP_PROXY env var.
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", target.Address)
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusPass
		res.Observed = "blocked"
		res.Detail = classifyNetError(err)
		return res
	}
	_ = conn.Close()

	// 2. TCP succeeded — probe candidate metadata paths cleanly with Proxy: nil (never print response body!).
	method := target.Method
	if method == "" {
		method = http.MethodGet
	}
	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil, // force direct connection, never trust HTTP_PROXY here
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	paths := make([]string, 0, 1+len(target.AltPaths))
	paths = append(paths, target.Path)
	paths = append(paths, target.AltPaths...)

	type httpHit struct {
		status int
		url    string
		n      int64
	}
	var bestHit *httpHit
	var lastNetErr error

	for _, p := range paths {
		reqURL := "http://" + target.Address + p
		req, reqErr := http.NewRequestWithContext(ctx, method, reqURL, nil)
		if reqErr != nil {
			lastNetErr = reqErr
			continue
		}
		for k, v := range target.Headers {
			req.Header.Set(k, v)
		}
		resp, httpErr := httpClient.Do(req)
		if httpErr != nil {
			lastNetErr = httpErr
			continue
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		hit := &httpHit{status: resp.StatusCode, url: reqURL, n: n}
		if bestHit == nil || (hit.status >= 200 && hit.status < 300 && (bestHit.status < 200 || bestHit.status >= 300)) {
			bestHit = hit
		}
		if hit.status >= 200 && hit.status < 300 {
			break
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if bestHit == nil {
		res.Status = model.StatusFail
		res.Observed = "tcp_reachable"
		if lastNetErr != nil {
			res.Detail = fmt.Sprintf("direct TCP handshake to %s succeeded; HTTP probe error: %s", target.Address, classifyNetError(lastNetErr))
		} else {
			res.Detail = fmt.Sprintf("direct TCP handshake to %s succeeded", target.Address)
		}
		return res
	}
	res.Target = strings.TrimPrefix(bestHit.url, "http://")

	if bestHit.status == http.StatusForbidden || bestHit.status == http.StatusUnavailableForLegalReasons {
		res.Status = model.StatusFail
		res.Observed = fmt.Sprintf("tcp_reachable_http_%d", bestHit.status)
		res.Detail = fmt.Sprintf("metadata IP accepted direct TCP and returned HTTP %d (%d bytes) — host metadata route is still exposed", bestHit.status, bestHit.n)
		return res
	}

	res.Status = model.StatusFail
	res.Observed = fmt.Sprintf("metadata_exposed_http_%d", bestHit.status)
	res.Detail = fmt.Sprintf("HTTP %s %s responded %d (%d bytes body omitted)", method, bestHit.url, bestHit.status, bestHit.n)
	return res
}

// ProbeDirectUDPDNS attempts a raw UDP:53 DNS lookup ignoring HTTP_PROXY.
func ProbeDirectUDPDNS(ctx context.Context, id, addr string, timeout time.Duration, proxyConfigured bool) model.ProbeResult {
	start := time.Now()
	cat := model.CategoryProxyBypass
	sev := model.SeverityHigh
	if proxyConfigured {
		sev = model.SeverityCritical
	}
	res := model.ProbeResult{
		ID:       id,
		Category: cat,
		Severity: sev,
		Target:   addr + "/udp",
		Expected: "blocked (direct UDP:53 egress dropped)",
	}

	pkt, txID, err := BuildDNSQuery("sandbox-check-canary.invalid")
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusSkip
		res.Observed = "query_build_error"
		res.Detail = err.Error()
		return res
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusPass
		res.Observed = "blocked"
		res.Detail = classifyNetError(err)
		return res
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(pkt); err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusPass
		res.Observed = "blocked"
		res.Detail = classifyNetError(err)
		return res
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Status = model.StatusPass
		res.Observed = "blocked"
		res.Detail = classifyNetError(err)
		return res
	}
	if n >= 12 && binary.BigEndian.Uint16(buf[0:2]) == txID {
		res.Status = model.StatusFail
		if proxyConfigured {
			res.Observed = "dns_tunnel_bypass"
			res.Detail = fmt.Sprintf("HTTP_PROXY is set, but raw UDP:53 to %s succeeded (%d byte DNS reply) — DNS tunneling bypasses proxy", addr, n)
		} else {
			res.Observed = "direct_udp53_open"
			res.Detail = fmt.Sprintf("raw UDP:53 packet to external resolver %s answered (%d bytes) — unrestricted DNS exfiltration channel", addr, n)
		}
		return res
	}

	res.Status = model.StatusWarn
	res.Observed = "unexpected_udp_reply"
	res.Detail = fmt.Sprintf("received %d bytes non-matching UDP reply from %s", n, addr)
	return res
}

// ProbeTCPBlocked verifies direct TCP connectivity to addr fails closed.
func ProbeTCPBlocked(ctx context.Context, id string, category model.Category, severity model.Severity, addr string, timeout time.Duration) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		ID:       id,
		Category: category,
		Severity: severity,
		Target:   addr,
		Expected: "blocked (timeout, refused, or network unreachable)",
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Status = model.StatusPass
		res.Observed = "blocked"
		res.Detail = classifyNetError(err)
		return res
	}
	_ = conn.Close()

	res.Status = model.StatusFail
	res.Observed = "reachable"
	res.Detail = fmt.Sprintf("direct TCP handshake to %s succeeded", addr)
	return res
}

// ProbeHTTPProxySSRF checks whether a configured sandbox HTTP_PROXY permits SSRF to IMDS/loopback targets.
func ProbeHTTPProxySSRF(ctx context.Context, id, proxyRawURL, targetURL string, timeout time.Duration) model.ProbeResult {
	return ProbeHTTPProxySSRFTargets(ctx, id, proxyRawURL, []string{targetURL}, nil, timeout)
}

// ProbeHTTPProxySSRFTargets tests candidate URLs through proxyRawURL and upgrades to HTTP 200 if any path succeeds.
func ProbeHTTPProxySSRFTargets(ctx context.Context, id, proxyRawURL string, targetURLs []string, headers map[string]string, timeout time.Duration) model.ProbeResult {
	start := time.Now()
	primary := ""
	if len(targetURLs) > 0 {
		primary = targetURLs[0]
	}
	res := model.ProbeResult{
		ID:       id,
		Category: model.CategoryProxyBypass,
		Severity: model.SeverityCritical,
		Target:   primary,
		Expected: "blocked by proxy (403/407/451 or refused)",
	}

	raw := strings.TrimSpace(proxyRawURL)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	proxyURL, err := url.Parse(raw)
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Status = model.StatusSkip
		res.Observed = "invalid_proxy_url"
		res.Detail = "could not parse proxy URL"
		return res
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type proxyHit struct {
		status int
		url    string
		n      int64
	}
	var best *proxyHit
	var lastErr error

	for _, u := range targetURLs {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			lastErr = doErr
			continue
		}
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()

		hit := &proxyHit{status: resp.StatusCode, url: u, n: n}
		if best == nil || (hit.status >= 200 && hit.status < 300 && (best.status < 200 || best.status >= 300)) {
			best = hit
		}
		if hit.status == http.StatusForbidden || hit.status == http.StatusProxyAuthRequired || hit.status == http.StatusUnavailableForLegalReasons {
			best = hit
			break
		}
		if hit.status >= 200 && hit.status < 300 {
			break
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	if best == nil {
		res.Status = model.StatusPass
		res.Observed = "blocked"
		res.Detail = classifyNetError(lastErr)
		return res
	}
	res.Target = best.url

	switch {
	case best.status == http.StatusForbidden || best.status == http.StatusProxyAuthRequired || best.status == http.StatusUnavailableForLegalReasons:
		res.Status = model.StatusPass
		res.Observed = fmt.Sprintf("proxy_denied_http_%d", best.status)
		res.Detail = fmt.Sprintf("proxy explicitly denied internal SSRF target with HTTP %d", best.status)
	case best.status >= 500:
		res.Status = model.StatusWarn
		res.Observed = fmt.Sprintf("proxy_upstream_error_http_%d", best.status)
		res.Detail = fmt.Sprintf("proxy returned HTTP %d without explicit 403/407 deny (may have attempted upstream dial)", best.status)
	default:
		res.Status = model.StatusFail
		res.Observed = fmt.Sprintf("proxy_ssrf_http_%d", best.status)
		res.Detail = fmt.Sprintf("HTTP_PROXY forwarded internal target %s and returned HTTP %d (%d bytes body omitted)", best.url, best.status, best.n)
	}
	return res
}

func classifyNetError(err error) string {
	if err == nil {
		return "none"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timed out (likely dropped by firewall/nftables or blackhole route)"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "network is unreachable"):
		return "network is unreachable"
	case strings.Contains(msg, "no route to host"):
		return "no route to host"
	case strings.Contains(msg, "operation not permitted"), strings.Contains(msg, "permission denied"):
		return "blocked by seccomp/socket policy (EPERM)"
	default:
		return msg
	}
}

func RunAll(ctx context.Context, opts Options) ([]model.ProbeResult, model.EnvironmentInfo) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 900 * time.Millisecond
	}

	gw, gwIface := DetectDefaultGateway()
	if strings.TrimSpace(opts.GatewayOverride) != "" {
		gw = strings.TrimSpace(opts.GatewayOverride)
	}
	resolvers := DetectResolvers()
	proxySet := HasProxyEnv()

	envInfo := model.EnvironmentInfo{
		DefaultGateway:  gw,
		Resolvers:       resolvers,
		ProxyConfigured: proxySet,
	}

	var results []model.ProbeResult

	// 1. Positive baseline / non-loopback network shape check
	start := time.Now()
	ifaces, ifErr := nonLoopbackIPs()
	netShape := "no_external_interface"
	if len(ifaces) > 0 && gw != "" {
		netShape = "routed_with_gateway"
	} else if len(ifaces) > 0 {
		netShape = "interface_without_default_gateway"
	}
	if proxySet {
		netShape += "+http_proxy"
	}
	ifDesc := "none"
	if ifErr == nil && len(ifaces) > 0 {
		ifDesc = strings.Join(ifaces, ", ")
	}
	results = append(results, model.ProbeResult{
		ID:         "baseline_network_posture",
		Category:   model.CategoryBaseline,
		Severity:   model.SeverityInfo,
		Status:     model.StatusInfo,
		Target:     gwIface,
		Expected:   "documented network posture (prevents false-negative confusion)",
		Observed:   netShape,
		Detail:     fmt.Sprintf("non-loopback IPs=[%s] gateway=%q resolvers=%v proxy_env=%v", ifDesc, gw, resolvers, proxySet),
		DurationMs: time.Since(start).Milliseconds(),
	})

	var checks []func(context.Context) model.ProbeResult

	// 2. Cloud Metadata / Link-Local IMDS probes
	imdsTargets := []MetadataTarget{
		{
			ID:       "imds_aws_gcp_azure_v4",
			Label:    "Cloud IMDS IPv4",
			Address:  "169.254.169.254:80",
			Path:     "/latest/meta-data/",
			AltPaths: []string{"/metadata/instance?api-version=2021-02-01", "/computeMetadata/v1/"},
			Headers:  map[string]string{"Metadata-Flavor": "Google", "Metadata": "true"},
			Severity: model.SeverityCritical,
		},
		{
			ID:       "imds_aws_imdsv2_token",
			Label:    "AWS IMDSv2 PUT",
			Address:  "169.254.169.254:80",
			Path:     "/latest/api/token",
			Method:   http.MethodPut,
			Headers:  map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "60"},
			Severity: model.SeverityCritical,
		},
		{
			ID:       "imds_aws_ecs_task",
			Label:    "AWS ECS Task Metadata",
			Address:  "169.254.170.2:80",
			Path:     "/v2/metadata",
			Severity: model.SeverityCritical,
		},
		{
			ID:       "imds_aws_ipv6",
			Label:    "AWS IPv6 IMDS",
			Address:  "[fd00:ec2::254]:80",
			Path:     "/latest/meta-data/",
			Severity: model.SeverityCritical,
		},
		{
			ID:       "imds_alibaba",
			Label:    "Alibaba/Tencent IMDS",
			Address:  "100.100.100.200:80",
			Path:     "/latest/meta-data/",
			Severity: model.SeverityHigh,
		},
	}
	for _, tgt := range imdsTargets {
		tCopy := tgt
		checks = append(checks, func(c context.Context) model.ProbeResult {
			return ProbeMetadataHTTP(c, tCopy, timeout)
		})
	}

	// 3. Proxy bypass & raw egress probes (DNS tunneling, raw TCP:443/80)
	checks = append(checks,
		func(c context.Context) model.ProbeResult {
			return ProbeDirectUDPDNS(c, "bypass_udp53_cloudflare", "1.1.1.1:53", timeout, proxySet)
		},
		func(c context.Context) model.ProbeResult {
			return ProbeDirectUDPDNS(c, "bypass_udp53_google", "8.8.8.8:53", timeout, proxySet)
		},
		func(c context.Context) model.ProbeResult {
			return ProbeTCPBlocked(c, "bypass_tcp53_direct", model.CategoryProxyBypass, model.SeverityHigh, "1.1.1.1:53", timeout)
		},
	)

	extIP := strings.TrimSpace(opts.ExternalIP)
	if extIP == "" {
		extIP = "1.1.1.1"
	}
	if !opts.AllowPublicNet {
		target443 := net.JoinHostPort(extIP, "443")
		checks = append(checks, func(c context.Context) model.ProbeResult {
			raw443 := ProbeTCPBlocked(c, "bypass_direct_tcp443", model.CategoryProxyBypass, model.SeverityHigh, target443, timeout)
			if !proxySet && raw443.Status == model.StatusFail {
				raw443.Severity = model.SeverityMedium
				raw443.Detail = raw443.Detail + " (public raw HTTPS egress allowed; pass --allow-public-net if intentional)"
			}
			return raw443
		})
	}

	// 4. Host gateway sensitive services
	hostTargets := []string{}
	if gw != "" {
		hostTargets = append(hostTargets, gw)
	}
	// Resolve host.docker.internal with a short timeout so offline sandboxes never hang on DNS retries
	lookupCtx, lookupCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	if ips, err := (&net.Resolver{}).LookupHost(lookupCtx, "host.docker.internal"); err == nil && len(ips) > 0 {
		hostTargets = append(hostTargets, ips[0])
	}
	lookupCancel()
	seenHost := map[string]bool{}
	hostPorts := []struct {
		port string
		name string
		sev  model.Severity
	}{
		{"22", "ssh", model.SeverityHigh},
		{"80", "http", model.SeverityHigh},
		{"2375", "docker_unencrypted", model.SeverityCritical},
		{"4222", "nats", model.SeverityHigh},
		{"5432", "postgres", model.SeverityHigh},
		{"6379", "redis", model.SeverityHigh},
		{"9000", "minio", model.SeverityHigh},
		{"10250", "kubelet", model.SeverityCritical},
		{"11434", "ollama", model.SeverityMedium},
	}
	for _, h := range hostTargets {
		if seenHost[h] {
			continue
		}
		seenHost[h] = true
		for _, p := range hostPorts {
			id := fmt.Sprintf("host_%s_%s_%s", strings.ReplaceAll(h, ".", "_"), p.name, p.port)
			addr := net.JoinHostPort(h, p.port)
			sev := p.sev
			checks = append(checks, func(c context.Context) model.ProbeResult {
				return ProbeTCPBlocked(c, id, model.CategoryHostNetwork, sev, addr, timeout)
			})
		}
	}

	// 5. Lateral RFC1918 & SMTP port 25
	rfc1918Probes := []struct {
		id   string
		addr string
	}{
		{"rfc1918_10_0_0_1", "10.0.0.1:80"},
		{"rfc1918_172_16_0_1", "172.16.0.1:80"},
		{"rfc1918_172_17_0_1", "172.17.0.1:80"},
		{"rfc1918_192_168_1_1", "192.168.1.1:80"},
		{"cgnat_100_64_0_1", "100.64.0.1:80"},
	}
	for _, p := range rfc1918Probes {
		pCopy := p
		checks = append(checks, func(c context.Context) model.ProbeResult {
			return ProbeTCPBlocked(c, pCopy.id, model.CategoryLateral, model.SeverityHigh, pCopy.addr, timeout)
		})
	}
	checks = append(checks, func(c context.Context) model.ProbeResult {
		return ProbeTCPBlocked(c, "smtp_egress_tcp25", model.CategoryLateral, model.SeverityHigh, "1.1.1.1:25", timeout)
	})

	if peer := strings.TrimSpace(opts.PeerTarget); peer != "" {
		peerCopy := peer
		checks = append(checks, func(c context.Context) model.ProbeResult {
			return ProbeTCPBlocked(c, "cross_tenant_peer", model.CategoryLateral, model.SeverityCritical, peerCopy, timeout)
		})
	}

	if proxyRaw := FirstHTTPProxyURL(); proxyRaw != "" {
		proxyCopy := proxyRaw
		checks = append(checks,
			func(c context.Context) model.ProbeResult {
				return ProbeHTTPProxySSRFTargets(c, "proxy_ssrf_imds_v4", proxyCopy, []string{
					"http://169.254.169.254/latest/meta-data/",
					"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
					"http://169.254.169.254/computeMetadata/v1/",
				}, map[string]string{"Metadata-Flavor": "Google", "Metadata": "true"}, timeout)
			},
			func(c context.Context) model.ProbeResult {
				return ProbeHTTPProxySSRF(c, "proxy_ssrf_loopback_docker", proxyCopy, "http://127.0.0.1:2375/_ping", timeout)
			},
		)
	}

	concurrentResults := make([]model.ProbeResult, len(checks))
	var wg sync.WaitGroup
	wg.Add(len(checks))
	for i, fn := range checks {
		go func(idx int, probeFn func(context.Context) model.ProbeResult) {
			defer wg.Done()
			concurrentResults[idx] = probeFn(ctx)
		}(i, fn)
	}
	wg.Wait()
	results = append(results, concurrentResults...)

	return results, envInfo
}

func nonLoopbackIPs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, a := range addrs {
			ips = append(ips, fmt.Sprintf("%s:%s", iface.Name, a.String()))
		}
	}
	return ips, nil
}
