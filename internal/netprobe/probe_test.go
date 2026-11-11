package netprobe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/humanethq/sandbox-check/internal/model"
)

func TestParseProcNetRouteGateway(t *testing.T) {
	// Little-endian hex representation of 172.16.0.1 is 010010AC on little-endian x86/arm64 Linux.
	sample := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t010010AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t000010AC\t00000000\t0001\t0\t0\t0\tFCFFFFFF\t0\t0\t0\n"

	gw, iface := ParseProcNetRoute(strings.NewReader(sample))
	if gw != "172.16.0.1" {
		t.Fatalf("gateway = %q, want 172.16.0.1", gw)
	}
	if iface != "eth0" {
		t.Fatalf("iface = %q, want eth0", iface)
	}
}

func TestBuildAndValidateDNSQueryPacket(t *testing.T) {
	pkt, txID, err := BuildDNSQuery("sc-canary.example.invalid")
	if err != nil {
		t.Fatalf("BuildDNSQuery: %v", err)
	}
	if len(pkt) < 17 {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	gotID := binary.BigEndian.Uint16(pkt[0:2])
	if gotID != txID {
		t.Fatalf("txID = %d, want %d", gotID, txID)
	}
}

func TestMetadataProbeDetectsReachableServerAsFailAndNeverLeaksBody(t *testing.T) {
	secretMarker := "ASIA_FAKE_TOKEN_NEVER_PRINT_ME_999"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"AccessKeyId":"%s"}`, secretMarker)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	res := ProbeMetadataHTTP(context.Background(), MetadataTarget{
		ID:       "imds_test",
		Label:    "Test IMDS",
		Address:  addr,
		Path:     "/latest/meta-data/",
		Severity: model.SeverityCritical,
	}, 500*time.Millisecond)

	if res.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL (observed=%q detail=%q)", res.Status, res.Observed, res.Detail)
	}
	if strings.Contains(res.Observed, secretMarker) || strings.Contains(res.Detail, secretMarker) {
		t.Fatalf("metadata response body leaked into probe output!")
	}
}

func TestMetadataProbeBlockedPortPasses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	res := ProbeMetadataHTTP(context.Background(), MetadataTarget{
		ID:       "imds_closed",
		Label:    "Closed IMDS",
		Address:  closedAddr,
		Path:     "/latest/meta-data/",
		Severity: model.SeverityCritical,
	}, 300*time.Millisecond)

	if res.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS (observed=%q detail=%q)", res.Status, res.Observed, res.Detail)
	}
}

func TestDirectUDP53BypassProbeDetectsOpenDNS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	go func() {
		buf := make([]byte, 512)
		n, addr, readErr := pc.ReadFrom(buf)
		if readErr != nil || n < 12 {
			return
		}
		// Craft minimal valid DNS response with QR=1 and txID copied
		resp := make([]byte, n)
		copy(resp, buf[:n])
		resp[2] = 0x81
		resp[3] = 0x83 // NXDOMAIN
		_, _ = pc.WriteTo(resp, addr)
	}()

	res := ProbeDirectUDPDNS(context.Background(), "udp_dns_test", pc.LocalAddr().String(), 500*time.Millisecond, true)
	if res.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL when direct UDP DNS responds", res.Status)
	}
}

func TestDirectTCPProbeBlocksWhenClosedAndFailsWhenOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	openRes := ProbeTCPBlocked(context.Background(), "open_test", model.CategoryHostNetwork, model.SeverityHigh, ln.Addr().String(), 300*time.Millisecond)
	if openRes.Status != model.StatusFail {
		t.Fatalf("open port status = %s, want FAIL", openRes.Status)
	}
	_ = ln.Close()

	closedRes := ProbeTCPBlocked(context.Background(), "closed_test", model.CategoryHostNetwork, model.SeverityHigh, ln.Addr().String(), 300*time.Millisecond)
	if closedRes.Status != model.StatusPass {
		t.Fatalf("closed port status = %s, want PASS", closedRes.Status)
	}
}

func TestProxySSRFProbeBlocksAndDetectsForwarding(t *testing.T) {
	// Proxy 1: fails closed with 403 Forbidden
	denyProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer denyProxy.Close()

	passRes := ProbeHTTPProxySSRF(context.Background(), "proxy_ssrf_deny", denyProxy.URL, "http://169.254.169.254/latest/meta-data/", 500*time.Millisecond)
	if passRes.Status != model.StatusPass {
		t.Fatalf("403 proxy status = %s, want PASS (detail=%q)", passRes.Status, passRes.Detail)
	}

	// Proxy 2: insecure proxy forwards and returns 200 OK (body must never leak)
	leakMarker := "SECRET_VIA_PROXY_SSRF_888"
	openProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(leakMarker))
	}))
	defer openProxy.Close()

	failRes := ProbeHTTPProxySSRF(context.Background(), "proxy_ssrf_open", openProxy.URL, "http://169.254.169.254/latest/meta-data/", 500*time.Millisecond)
	if failRes.Status != model.StatusFail {
		t.Fatalf("open proxy status = %s, want FAIL (detail=%q)", failRes.Status, failRes.Detail)
	}
	if strings.Contains(failRes.Observed, leakMarker) || strings.Contains(failRes.Detail, leakMarker) {
		t.Fatal("proxy SSRF response body leaked into output")
	}

	// Proxy 3: naive proxy returns 502 Bad Gateway after attempting upstream dial -> WARN, not PASS
	upstreamErrProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer upstreamErrProxy.Close()

	warnRes := ProbeHTTPProxySSRF(context.Background(), "proxy_ssrf_502", upstreamErrProxy.URL, "http://127.0.0.1:2375/_ping", 500*time.Millisecond)
	if warnRes.Status != model.StatusWarn {
		t.Fatalf("502 proxy status = %s, want WARN (detail=%q)", warnRes.Status, warnRes.Detail)
	}
}

func TestMetadataProbeFallsBackToAzureAltPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata/instance" && r.Header.Get("Metadata") == "true" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"compute":{"name":"vm"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res := ProbeMetadataHTTP(context.Background(), MetadataTarget{
		ID:       "imds_azure_alt",
		Label:    "Azure IMDS",
		Address:  strings.TrimPrefix(srv.URL, "http://"),
		Path:     "/latest/meta-data/",
		AltPaths: []string{"/metadata/instance?api-version=2021-02-01"},
		Headers:  map[string]string{"Metadata": "true"},
		Severity: model.SeverityCritical,
	}, 500*time.Millisecond)

	if res.Status != model.StatusFail || res.Observed != "metadata_exposed_http_200" {
		t.Fatalf("got status=%s observed=%q, want FAIL/metadata_exposed_http_200", res.Status, res.Observed)
	}
}
