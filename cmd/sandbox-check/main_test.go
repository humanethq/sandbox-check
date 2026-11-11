package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/humanethq/sandbox-check/internal/model"
)

func TestRunEmitsValidJSONWithoutSecretLeak(t *testing.T) {
	secret := "sk-live-secret-should-never-appear-in-json-output-9911"
	t.Setenv("OPENAI_API_KEY", secret)

	rep := Run(context.Background(), Config{
		Root:           t.TempDir(),
		Timeout:        50 * time.Millisecond,
		Gateway:        "127.0.0.1",
		ExternalIP:     "127.0.0.1",
		AllowPublicNet: true,
	})
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("raw env secret appeared in serialized JSON report!")
	}
	if !strings.Contains(string(raw), "OPENAI_API_KEY") {
		t.Fatalf("expected OPENAI_API_KEY key name in report, got: %s", string(raw))
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	v, ok := decoded["verdict"].(string)
	if !ok || (v != "pass" && v != "warn" && v != "fail") {
		t.Fatalf("expected top-level JSON verdict in {pass,warn,fail}, got %#v", decoded["verdict"])
	}
}

func TestWarnOnlyReportSetsWarnVerdictAndNonZeroExitCode(t *testing.T) {
	r := model.Report{
		Tool:        "sandbox-check",
		Version:     "v0.2.0-test",
		GeneratedAt: time.Unix(1700000000, 0).UTC(),
		Environment: model.EnvironmentInfo{
			OS:              "linux",
			Arch:            "amd64",
			DetectedRuntime: "docker_container",
			ProxyConfigured: true,
		},
		Probes: []model.ProbeResult{
			{
				ID:       "proxy_ssrf_loopback_docker",
				Category: model.CategoryProxyBypass,
				Severity: model.SeverityCritical,
				Status:   model.StatusWarn,
				Target:   "http://127.0.0.1:2375/_ping",
				Observed: "proxy_upstream_error_http_502",
				Detail:   "proxy attempted upstream dial",
			},
		},
	}
	r.Summary = model.ComputeSummary(r.Probes)
	r.Verdict = model.ComputeVerdict(r.Summary)

	if r.Verdict != model.VerdictWarn {
		t.Fatalf("Verdict = %q, want warn", r.Verdict)
	}
	if code := model.ExitCode(r.Summary); code != 3 {
		t.Fatalf("ExitCode = %d, want 3 for warn-only report", code)
	}

	var buf bytes.Buffer
	renderReport(&buf, r)
	out := buf.String()
	if strings.Contains(out, "NO DETECTED LEAKS") {
		t.Fatalf("warn-only report falsely claimed NO DETECTED LEAKS:\n%s", out)
	}
	if !strings.Contains(out, "WARNINGS DETECTED / INCONCLUSIVE") {
		t.Fatalf("expected WARNINGS DETECTED / INCONCLUSIVE in output, got:\n%s", out)
	}

	var strictBuf bytes.Buffer
	renderReportWithOptions(&strictBuf, r, true)
	if !strings.Contains(strictBuf.String(), "exit code 2") {
		t.Fatalf("expected strict mode to render exit code 2, got:\n%s", strictBuf.String())
	}
}

func TestPrintTextReportSummarizesFailuresAndCounts(t *testing.T) {
	r := model.Report{
		Tool:        "sandbox-check",
		Version:     "v0.1.0-test",
		GeneratedAt: time.Unix(1700000000, 0).UTC(),
		Environment: model.EnvironmentInfo{
			OS:              "linux",
			Arch:            "amd64",
			UID:             0,
			GID:             0,
			PID1Name:        "init",
			DetectedRuntime: "firecracker_microvm",
			DefaultGateway:  "172.16.0.1",
			ProxyConfigured: true,
		},
		Probes: []model.ProbeResult{
			{
				ID:       "baseline_network_posture",
				Category: model.CategoryBaseline,
				Severity: model.SeverityInfo,
				Status:   model.StatusInfo,
				Target:   "eth0",
				Observed: "routed_with_gateway+http_proxy",
				Detail:   "ok",
			},
			{
				ID:       "imds_aws_gcp_azure_v4",
				Category: model.CategoryMetadata,
				Severity: model.SeverityCritical,
				Status:   model.StatusPass,
				Target:   "169.254.169.254:80",
				Observed: "blocked",
				Detail:   "timed out",
			},
			{
				ID:       "bypass_udp53_cloudflare",
				Category: model.CategoryProxyBypass,
				Severity: model.SeverityCritical,
				Status:   model.StatusFail,
				Target:   "1.1.1.1:53/udp",
				Observed: "dns_tunnel_bypass",
				Detail:   "raw UDP:53 succeeded despite HTTP_PROXY",
			},
		},
	}
	r.Summary = model.ComputeSummary(r.Probes)

	oldStdout := ""
	_ = oldStdout
	if r.Summary.Failed != 1 || r.Summary.Critical != 1 {
		t.Fatalf("unexpected summary: %+v", r.Summary)
	}
	if model.ExitCode(r.Summary) != 2 {
		t.Fatalf("ExitCode = %d, want 2", model.ExitCode(r.Summary))
	}

	var buf bytes.Buffer
	renderReport(&buf, r)
	out := buf.String()
	for _, want := range []string{"HUMANET SANDBOX-CHECK", "firecracker_microvm", "bypass_udp53_cloudflare", "dns_tunnel_bypass", "fail=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in rendered report, got:\n%s", want, out)
		}
	}
}

func TestHumanetCLIBranding(t *testing.T) {
	if got := formatVersionString(); !strings.HasPrefix(got, "Humanet sandbox-check ") {
		t.Fatalf("expected version string to start with 'Humanet sandbox-check ', got %q", got)
	}
}
