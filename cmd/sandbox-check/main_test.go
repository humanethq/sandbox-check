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
