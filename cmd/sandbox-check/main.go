package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/humanethq/sandbox-check/internal/hostprobe"
	"github.com/humanethq/sandbox-check/internal/model"
	"github.com/humanethq/sandbox-check/internal/netprobe"
)

var version = "v0.1.0-dev"

type Config struct {
	Root           string
	Timeout        time.Duration
	Gateway        string
	Peer           string
	ExternalIP     string
	AllowPublicNet bool
}

func Run(ctx context.Context, cfg Config) model.Report {
	root := cfg.Root
	if root == "" {
		root = "/"
	}
	hostResults, detectedRuntime, pid1Name := hostprobe.RunAll(root)
	netResults, netEnv := netprobe.RunAll(ctx, netprobe.Options{
		Timeout:         cfg.Timeout,
		GatewayOverride: cfg.Gateway,
		PeerTarget:      cfg.Peer,
		ExternalIP:      cfg.ExternalIP,
		AllowPublicNet:  cfg.AllowPublicNet,
	})

	hostname, _ := os.Hostname()
	envInfo := model.EnvironmentInfo{
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		Hostname:        hostname,
		UID:             os.Getuid(),
		GID:             os.Getgid(),
		PID1Name:        pid1Name,
		DetectedRuntime: detectedRuntime,
		DefaultGateway:  netEnv.DefaultGateway,
		Resolvers:       netEnv.Resolvers,
		ProxyConfigured: netEnv.ProxyConfigured,
	}

	allProbes := make([]model.ProbeResult, 0, len(netResults)+len(hostResults))
	allProbes = append(allProbes, netResults...)
	allProbes = append(allProbes, hostResults...)

	summary := model.ComputeSummary(allProbes)
	return model.Report{
		Tool:        "sandbox-check",
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Environment: envInfo,
		Probes:      allProbes,
		Summary:     summary,
	}
}

func formatVersionString() string {
	return fmt.Sprintf("Humanet sandbox-check %s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

func main() {
	jsonOut := flag.Bool("json", false, "output structured JSON report to stdout")
	timeout := flag.Duration("timeout", 900*time.Millisecond, "per-probe network dial timeout")
	gateway := flag.String("gateway", "", "override detected default gateway IP for host service checks")
	peer := flag.String("peer", "", "optional cross-tenant peer ip:port to assert L3 isolation")
	extIP := flag.String("external-ip", "1.1.1.1", "external IP used for direct raw egress bypass probes")
	allowPublicNet := flag.Bool("allow-public-net", false, "do not mark direct outbound TCP:443 as a failure when intentionally allowed")
	showVersion := flag.Bool("version", false, "print Humanet sandbox-check version and exit")
	flag.Usage = func() {
		uOut := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(uOut, "Humanet sandbox-check %s\n", version)
		_, _ = fmt.Fprintln(uOut, "Usage of Humanet sandbox-check: sandbox-check [flags]")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(formatVersionString())
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	report := Run(ctx, Config{
		Root:           "/",
		Timeout:        *timeout,
		Gateway:        *gateway,
		Peer:           *peer,
		ExternalIP:     *extIP,
		AllowPublicNet: *allowPublicNet,
	})
	summary := report.Summary

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "Humanet sandbox-check: encode json: %v\n", err)
			os.Exit(1)
		}
		os.Exit(model.ExitCode(summary))
	}

	renderReport(os.Stdout, report)
	os.Exit(model.ExitCode(summary))
}

func renderReport(w io.Writer, r model.Report) {
	_, _ = fmt.Fprintf(w, "HUMANET SANDBOX-CHECK %s — runtime=%s (%s/%s) uid=%d pid1=%q gw=%q proxy_env=%v\n",
		r.Version,
		r.Environment.DetectedRuntime,
		r.Environment.OS,
		r.Environment.Arch,
		r.Environment.UID,
		r.Environment.PID1Name,
		r.Environment.DefaultGateway,
		r.Environment.ProxyConfigured,
	)
	_, _ = fmt.Fprintln(w, strings.Repeat("=", 86))

	categories := []struct {
		cat   model.Category
		title string
	}{
		{model.CategoryBaseline, "BASELINE"},
		{model.CategoryMetadata, "CLOUD METADATA / IMDS"},
		{model.CategoryProxyBypass, "PROXY BYPASS & DIRECT EGRESS"},
		{model.CategoryHostNetwork, "HOST GATEWAY SERVICES"},
		{model.CategoryLateral, "LATERAL RFC1918 & SMTP"},
		{model.CategoryRuntime, "KERNEL, CAPS & MOUNTS"},
		{model.CategoryLimits, "RESOURCE / CGROUP LIMITS"},
		{model.CategorySecrets, "ENVIRONMENT SECRETS"},
	}

	for _, group := range categories {
		var matched []model.ProbeResult
		for _, p := range r.Probes {
			if p.Category == group.cat {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(w, "\n[%s]\n", group.title)
		for _, p := range matched {
			sev := ""
			if p.Status == model.StatusFail || p.Status == model.StatusWarn {
				sev = fmt.Sprintf(" (%s)", strings.ToUpper(string(p.Severity)))
			}
			_, _ = fmt.Fprintf(w, "  %-4s %-32s %-24s %s%s\n",
				p.Status,
				p.ID,
				truncate(p.Target, 24),
				p.Observed,
				sev,
			)
			if p.Status == model.StatusFail || p.Status == model.StatusWarn || group.cat == model.CategoryBaseline || p.Category == model.CategorySecrets || p.Category == model.CategoryLimits {
				_, _ = fmt.Fprintf(w, "       -> %s (%dms)\n", p.Detail, p.DurationMs)
			}
		}
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, strings.Repeat("-", 86))
	_, _ = fmt.Fprintf(w, "SUMMARY: total=%d pass=%d fail=%d warn=%d info=%d skip=%d (critical=%d high=%d)\n",
		r.Summary.Total,
		r.Summary.Passed,
		r.Summary.Failed,
		r.Summary.Warned,
		r.Summary.Info,
		r.Summary.Skipped,
		r.Summary.Critical,
		r.Summary.High,
	)
	if r.Summary.Failed > 0 {
		_, _ = fmt.Fprintf(w, "RESULT: ISOLATION GAPS DETECTED (exit code %d)\n", model.ExitCode(r.Summary))
	} else {
		_, _ = fmt.Fprintf(w, "RESULT: NO DETECTED LEAKS WITHIN TESTED CHECKS (exit code %d)\n", model.ExitCode(r.Summary))
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
