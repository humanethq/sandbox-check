package model

import "time"

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusInfo Status = "INFO"
	StatusSkip Status = "SKIP"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Category string

const (
	CategoryBaseline    Category = "baseline"
	CategoryMetadata    Category = "metadata"
	CategoryProxyBypass Category = "proxy_bypass"
	CategoryHostNetwork Category = "host_network"
	CategoryLateral     Category = "lateral_smtp"
	CategoryRuntime     Category = "runtime_surface"
	CategoryLimits      Category = "resource_limits"
	CategorySecrets     Category = "env_secrets"
)

type ProbeResult struct {
	ID         string            `json:"id"`
	Category   Category          `json:"category"`
	Severity   Severity          `json:"severity"`
	Status     Status            `json:"status"`
	Target     string            `json:"target,omitempty"`
	Expected   string            `json:"expected"`
	Observed   string            `json:"observed"`
	Detail     string            `json:"detail,omitempty"`
	DurationMs int64             `json:"duration_ms"`
	Meta       map[string]string `json:"meta,omitempty"`
}

type EnvironmentInfo struct {
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	Hostname        string   `json:"hostname,omitempty"`
	UID             int      `json:"uid"`
	GID             int      `json:"gid"`
	PID1Name        string   `json:"pid1_name,omitempty"`
	DetectedRuntime string   `json:"detected_runtime"`
	DefaultGateway  string   `json:"default_gateway,omitempty"`
	Resolvers       []string `json:"resolvers,omitempty"`
	ProxyConfigured bool     `json:"proxy_configured"`
}

type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warned   int `json:"warned"`
	Info     int `json:"info"`
	Skipped  int `json:"skipped"`
	Critical int `json:"critical_leaks"`
	High     int `json:"high_leaks"`
}

type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictWarn Verdict = "warn"
	VerdictFail Verdict = "fail"
)

type Report struct {
	Tool        string          `json:"tool"`
	Version     string          `json:"version"`
	Verdict     Verdict         `json:"verdict"`
	GeneratedAt time.Time       `json:"generated_at"`
	Environment EnvironmentInfo `json:"environment"`
	Probes      []ProbeResult   `json:"probes"`
	Summary     Summary         `json:"summary"`
}

func ComputeSummary(probes []ProbeResult) Summary {
	var s Summary
	s.Total = len(probes)
	for _, p := range probes {
		switch p.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed++
			switch p.Severity {
			case SeverityCritical:
				s.Critical++
			case SeverityHigh:
				s.High++
			}
		case StatusWarn:
			s.Warned++
		case StatusInfo:
			s.Info++
		case StatusSkip:
			s.Skipped++
		}
	}
	return s
}

func ComputeVerdict(s Summary) Verdict {
	if s.Failed > 0 {
		return VerdictFail
	}
	if s.Warned > 0 {
		return VerdictWarn
	}
	return VerdictPass
}

func ExitCode(s Summary) int {
	return ExitCodeWithOptions(s, false)
}

func ExitCodeWithOptions(s Summary, strict bool) int {
	if s.Failed > 0 {
		return 2
	}
	if s.Warned > 0 {
		if strict {
			return 2
		}
		return 3
	}
	return 0
}
