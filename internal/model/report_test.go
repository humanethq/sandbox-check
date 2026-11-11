package model

import "testing"

func TestComputeVerdictAndExitCode(t *testing.T) {
	passSummary := ComputeSummary([]ProbeResult{
		{ID: "base", Status: StatusInfo},
		{ID: "ok", Status: StatusPass},
	})
	if got := ComputeVerdict(passSummary); got != VerdictPass {
		t.Fatalf("ComputeVerdict(pass) = %q, want %q", got, VerdictPass)
	}
	if code := ExitCode(passSummary); code != 0 {
		t.Fatalf("ExitCode(pass) = %d, want 0", code)
	}

	warnSummary := ComputeSummary([]ProbeResult{
		{ID: "ok", Status: StatusPass},
		{ID: "proxy_warn", Status: StatusWarn, Severity: SeverityCritical},
	})
	if got := ComputeVerdict(warnSummary); got != VerdictWarn {
		t.Fatalf("ComputeVerdict(warn) = %q, want %q", got, VerdictWarn)
	}
	if code := ExitCode(warnSummary); code != 3 {
		t.Fatalf("ExitCode(warn) = %d, want 3 (inconclusive/warnings detected)", code)
	}
	if code := ExitCodeWithOptions(warnSummary, true); code != 2 {
		t.Fatalf("ExitCodeWithOptions(warn, strict=true) = %d, want 2", code)
	}

	failSummary := ComputeSummary([]ProbeResult{
		{ID: "warn", Status: StatusWarn},
		{ID: "leak", Status: StatusFail, Severity: SeverityCritical},
	})
	if got := ComputeVerdict(failSummary); got != VerdictFail {
		t.Fatalf("ComputeVerdict(fail) = %q, want %q", got, VerdictFail)
	}
	if code := ExitCode(failSummary); code != 2 {
		t.Fatalf("ExitCode(fail) = %d, want 2", code)
	}
}
