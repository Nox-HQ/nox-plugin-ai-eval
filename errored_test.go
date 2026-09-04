package main

import (
	"strings"
	"testing"
)

// Zero findings has two completely different meanings: the endpoint resisted
// every attack, or no attack ever reached it. Both used to be reported at INFO
// with an empty findings list, so anything gating on severity, findings or exit
// code read "the endpoint was unreachable" as "the endpoint held" — a clean
// bill of health for a model that was never tested.
func TestCountVerdictsKeepsErroredApartFromResisted(t *testing.T) {
	resisted := []Verdict{{}, {}, {}}
	errored := []Verdict{{Error: "connection refused"}, {Error: "connection refused"}, {Error: "connection refused"}}

	if c := CountVerdicts(resisted); c.Resisted != 3 || c.Errored != 0 {
		t.Errorf("resisted run counted as %+v", c)
	}
	if c := CountVerdicts(errored); c.Errored != 3 || c.Resisted != 0 {
		t.Errorf("errored run counted as %+v — an unreachable endpoint has resisted nothing", c)
	}

	// The two must not render identically either.
	if SummariseVerdicts(resisted) == SummariseVerdicts(errored) {
		t.Error("a fully-resisted run and a fully-errored run summarise the same")
	}
}

// A mixed run is a floor, not a verdict: the entries that ran are meaningful,
// but the corpus was not fully exercised.
func TestCountVerdictsTalliesMixedRuns(t *testing.T) {
	c := CountVerdicts([]Verdict{
		{Success: true},
		{},
		{Error: "timeout"},
		{Success: true},
	})
	if c.Succeeded != 2 || c.Resisted != 1 || c.Errored != 1 || c.Total() != 4 {
		t.Errorf("counts = %+v, want 2 succeeded / 1 resisted / 1 errored / 4 total", c)
	}
	if !strings.Contains(SummariseVerdicts([]Verdict{{Error: "x"}}), "1 errored") {
		t.Error("summary does not report errored entries")
	}
}
