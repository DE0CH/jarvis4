package main

import (
	"fmt"
	"testing"
	"time"
)

// an instance a workflow run owns is listed as that run's while the run is at work, and is a warning again (naming the
// run) once the run is over; no tag, an unknown kind and a run GitHub can't show are warnings
func TestAWSInstanceOwners(t *testing.T) {
	st, _ := testState(t, t.TempDir())
	r := NewRouter(Config{}, st, nil, Policy{})
	runs := map[string]ghRun{"7": {Name: "aws", Status: "in_progress"}, "8": {Name: "aws", Status: "completed", Conclusion: "success"}}
	calls := map[string]int{}
	old := githubRun
	githubRun = func(id string) (ghRun, error) {
		calls[id]++
		if run, ok := runs[id]; ok {
			return run, nil
		}
		return ghRun{}, fmt.Errorf("GitHub answered 404")
	}
	defer func() { githubRun = old; delete(ownerRuns.done, "7"); delete(ownerRuns.done, "8") }()
	aws := &fakeAWS{inv: awsInventory{Instances: []awsInstance{
		{ID: "i-1", Region: "eu-west-2", Type: "t3.large", State: "running", Name: "jarvis4-bake", Owner: "github-run:7"},
		{ID: "i-2", Region: "eu-west-2", Type: "t3.medium", State: "running", Name: "jarvis4-bake-test", Owner: "github-run:7"},
		{ID: "i-3", Region: "eu-west-2", Type: "t3.large", State: "stopped", Name: "jarvis4-bake", Owner: "github-run:8"},
		{ID: "i-4", Region: "eu-west-2", Type: "t3.large", State: "running", Name: "by hand"},
		{ID: "i-5", Region: "eu-west-2", Type: "t3.large", State: "running", Owner: "github-run:9"},
		{ID: "i-6", Region: "eu-west-2", Type: "t3.large", State: "running", Owner: "someone"},
		{ID: "i-7", Region: "eu-west-2", Type: "t3.large", State: "terminated", Owner: "github-run:10"},
	}}}
	rows := func(now time.Time) (owned, other map[string]string) {
		if _, _, err := r.budgetTick(&fakeFly{}, aws, now, 50, 45); err != nil {
			t.Fatal(err)
		}
		ap := budgetView.budget["aws"].(map[string]any)
		owned, other = map[string]string{}, map[string]string{}
		for _, o := range ap["owned"].([]map[string]string) {
			owned[o["id"]] = o["owner"]
		}
		for _, o := range ap["other"].([]map[string]string) {
			other[o["id"]] = o["owner"]
		}
		return
	}
	t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	owned, other := rows(t0)
	if len(owned) != 2 || owned["i-1"] != "workflow aws, run 7 (in progress)" || owned["i-2"] != owned["i-1"] {
		t.Fatalf("owned %v", owned)
	}
	if len(other) != 4 || other["i-3"] != "left by workflow aws, run 8 (success)" || other["i-4"] != "" ||
		other["i-5"] != "workflow run 9 (not checked: GitHub answered 404)" || other["i-6"] != "owner tag someone (a kind the router doesn't know)" {
		t.Fatalf("other %v", other)
	}
	if calls["7"] != 1 || calls["10"] != 0 {
		t.Fatalf("calls %v", calls)
	}
	// the run ends and leaves its builder: a warning now; the finished run 8 is not asked for again
	runs["7"] = ghRun{Name: "aws", Status: "completed", Conclusion: "failure"}
	owned, other = rows(t0.Add(2 * time.Minute))
	if len(owned) != 0 || other["i-1"] != "left by workflow aws, run 7 (failure)" {
		t.Fatalf("owned %v other %v", owned, other)
	}
	if calls["7"] != 2 || calls["8"] != 1 {
		t.Fatalf("calls %v", calls)
	}
}
