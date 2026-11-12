package main

// Who owns an AWS instance that is no session's machine (Deyao, 2026-11-12: "there should be an ownership tracked by
// jarvis 4": the budget view warned about the bake's builders on every image pin).
//
// Whatever starts an instance outside the spawner names its owner in the tag jarvis4_owner. One kind today:
// "github-run:<run id>", a run of a workflow of this repo (infra/aws/bake.sh's builder and test instances). The router
// asks GitHub for the run: while it is queued or in progress the instance is owned and listed as such, not as a
// warning; once the run is over, an instance it left behind is a stray again and the warning says which run left it.
// No tag, a kind the router doesn't know, or a run GitHub can't show: a warning, with the reason.
//
// The tag is not a credential: whoever can tag an instance in the account can already start and stop them. It only
// decides which row of the budget view an instance is in.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

// ownerRepo: the repo whose workflow runs may own an instance
const ownerRepo = "DE0CH/jarvis4"

// awsOwner: what the router found out about an instance's jarvis4_owner tag
type awsOwner struct {
	Text string // "workflow aws, run 43185774604 (in progress)"
	Live bool   // the owner is still at work: not a stray
}

type ghRun struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

var ownerRunRe = regexp.MustCompile(`^github-run:([0-9]{1,20})$`)

// a finished run never changes: looked up once
var ownerRuns = struct {
	sync.Mutex
	done map[string]ghRun
}{done: map[string]ghRun{}}

// githubRun: one workflow run of ownerRepo (a public repo: the read token only lifts the rate limit)
var githubRun = func(id string) (ghRun, error) {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/repos/%s/actions/runs/%s", githubAPI, ownerRepo, id), nil)
	if tok := os.Getenv("GITHUB_READ_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "jarvis2-router/1")
	resp, err := githubClient.Do(req)
	if err != nil {
		return ghRun{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return ghRun{}, fmt.Errorf("GitHub answered %d", resp.StatusCode)
	}
	var run ghRun
	if err := json.Unmarshal(b, &run); err != nil || run.Status == "" {
		return ghRun{}, fmt.Errorf("GitHub's answer has no run status")
	}
	return run, nil
}

// resolveAWSOwner: the owner a jarvis4_owner tag names, and whether it is still at work
func resolveAWSOwner(tag string) awsOwner {
	if tag == "" {
		return awsOwner{}
	}
	m := ownerRunRe.FindStringSubmatch(tag)
	if m == nil {
		return awsOwner{Text: "owner tag " + tag + " (a kind the router doesn't know)"}
	}
	id := m[1]
	ownerRuns.Lock()
	run, ok := ownerRuns.done[id]
	ownerRuns.Unlock()
	if !ok {
		var err error
		if run, err = githubRun(id); err != nil {
			return awsOwner{Text: "workflow run " + id + " (not checked: " + err.Error() + ")"}
		}
		if run.Status == "completed" {
			ownerRuns.Lock()
			ownerRuns.done[id] = run
			ownerRuns.Unlock()
		}
	}
	name := strings.TrimSpace("workflow " + run.Name)
	if run.Status == "completed" {
		return awsOwner{Text: fmt.Sprintf("left by %s, run %s (%s)", name, id, run.Conclusion)}
	}
	return awsOwner{Text: fmt.Sprintf("%s, run %s (%s)", name, id, strings.ReplaceAll(run.Status, "_", " ")), Live: true}
}

// awsOwners: the owner of every live instance carrying the tag, by instance id (one lookup per run)
func awsOwners(ins []awsInstance) map[string]awsOwner {
	out, byTag := map[string]awsOwner{}, map[string]awsOwner{}
	for _, in := range ins {
		if in.Owner == "" || in.State == "terminated" || in.State == "shutting-down" {
			continue
		}
		o, ok := byTag[in.Owner]
		if !ok {
			o = resolveAWSOwner(in.Owner)
			byTag[in.Owner] = o
		}
		out[in.ID] = o
	}
	return out
}
