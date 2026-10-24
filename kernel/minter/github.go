package minter

// GitHub's deploy-key API: one add, or one delete by the id GitHub gave at the add. The token comes in each call,
// sealed to the minter by secrets, and is never kept. The host is fixed here, in git, like the Fly app: the token can
// only ever go to api.github.com.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type DeployKey struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
	Key   string `json:"key"`
}

type GitHub interface {
	AddDeployKey(token, repo, title, publicKey string) (DeployKey, error)
	DeleteDeployKey(token, repo string, id int64) error
}

// GitHubAPIBase: the one GitHub host the minter talks to
const GitHubAPIBase = "https://api.github.com"

type GitHubAPI struct{ http *http.Client }

// GitHubError: GitHub refused; Status is its HTTP status (403/404 = the token can't manage this repo's keys)
type GitHubError struct {
	Status int
	Msg    string
}

func (e *GitHubError) Error() string { return e.Msg }

func (g *GitHubAPI) call(token, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, GitHubAPIBase+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "jarvis4-minter/1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.http.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub unreachable: %v", strings.ReplaceAll(err.Error(), token, "***"))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(b, &e)
		return &GitHubError{resp.StatusCode, fmt.Sprintf("GitHub %s %s: HTTP %d %s", method, path, resp.StatusCode, e.Message)}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (g *GitHubAPI) AddDeployKey(token, repo, title, publicKey string) (DeployKey, error) {
	var k DeployKey
	err := g.call(token, "POST", "/repos/"+repo+"/keys", map[string]any{"title": title, "key": publicKey, "read_only": false}, &k)
	return k, err
}

func (g *GitHubAPI) DeleteDeployKey(token, repo string, id int64) error {
	err := g.call(token, "DELETE", fmt.Sprintf("/repos/%s/keys/%d", repo, id), nil, nil)
	if ge, ok := err.(*GitHubError); ok && ge.Status == 404 {
		return nil // already gone
	}
	return err
}

func NewGitHubAPI() *GitHubAPI { return &GitHubAPI{http: &http.Client{Timeout: 30 * time.Second}} }
