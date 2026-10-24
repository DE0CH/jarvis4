package main

// The Claude app's own title of this session (Jarvis 1's codeSessionTitles / appTitleOf in jarvis/server.js):
// the conversation's Remote Control entry on claude.ai, which follows Deyao's renames in the app. Jarvis 1 read
// it on the box with the stored Claude login; here the machine reads it with its own (it holds the session's
// Claude login anyway) and sends only the title with its status report (status.go), so no token leaves it.
// The entry is the registry's bridgeSessionId (session_<key>); the API is GET /v1/code/sessions/cse_<key>,
// else the list (Jarvis 1's call).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	codeSessionsURL = "https://api.anthropic.com/v1/code/sessions"
	claudeHome      = "/home/claude"
	appTitleTTL     = 60 * time.Second
)

// hostBridge: the Remote Control entry of claude's host process (the registry entry with a bridgeSessionId,
// oldest first — router/registry.go picks the same one), without its "session_"/"cse_" prefix
func hostBridge() string {
	files, _ := filepath.Glob(filepath.Join(claudeHome, ".claude/sessions/*.json"))
	type entry struct {
		Bridge    string `json:"bridgeSessionId"`
		StartedAt int64  `json:"startedAt"`
	}
	var es []entry
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var e entry
		if json.Unmarshal(b, &e) == nil && e.Bridge != "" {
			es = append(es, e)
		}
	}
	if len(es) == 0 {
		return ""
	}
	sort.Slice(es, func(i, j int) bool { return es[i].StartedAt < es[j].StartedAt })
	return strings.TrimPrefix(strings.TrimPrefix(es[0].Bridge, "cse_"), "session_")
}

// claudeAccessToken: the session's Claude OAuth access token (never logged or sent anywhere but Anthropic)
func claudeAccessToken() string {
	b, err := os.ReadFile(filepath.Join(claudeHome, ".claude/.credentials.json"))
	if err != nil {
		return ""
	}
	var c struct {
		ClaudeAiOauth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	json.Unmarshal(b, &c)
	return c.ClaudeAiOauth.AccessToken
}

var appHTTP = &http.Client{Timeout: 15 * time.Second}

func codeSessionsGet(url, tok string, out any) (int, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("anthropic-beta", "ccr-byoc-2025-07-29,oauth-2025-04-20")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jarvis-machine/1")
	resp, err := appHTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return resp.StatusCode, fmt.Errorf("code sessions: HTTP %d", resp.StatusCode)
	}
	return 200, json.Unmarshal(b, out)
}

// fetchAppTitle: the entry's title on claude.ai ("" when it has none yet)
func fetchAppTitle(key, tok string) (string, error) {
	var one struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	st, err := codeSessionsGet(codeSessionsURL+"/cse_"+key, tok, &one)
	if err == nil {
		return one.Title, nil
	}
	if st != 404 && st != 405 {
		return "", err
	}
	var list struct {
		Data []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"data"`
	}
	if _, err := codeSessionsGet(codeSessionsURL+"?limit=100", tok, &list); err != nil {
		return "", err
	}
	for _, s := range list.Data {
		if strings.TrimPrefix(strings.TrimPrefix(s.ID, "cse_"), "session_") == key {
			return s.Title, nil
		}
	}
	return "", errors.New("the session's Remote Control entry isn't listed")
}

// appTitler: the title, read at most once a minute; a failed read keeps the last title of the same entry
type appTitler struct {
	bridge, title string
	at            time.Time
}

func (a *appTitler) current() string {
	key := hostBridge()
	if key == "" {
		return ""
	}
	if key == a.bridge && time.Since(a.at) < appTitleTTL {
		return a.title
	}
	if key != a.bridge {
		a.bridge, a.title = key, ""
	}
	a.at = time.Now()
	tok := claudeAccessToken()
	if tok == "" {
		return a.title
	}
	if t, err := fetchAppTitle(key, tok); err == nil && strings.TrimSpace(t) != "" {
		a.title = strings.TrimSpace(t)
	}
	return a.title
}
