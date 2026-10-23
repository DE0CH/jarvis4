package main

// Discord (Jarvis 1 parity, its lib/discord.js): Jarvis 4 shares Jarvis 1's bot, lobster.
//   DM       → r.DM(text) posts to Deyao's DM with the bot (dmHook)
//   create   → every session gets a text channel under its own category (DISCORD_SESSIONS_CATEGORY,
//              default "Jarvis 4"; Jarvis 1's "Sessions" category and its channels are never touched),
//              made when the router builds the machine's env (envHooks), so a start or resume carries it
//              as LOBSTER_CHANNEL and the session's scripts/lobster-send.sh posts there. A resume reuses the
//              channel; one deleted by hand is made again.
//              name = a slug of the session's title, topic = "Jarvis 4 session <id>" (Jarvis 1 adds the
//              Remote Control link; Jarvis 4 doesn't know it)
//   title    → a tick renames the channel when the session's title changes (Discord allows 2 name/topic
//              edits per channel per 10 minutes; a third waits for the window)
//   destroy  → the channel's messages and attachments go into the session's archive (archivetar.go),
//              discord/{messages.json,attachments/<message id>-<file>}, then the channel is deleted. A
//              failed export (or no archive) keeps the channel (Deyao gets a DM) and the destroy goes on.
// Settings (router env): LOBSTER_TOKEN (without it nothing here runs and r.DM only logs), DISCORD_GUILD_ID,
// DISCORD_DM_CHANNEL, DISCORD_SESSIONS_CATEGORY, DISCORD_SESSION_CHANNELS=off (DMs only).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	discordAPI         = "https://discord.com/api/v10"
	discordUA          = "jarvis4-router (https://github.com/DE0CH/jarvis4, 1.0)"
	discordEditWindow  = 10 * time.Minute // Discord: 2 name/topic edits per 10 min per channel
	discordEditsPerWin = 2
	discordMsgLimit    = 2000
	discordTickEvery   = time.Minute
)

type discordClient struct {
	api, token, guild, dm, category string
	channels                        bool // per-session channels on (DISCORD_SESSION_CHANNELS != off)
	http                            *http.Client
	maxWait                         time.Duration // a 429 asking for longer than this fails (the caller retries later)
	sleep                           func(time.Duration)
	now                             func() time.Time

	mu         sync.Mutex
	categoryID string
	categoryAt time.Time
	names      map[string]*discordChanInfo // channel id → what it was last seen as
}

type discordChanInfo struct {
	name, topic string
	edits       []time.Time
}

type discordChannel struct {
	ID       string `json:"id"`
	Type     int    `json:"type"`
	Name     string `json:"name"`
	Topic    string `json:"topic"`
	GuildID  string `json:"guild_id"`
	ParentID string `json:"parent_id"`
}

// errDiscordRateLimited: a 429 whose wait is longer than the client holds a call for
type errDiscordRateLimited struct {
	method, path string
	wait         time.Duration
}

func (e *errDiscordRateLimited) Error() string {
	return fmt.Sprintf("discord rate limit on %s %s: retry in %s", e.method, e.path, e.wait.Round(time.Second))
}

func newDiscordFromEnv() *discordClient {
	token := os.Getenv("LOBSTER_TOKEN")
	if token == "" {
		return nil
	}
	return &discordClient{
		api: discordAPI, token: token,
		guild:    env("DISCORD_GUILD_ID", "1482150592414486748"),
		dm:       env("DISCORD_DM_CHANNEL", "1531422588247474266"),
		category: env("DISCORD_SESSIONS_CATEGORY", "Jarvis 4"),
		channels: os.Getenv("DISCORD_SESSION_CHANNELS") != "off",
		http:     &http.Client{Timeout: 30 * time.Second},
		maxWait:  30 * time.Second, sleep: time.Sleep, now: time.Now,
		names: map[string]*discordChanInfo{},
	}
}

// req: one REST call. 429 → wait retry_after and try again, up to 3 times (a wait over maxWait fails at once
// with errDiscordRateLimited). 404 → found=false, no error. The body is the raw JSON ({} for 204).
func (d *discordClient) req(method, path string, body any) (out []byte, found bool, err error) {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	for i := 0; ; i++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		hr, _ := http.NewRequest(method, d.api+path, rd)
		hr.Header.Set("Authorization", "Bot "+d.token)
		hr.Header.Set("User-Agent", discordUA)
		if payload != nil {
			hr.Header.Set("Content-Type", "application/json")
		}
		resp, err := d.http.Do(hr)
		if err != nil {
			return nil, false, err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 429 && i < 3:
			wait := retryAfter(b, resp.Header.Get("Retry-After"))
			if wait > d.maxWait {
				return nil, false, &errDiscordRateLimited{method, path, wait}
			}
			d.sleep(wait)
			continue
		case resp.StatusCode == 404:
			return nil, false, nil
		case resp.StatusCode == 204:
			return []byte("{}"), true, nil
		case resp.StatusCode < 200 || resp.StatusCode > 299:
			t := strings.TrimSpace(string(b))
			if len(t) > 200 {
				t = t[:200]
			}
			return nil, false, fmt.Errorf("discord %d on %s %s: %s", resp.StatusCode, method, path, t)
		}
		if len(b) == 0 {
			b = []byte("{}")
		}
		return b, true, nil
	}
}

// retryAfter: Discord's JSON retry_after (seconds, fractional), else the Retry-After header, else 1 s
func retryAfter(body []byte, header string) time.Duration {
	var r struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if json.Unmarshal(body, &r) == nil && r.RetryAfter > 0 {
		return time.Duration(r.RetryAfter * float64(time.Second))
	}
	if f, err := strconv.ParseFloat(header, 64); err == nil && f > 0 {
		return time.Duration(f * float64(time.Second))
	}
	return time.Second
}

// ---- messages ------------------------------------------------------------------------------------------

// splitMessage: Discord's 2000-character limit, split on line breaks where possible
func splitMessage(text string) []string {
	var out []string
	r := []rune(text)
	for len(r) > discordMsgLimit {
		cut := discordMsgLimit
		for i := discordMsgLimit; i > discordMsgLimit/2; i-- {
			if r[i-1] == '\n' {
				cut = i
				break
			}
		}
		out = append(out, string(r[:cut]))
		r = r[cut:]
	}
	if len(r) > 0 {
		out = append(out, string(r))
	}
	return out
}

func (d *discordClient) send(channel, text string) error {
	for _, part := range splitMessage(text) {
		if _, found, err := d.req("POST", "/channels/"+channel+"/messages", map[string]string{"content": part}); err != nil {
			return err
		} else if !found {
			return fmt.Errorf("discord channel %s not found", channel)
		}
	}
	return nil
}

// ---- names -----------------------------------------------------------------------------------------------

// channelName: Discord channel names are 1–100 chars, lower case; the slug keeps ascii letters/digits and CJK
// ideographs, everything else becomes one dash (as Jarvis 1's)
func channelName(title, sid string) string {
	var b strings.Builder
	dash := false
	for _, c := range strings.ToLower(title) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 0x4e00 && c <= 0x9fff) {
			b.WriteRune(c)
			dash = false
		} else if unicode.Is(unicode.Mn, c) {
			continue // a combining mark: dropped, as Jarvis 1's NFKD strip does
		} else if !dash {
			b.WriteRune('-')
			dash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if r := []rune(s); len(r) > 90 {
		s = strings.TrimRight(string(r[:90]), "-")
	}
	if s == "" {
		if len(sid) > 8 {
			sid = sid[len(sid)-8:]
		}
		if sid == "" {
			sid = "new"
		}
		s = "session-" + sid
	}
	return s
}

func channelTopic(sid string) string { return "Jarvis 4 session " + sid }

// sessionTitle: the name a session's card, channel and archive folder carry — Jarvis 1's pickTitle: the Claude
// app's own title (AppTitle, which follows Deyao's rename in the app) beats a name he pinned in the CLI
// (UserTitle), which beats the label given at New session, which beats the AI title; else the id.
func sessionTitle(s Session) string {
	for _, t := range []string{s.AppTitle, s.UserTitle, s.Label, s.Title} {
		if t = strings.TrimSpace(t); t != "" {
			return t
		}
	}
	return s.ID
}

// ---- the category and one channel's life ----------------------------------------------------------------

func (d *discordClient) ensureCategory() (string, error) {
	d.mu.Lock()
	if d.categoryID != "" && d.now().Sub(d.categoryAt) < time.Hour {
		id := d.categoryID
		d.mu.Unlock()
		return id, nil
	}
	d.mu.Unlock()
	b, _, err := d.req("GET", "/guilds/"+d.guild+"/channels", nil)
	if err != nil {
		return "", err
	}
	var all []discordChannel
	json.Unmarshal(b, &all)
	id := ""
	for _, c := range all {
		if c.Type == 4 && strings.EqualFold(c.Name, d.category) {
			id = c.ID
			break
		}
	}
	if id == "" {
		b, _, err := d.req("POST", "/guilds/"+d.guild+"/channels", map[string]any{"name": d.category, "type": 4})
		if err != nil {
			return "", err
		}
		var c discordChannel
		if json.Unmarshal(b, &c) != nil || c.ID == "" {
			return "", errors.New("discord: the category wasn't made")
		}
		id = c.ID
	}
	d.mu.Lock()
	d.categoryID, d.categoryAt = id, d.now()
	d.mu.Unlock()
	return id, nil
}

// getChannel: the channel if it still exists in OUR guild (one deleted by hand, or another guild's id, is gone)
func (d *discordClient) getChannel(id string) (*discordChannel, error) {
	if id == "" {
		return nil, nil
	}
	b, found, err := d.req("GET", "/channels/"+id, nil)
	if err != nil || !found {
		return nil, err
	}
	var c discordChannel
	if json.Unmarshal(b, &c) != nil || c.GuildID != d.guild {
		return nil, nil
	}
	return &c, nil
}

func (d *discordClient) remember(c *discordChannel) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.names[c.ID] == nil {
		d.names[c.ID] = &discordChanInfo{name: c.Name, topic: c.Topic}
	}
}

// ensureChannel: the channel a session carries when it still exists, else a new one under the category
func (d *discordClient) ensureChannel(id, sid, title string) (ch *discordChannel, created bool, err error) {
	cur, err := d.getChannel(id)
	if err != nil {
		return nil, false, err
	}
	if cur != nil {
		d.remember(cur)
		return cur, false, nil
	}
	parent, err := d.ensureCategory()
	if err != nil {
		return nil, false, err
	}
	b, _, err := d.req("POST", "/guilds/"+d.guild+"/channels", map[string]any{"name": channelName(title, sid), "type": 0, "parent_id": parent, "topic": channelTopic(sid)})
	if err != nil {
		return nil, false, err
	}
	var c discordChannel
	if json.Unmarshal(b, &c) != nil || c.ID == "" {
		return nil, false, errors.New("discord: the channel wasn't made")
	}
	d.remember(&c)
	return &c, true, nil
}

// syncName: rename to match the title (and fix the topic) — one PATCH, only when something differs and fewer
// than 2 edits were made in the last 10 minutes. Returns true when it edited.
func (d *discordClient) syncName(id, title, sid string) (bool, error) {
	d.mu.Lock()
	cur := d.names[id]
	d.mu.Unlock()
	if cur == nil {
		c, err := d.getChannel(id)
		if err != nil || c == nil {
			return false, err
		}
		d.remember(c)
		d.mu.Lock()
		cur = d.names[id]
		d.mu.Unlock()
	}
	d.mu.Lock()
	patch := map[string]string{}
	if want := channelName(title, sid); cur.name != want {
		patch["name"] = want
	}
	if want := channelTopic(sid); cur.topic != want {
		patch["topic"] = want
	}
	now := d.now()
	kept := cur.edits[:0]
	for _, t := range cur.edits {
		if now.Sub(t) < discordEditWindow {
			kept = append(kept, t)
		}
	}
	cur.edits = kept
	if len(patch) == 0 || len(cur.edits) >= discordEditsPerWin {
		d.mu.Unlock()
		return false, nil
	}
	cur.edits = append(cur.edits, now) // counted even if it fails: no hammering a rate-limited edit
	d.mu.Unlock()
	b, found, err := d.req("PATCH", "/channels/"+id, patch)
	if err != nil || !found {
		return false, err
	}
	var c discordChannel
	if json.Unmarshal(b, &c) == nil && c.ID != "" {
		d.mu.Lock()
		cur.name, cur.topic = c.Name, c.Topic
		d.mu.Unlock()
	}
	return true, nil
}

func (d *discordClient) deleteChannel(id string) (bool, error) {
	_, found, err := d.req("DELETE", "/channels/"+id, nil)
	d.mu.Lock()
	delete(d.names, id)
	d.mu.Unlock()
	return found, err
}

// ---- export: every message + every attachment, oldest first ------------------------------------------

type exportSink interface {
	putBytes(rel string, b []byte, contentType string) error
}

type exportResult struct {
	Messages, Attachments, AttachmentsFailed int
	Name                                     string
}

// exportChannel: messages paged newest→oldest (limit 100, before=…) and written oldest first to
// messages.json; attachment bytes downloaded now (CDN links expire) to attachments/<message id>-<file>. A
// failed attachment is noted on its entry (exportError) and doesn't fail the export. nil when the channel is
// already gone.
func (d *discordClient) exportChannel(id string, sink exportSink, fetch func(url string) ([]byte, error)) (*exportResult, error) {
	ch, err := d.getChannel(id)
	if err != nil || ch == nil {
		return nil, err
	}
	var all []map[string]any
	before := ""
	for {
		p := "/channels/" + id + "/messages?limit=100"
		if before != "" {
			p += "&before=" + before
		}
		b, _, err := d.req("GET", p, nil)
		if err != nil {
			return nil, err
		}
		var page []map[string]any
		if err := json.Unmarshal(b, &page); err != nil {
			return nil, fmt.Errorf("discord messages: %v", err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		before, _ = page[len(page)-1]["id"].(string)
		if len(page) < 100 || before == "" {
			break
		}
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	res := &exportResult{Messages: len(all), Name: ch.Name}
	for _, m := range all {
		mid, _ := m["id"].(string)
		atts, _ := m["attachments"].([]any)
		for _, x := range atts {
			a, ok := x.(map[string]any)
			if !ok {
				continue
			}
			name, _ := a["filename"].(string)
			if name == "" {
				name, _ = a["id"].(string)
			}
			rel := "attachments/" + mid + "-" + safeFileName(name)
			u, _ := a["url"].(string)
			ct, _ := a["content_type"].(string)
			if ct == "" {
				ct = "application/octet-stream"
			}
			b, err := fetch(u)
			if err == nil {
				err = sink.putBytes(rel, b, ct)
			}
			if err != nil {
				a["exportError"] = err.Error()
				res.AttachmentsFailed++
				continue
			}
			a["exported"] = rel
			res.Attachments++
		}
	}
	if all == nil {
		all = []map[string]any{}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"channel":    map[string]string{"id": ch.ID, "name": ch.Name, "topic": ch.Topic, "guild": d.guild},
		"exportedAt": d.now().UTC().Format(time.RFC3339), "messages": all,
	}, "", " ")
	if err := sink.putBytes("messages.json", out, "application/json"); err != nil {
		return nil, err
	}
	return res, nil
}

func safeFileName(s string) string {
	r := []rune(strings.Map(func(c rune) rune {
		if strings.ContainsRune(`/\:*?"<>|`, c) || c < 0x20 {
			return '_'
		}
		return c
	}, s))
	if len(r) > 120 {
		r = r[:120]
	}
	return string(r)
}

func httpFetch(u string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ---- the router side ------------------------------------------------------------------------------------

var (
	disc      *discordClient
	discFetch = httpFetch
)

func (r *Router) startDiscord() {
	disc = newDiscordFromEnv()
	if disc == nil {
		log.Printf("[discord] no LOBSTER_TOKEN: no DMs, no session channels")
		return
	}
	dmHook = func(text string) {
		go func() {
			if err := disc.send(disc.dm, text); err != nil {
				log.Printf("[discord] DM not sent: %v", err)
			}
		}()
	}
	if !disc.channels {
		log.Printf("[discord] DISCORD_SESSION_CHANNELS=off: DMs only")
		return
	}
	envHooks = append(envHooks, discordEnv)
	onDestroy = append(onDestroy, discordDestroy)
	go func() {
		for {
			time.Sleep(discordTickEvery)
			awaitLead() // leaderlease.go
			r.discordTick()
		}
	}()
}

// discordEnv: at every start/resume the session's channel (the one it carries, or a new one) goes into the
// machine's env as LOBSTER_CHANNEL. Best effort: Discord being down mustn't stop a session (the session's
// lobster-send.sh then DMs).
func discordEnv(r *Router, s *Session, env map[string]string) {
	if disc == nil || isTaskHarness(s.Harness) { // task lines report to their run records and the DM
		return
	}
	ch, created, err := disc.ensureChannel(s.DiscordChannel, s.ID, sessionTitle(*s))
	if err != nil {
		log.Printf("[discord] %s: no channel: %v", s.ID, err)
		return
	}
	if ch.ID != s.DiscordChannel {
		s.DiscordChannel = ch.ID
		r.st.Do(func(d *persisted) {
			if x := d.Sessions[s.ID]; x != nil {
				x.DiscordChannel = ch.ID
			}
		})
	}
	if created {
		log.Printf("[discord] %s: channel #%s made", s.ID, ch.Name)
	}
	env["LOBSTER_CHANNEL"] = ch.ID
}

// discordTick: channels follow their sessions' titles; a running session without one (Discord was down when
// it started) gets one, so its destroy has something to export (its env can't change: it keeps DMing)
func (r *Router) discordTick() {
	var list []Session
	r.st.Do(func(d *persisted) {
		for _, s := range d.Sessions {
			list = append(list, *s)
		}
	})
	for _, s := range list {
		if s.State == "destroying" || s.State == "destroyed" || s.State == "approval" || isTaskHarness(s.Harness) {
			continue
		}
		if s.DiscordChannel == "" {
			if s.MachineID == "" || s.State != "started" {
				continue
			}
			ch, _, err := disc.ensureChannel("", s.ID, sessionTitle(s))
			if err != nil {
				log.Printf("[discord] %s: no channel: %v", s.ID, err)
				continue
			}
			r.st.Do(func(d *persisted) {
				if x := d.Sessions[s.ID]; x != nil {
					x.DiscordChannel = ch.ID
				}
			})
			log.Printf("[discord] %s: channel #%s made for a session that had none", s.ID, ch.Name)
			continue
		}
		if ok, err := disc.syncName(s.DiscordChannel, sessionTitle(s), s.ID); err != nil {
			var rl *errDiscordRateLimited
			if !errors.As(err, &rl) {
				log.Printf("[discord] %s: rename failed: %v", s.ID, err)
			}
		} else if ok {
			log.Printf("[discord] %s: channel renamed to #%s", s.ID, channelName(sessionTitle(s), s.ID))
		}
	}
}

// discordExports: the sessions whose channel went into their archive (discordExport), so the destroy hook deletes it
var discordExports sync.Map

// discordExport: the session's channel exported into a local dir (tmp/discord) for its archive (archivetar.go); ""
// when it has no channel, the channel is gone, or the export failed (then the channel is kept and Deyao told, by
// discordDestroy). done(archived) notes whether the archive holding it reached the Storage Box.
func (r *Router) discordExport(s Session, tmp string) (dir string, done func(archived error)) {
	done = func(error) {}
	if disc == nil || s.DiscordChannel == "" {
		return "", done
	}
	dir = filepath.Join(tmp, "discord")
	res, err := disc.exportChannel(s.DiscordChannel, &dirSink{dir: dir}, discFetch)
	if err != nil {
		log.Printf("[discord] %s: channel %s NOT exported: %v", s.ID, s.DiscordChannel, err)
		discordExports.Store(s.ID, err)
		return "", done
	}
	if res == nil {
		return "", done
	}
	return dir, func(archived error) {
		if archived != nil {
			discordExports.Store(s.ID, fmt.Errorf("its archive failed: %v", archived))
			return
		}
		discordExports.Store(s.ID, res)
	}
}

// discordDestroy: the channel goes once its archive holds it; otherwise it is kept and Deyao told
func discordDestroy(r *Router, s Session) {
	if disc == nil || s.DiscordChannel == "" {
		return
	}
	v, _ := discordExports.LoadAndDelete(s.ID)
	res, ok := v.(*exportResult)
	if !ok {
		why := "the session has no archive"
		if err, isErr := v.(error); isErr {
			why = err.Error()
		}
		log.Printf("[discord] %s: channel %s NOT exported, kept: %s", s.ID, s.DiscordChannel, why)
		r.DM(fmt.Sprintf("Jarvis 4: the Discord channel of destroyed session %q wasn't exported (%s); it is kept: https://discord.com/channels/%s/%s", sessionTitle(s), why, disc.guild, s.DiscordChannel))
		return
	}
	if _, err := disc.deleteChannel(s.DiscordChannel); err != nil {
		log.Printf("[discord] %s: channel %s exported but NOT deleted: %v", s.ID, s.DiscordChannel, err)
		return
	}
	log.Printf("[discord] %s: channel #%s exported (%d message(s), %d attachment(s), %d failed) and deleted", s.ID, res.Name, res.Messages, res.Attachments, res.AttachmentsFailed)
}

// dirSink: the export's files under a local dir
type dirSink struct{ dir string }

func (s *dirSink) putBytes(rel string, b []byte, _ string) error {
	p := filepath.Join(s.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
