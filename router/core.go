package main

// The core's HTTP API (core/main.go). The router reads what it needs from the signed answers' payloads
// but doesn't rely on them for anything security-relevant; it passes the documents on unchanged.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Doc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func (d *Doc) Decode(out any) error { return json.Unmarshal([]byte(d.Payload), out) }

type CoreClient struct {
	mu   sync.RWMutex
	base string
	// baseFn: where the client points, asked at every call (the kernel's serving secrets, kernel.go storesOnSecrets);
	// name: what its errors call it ("" = "core")
	baseFn func() string
	name   string
	http   *http.Client
	// onLineSeq: every answer's X-Line-Seq (linestate.go keeps the core's line state when it moved), called before
	// the answer goes back to the caller
	onLineSeq func(int)
}

// URL: the core this client talks to now
func (c *CoreClient) URL() string {
	if c.baseFn != nil {
		return c.baseFn()
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.base
}

// SetURL: point the client at another core (nextcore.go: a flip), for every later call
func (c *CoreClient) SetURL(u string) {
	c.mu.Lock()
	c.base = u
	c.mu.Unlock()
}

// CoreError: the core refused; Body is its signed error document (relayed as is)
type CoreError struct {
	Status int
	Body   []byte
	Msg    string
}

func (e *CoreError) Error() string { return e.Msg }

// coreCallMax: how long the router waits for one core call. The default covers every call that answers from memory or
// makes one Fly request. The running core (sha-06ab2452f8ad, from before R2; held by core-pin) waits INSIDE /start
// and /kill: its start is a Fly create, up to 10 waits for "started" and up to 10 init execs, each Fly request bounded
// by its own 90 s client (≈ 34 min at worst), and its kill a destroy plus up to 20 confirming reads (≈ 32 min). A
// router that gave up sooner (15 min, 2026-10-15: "start: core /start: … Client.Timeout exceeded") failed a start the
// core was still carrying out, which then left a started machine nobody knew of. So those two wait past the core's
// own worst case and always hear its answer (DECISIONS 181).
var coreCallMax = map[string]time.Duration{"/start": 40 * time.Minute, "/kill": 40 * time.Minute}

const coreCallDefault = 15 * time.Minute

func coreCallTimeout(path string) time.Duration {
	if d, ok := coreCallMax[path]; ok {
		return d
	}
	return coreCallDefault
}

func (c *CoreClient) Raw(method, path string, body []byte) (int, []byte, error) {
	status, b, seq, err := c.raw(method, path, body)
	if err == nil && seq > 0 && c.onLineSeq != nil {
		c.onLineSeq(seq)
	}
	return status, b, err
}

// rawNoHook: Raw without the line-state hook (the hook's own calls)
func (c *CoreClient) rawNoHook(method, path string, body []byte) (int, []byte, error) {
	status, b, _, err := c.raw(method, path, body)
	return status, b, err
}

func (c *CoreClient) raw(method, path string, body []byte) (int, []byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), coreCallTimeout(path))
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL(), "/")+path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	seq, _ := strconv.Atoi(resp.Header.Get(lineSeqHeader))
	return resp.StatusCode, b, seq, err
}

// who: what errors call the client's server
func (c *CoreClient) who() string {
	if c.name != "" {
		return c.name
	}
	return "core"
}

// Call: POST a JSON body, expect a signed document
func (c *CoreClient) Call(path string, in any) (*Doc, error) {
	d, _, err := c.CallAnswer(path, in)
	return d, err
}

// Answer: what the core answers beside a cert (not under its signature; each its own proof): the cert's input-log
// entry (core-signed) and the line's carried secrets rebound to the cert's machine (only the core opens them). Empty
// from a core before R2 (it kept its log for reading and had /carry/forward).
type Answer struct {
	Entry *Doc   `json:"entry"`
	Carry string `json:"carry"`
}

// CallAnswer: Call, with what came beside the signed document
func (c *CoreClient) CallAnswer(path string, in any) (*Doc, *Answer, error) {
	body, _ := json.Marshal(in)
	status, b, err := c.Raw("POST", path, body)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", c.who(), path, err)
	}
	var d Doc
	if status != 200 {
		msg := fmt.Sprintf("%s %s: HTTP %d", c.who(), path, status)
		var e struct{ Error string }
		if json.Unmarshal(b, &d) == nil && d.Decode(&e) == nil && e.Error != "" {
			msg = c.who() + ": " + e.Error
		}
		return nil, nil, &CoreError{Status: status, Body: b, Msg: msg}
	}
	if err := json.Unmarshal(b, &d); err != nil || d.Payload == "" {
		return nil, nil, fmt.Errorf("%s %s: not a signed document", c.who(), path)
	}
	var a Answer
	json.Unmarshal(b, &a)
	return &Doc{Payload: d.Payload, Sig: d.Sig}, &a, nil
}

// Key: the core's public keys (from /identity; the box signature and signed state are the app's and setup's to check)
func (c *CoreClient) Key() (map[string]string, error) {
	status, b, err := c.Raw("GET", "/identity", nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("%s /identity: HTTP %d", c.who(), status)
	}
	var id struct {
		SigningKey   string `json:"signingKey"`
		AgreementKey string `json:"agreementKey"`
		SizeLadder   int    `json:"sizeLadder"`
	}
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, err
	}
	if c.name == "" {
		noteCoreSizes(id.SizeLadder >= 1) // sizes.go (the core's own; secrets starts no machine)
	}
	return map[string]string{"signingKey": id.SigningKey, "agreementKey": id.AgreementKey}, nil
}
