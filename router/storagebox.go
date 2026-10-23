package main

// The Storage Box (Hetzner, WebDAV over https on 443) with the router's own credentials: router env
// STORAGEBOX_HOST, STORAGEBOX_USER, STORAGEBOX_PASSWORD. The archives of destroyed sessions live there, one .tar.gz
// each in Jarvis 4's own folder (archivetar.go).

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type StorageBox struct {
	base, user, pass string
	http             *http.Client
}

// putBackoff: the wait before a PUT is retried (times the attempt)
var putBackoff = time.Second

var errNoStorageBox = errors.New("the router has no STORAGEBOX_HOST/USER/PASSWORD")

// recordsBoxFromEnv: nil when any of the three is missing
func recordsBoxFromEnv() *StorageBox {
	h, u, p := os.Getenv("STORAGEBOX_HOST"), os.Getenv("STORAGEBOX_USER"), os.Getenv("STORAGEBOX_PASSWORD")
	if h == "" || u == "" || p == "" {
		return nil
	}
	return newStorageBox("https://"+h, u, p)
}

func newStorageBox(base, user, pass string) *StorageBox {
	// its own transport: the default keeps 2 idle connections per host, too few for the live copies' and content
	// stores' calls in parallel, which would then open a new TLS connection for most
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 8
	return &StorageBox{base: strings.TrimSuffix(base, "/") + "/", user: user, pass: pass, http: &http.Client{Timeout: 30 * time.Minute, Transport: t}}
}

func davURL(base, p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return base + strings.Join(segs, "/")
}

func (b *StorageBox) do(method, p string, body io.Reader, size int64, hdr map[string]string) (*http.Response, error) {
	u := davURL(b.base, p)
	// a directory keeps its trailing "/": Apache answers a collection without it with a 301, which Go's client follows
	// as a GET (an HTML listing instead of a multistatus)
	if ((method == "DELETE" || method == "PROPFIND") && strings.HasSuffix(p, "/")) || method == "MKCOL" {
		u += "/"
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	req.SetBasicAuth(b.user, b.pass)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return b.http.Do(req)
}

// Mkcols: every segment of a directory path (an existing one answers 405, which is fine)
func (b *StorageBox) Mkcols(dir string) error {
	cur := ""
	for _, s := range strings.Split(strings.Trim(dir, "/"), "/") {
		if s == "" {
			continue
		}
		cur += s + "/"
		if err := b.mkcol(strings.TrimSuffix(cur, "/")); err != nil {
			return err
		}
	}
	return nil
}

// mkcol: one directory whose parent exists (an existing one answers 405, which is fine)
func (b *StorageBox) mkcol(dir string) error {
	resp, err := b.do("MKCOL", strings.Trim(dir, "/"), nil, 0, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 405 {
		return fmt.Errorf("MKCOL %s/: HTTP %d", strings.Trim(dir, "/"), resp.StatusCode)
	}
	return nil
}

// PutFile: a local file, three tries
func (b *StorageBox) PutFile(p, local string) error {
	var last error
	for i := 0; i < 3; i++ {
		f, err := os.Open(local)
		if err != nil {
			return err
		}
		fi, _ := f.Stat()
		last = b.put(p, f, fi.Size())
		f.Close()
		if last == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * putBackoff)
	}
	return last
}

func (b *StorageBox) PutBytes(p string, data []byte) error {
	var last error
	for i := 0; i < 3; i++ {
		if last = b.put(p, strings.NewReader(string(data)), int64(len(data))); last == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * putBackoff)
	}
	return last
}

func (b *StorageBox) put(p string, r io.Reader, size int64) error {
	resp, err := b.do("PUT", p, r, size, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}

// Get: nil, nil when the file is missing
func (b *StorageBox) Get(p string) ([]byte, error) {
	return b.get(p, nil)
}

// GetTail: the file's last n bytes (a server that ignores Range sends it whole; the caller copes)
func (b *StorageBox) GetTail(p string, n int) ([]byte, error) {
	return b.get(p, map[string]string{"Range": fmt.Sprintf("bytes=-%d", n)})
}

func (b *StorageBox) get(p string, hdr map[string]string) ([]byte, error) {
	resp, err := b.do("GET", p, nil, 0, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d", p, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// Download: a file to a local path (streamed); false when it is missing
func (b *StorageBox) Download(p, local string) (bool, error) {
	resp, err := b.do("GET", p, nil, 0, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("GET %s: HTTP %d", p, resp.StatusCode)
	}
	f, err := os.OpenFile(local, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err == nil, err
}

func (b *StorageBox) Exists(p string) (bool, error) {
	resp, err := b.do("HEAD", p, nil, 0, nil)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == 404:
		return false, nil
	case resp.StatusCode < 300:
		return true, nil
	}
	return false, fmt.Errorf("HEAD %s: HTTP %d", p, resp.StatusCode)
}

// Delete: a file, or a directory with a trailing "/" (whole); a missing one is fine
func (b *StorageBox) Delete(p string) error {
	resp, err := b.do("DELETE", p, nil, 0, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		return fmt.Errorf("DELETE %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}

// PutStream: a body of unknown length, sent chunked (an archive written while it uploads, archivetar.go); one try,
// since a stream can't be sent again (the caller makes it again)
func (b *StorageBox) PutStream(p string, body io.Reader) error {
	req, err := http.NewRequest("PUT", davURL(b.base, p), body)
	if err != nil {
		return err
	}
	req.ContentLength = -1
	req.SetBasicAuth(b.user, b.pass)
	resp, err := streamClient.Do(req) // no overall time limit: a multi-GB archive outlasts any fixed one
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: HTTP %d", p, resp.StatusCode)
	}
	return nil
}

// Move: a file to a new name (WebDAV MOVE, server side), replacing what is there
func (b *StorageBox) Move(from, to string) error {
	resp, err := b.do("MOVE", from, nil, 0, map[string]string{"Destination": davURL(b.base, to), "Overwrite": "T"})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("MOVE %s → %s: HTTP %d", from, to, resp.StatusCode)
	}
	return nil
}

// Size: a file's size (-1 when it is missing)
func (b *StorageBox) Size(p string) (int64, error) {
	resp, err := b.do("HEAD", p, nil, 0, nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == 404:
		return -1, nil
	case resp.StatusCode < 300:
		return resp.ContentLength, nil
	}
	return 0, fmt.Errorf("HEAD %s: HTTP %d", p, resp.StatusCode)
}
