package main

// Snapshots straight between the machine and the bucket (router/snapdirect.go, DECISIONS 241). The machines' way to
// the router (Fly's WireGuard peer into m-gateway) carries about 6 MB/s per connection and 15 MB/s in all (measured
// 2026-10-25), while the bucket answers a Fly machine at 86 MB/s on one stream and 380 MB/s on eight. So the bytes go
// to the bucket and only the asking goes to the router:
//
//	upload    POST /m/snapshot-upload → a multipart upload of this machine's own object; the tar is cut into parts as it
//	          is made and directWorkers of them go up at once through part URLs the router signs
//	          (POST /m/snapshot-upload/parts); POST /m/snapshot-upload/done ends it and the router reads the object back
//	          for its hash, which must be this machine's, before it keeps it as the pending snapshot. The commit is the
//	          same as a streamed one's (snapstream.go).
//	download  GET /m/snapshot-url → a read URL of the snapshot /m/snapshot would send, its sha256, size and signature;
//	          directWorkers ranges at once into the file, then the hash is checked as before.
//
// A router without these routes, or a bucket it can't sign for (the stand-ins' memory), answers 404: the stream through
// the router, as before. Part and read URLs are good for one hour and name this machine's own object only; a part URL
// is dead once its upload is finished.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	errNoDirect   = errors.New("the router signs no bucket URLs")
	directWorkers = 4
	directTries   = 4
	directBackoff = 2 * time.Second
	// bucketHTTP: the machine's own way to the bucket (the internet, not the router's gateway). HTTP/1.1, so the
	// parts and ranges in flight each have a connection of their own (HTTP/2 would put them on one).
	bucketHTTP = &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 2 * time.Minute, MaxIdleConnsPerHost: 16}}
)

type uploadedPart struct {
	N    int    `json:"n"`
	ETag string `json:"etag"`
}

// directSnapshot: the snapshot made and sent to the bucket in parts → the hash the router read back
func directSnapshot(c *client) (string, int64, error) {
	b, _, status, err := c.raw("POST", "/m/snapshot-upload", []byte("{}"))
	if err != nil {
		return "", 0, err
	}
	if status == 404 || status == 405 {
		return "", 0, errNoDirect
	}
	if status != 200 {
		return "", 0, fmt.Errorf("snapshot upload: HTTP %d %s", status, bytes.TrimSpace(b))
	}
	var up struct {
		Upload   string `json:"upload"`
		PartSize int64  `json:"partSize"`
	}
	if json.Unmarshal(b, &up) != nil || up.Upload == "" || up.PartSize < 5<<20 || up.PartSize > 1<<30 {
		return "", 0, fmt.Errorf("snapshot upload: a bad answer %.200s", b)
	}
	pr, pw := io.Pipe()
	type made struct {
		sum string
		n   int64
		err error
	}
	done := make(chan made, 1)
	go func() {
		sum, n, err := writeSnapshot(pw)
		pw.CloseWithError(err)
		done <- made{sum, n, err}
	}()
	parts, err := uploadParts(c, up.Upload, up.PartSize, pr)
	pr.CloseWithError(errors.New("the upload stopped")) // a failed upload stops the writer too
	m := <-done
	if err == nil && m.err != nil {
		err = fmt.Errorf("making the snapshot: %w", m.err)
	}
	if err != nil {
		if aerr := c.json("POST", "/m/snapshot-upload/abort", map[string]string{"upload": up.Upload}, nil); aerr != nil {
			log.Printf("snapshot upload: abort: %v", aerr)
		}
		return "", 0, err
	}
	var got struct {
		Sha256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	}
	if err := c.json("POST", "/m/snapshot-upload/done", map[string]any{"upload": up.Upload, "parts": parts, "sha256": m.sum, "bytes": m.n}, &got); err != nil {
		return "", 0, err
	}
	if got.Sha256 != m.sum || got.Bytes != m.n {
		return "", 0, fmt.Errorf("the bucket holds other bytes (%s, %d) than were sent (%s, %d)", got.Sha256, got.Bytes, m.sum, m.n)
	}
	return m.sum, m.n, nil
}

// uploadParts: r cut into parts of size, directWorkers of them on their way at once → the parts in order
func uploadParts(c *client, upload string, size int64, r io.Reader) ([]uploadedPart, error) {
	var (
		mu    sync.Mutex
		etags []string
		ferr  error
	)
	fail := func(err error) {
		mu.Lock()
		if ferr == nil {
			ferr = err
		}
		mu.Unlock()
	}
	failed := func() error {
		mu.Lock()
		defer mu.Unlock()
		return ferr
	}
	type job struct {
		n   int
		url string
		buf []byte
	}
	free := make(chan []byte, directWorkers+1)
	for range directWorkers + 1 {
		free <- make([]byte, size)
	}
	work := make(chan job)
	var wg sync.WaitGroup
	for range directWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				etag, err := putPart(j.url, j.buf)
				if err != nil {
					fail(fmt.Errorf("part %d: %w", j.n, err))
				} else {
					mu.Lock()
					for len(etags) < j.n {
						etags = append(etags, "")
					}
					etags[j.n-1] = etag
					mu.Unlock()
				}
				free <- j.buf[:cap(j.buf)]
			}
		}()
	}
	var urls []string
	for n := 1; failed() == nil; n++ {
		buf := <-free
		k, err := io.ReadFull(r, buf)
		if k == 0 && err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			fail(err)
			break
		}
		if len(urls) == 0 {
			var out struct {
				URLs []string `json:"urls"`
			}
			if uerr := c.json("POST", "/m/snapshot-upload/parts", map[string]any{"upload": upload, "from": n, "count": 16}, &out); uerr != nil || len(out.URLs) == 0 {
				fail(fmt.Errorf("part URLs: %v", uerr))
				break
			}
			urls = out.URLs
		}
		work <- job{n, urls[0], buf[:k]}
		urls = urls[1:]
		if err == io.ErrUnexpectedEOF {
			break
		}
	}
	close(work)
	wg.Wait()
	if err := failed(); err != nil {
		return nil, err
	}
	parts := make([]uploadedPart, len(etags))
	for i, e := range etags {
		parts[i] = uploadedPart{i + 1, e}
	}
	return parts, nil
}

// putPart: one part to its URL, tried again on a failure → its ETag
func putPart(url string, body []byte) (string, error) {
	var last error
	for try := 1; try <= directTries; try++ {
		req, _ := http.NewRequest("PUT", url, bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		resp, err := bucketHTTP.Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			if resp.StatusCode == 200 && resp.Header.Get("ETag") != "" {
				return resp.Header.Get("ETag"), nil
			}
			err = fmt.Errorf("HTTP %d %s", resp.StatusCode, bytes.TrimSpace(b))
		}
		last = err
		time.Sleep(time.Duration(try) * directBackoff)
	}
	return "", last
}

// fetchSnapshot: the snapshot /m/snapshot would send, into dst (from the bucket, else through the router) → its sha256
// and the signature the router keeps with it ("" when it has none: a restore's)
func fetchSnapshot(c *client, dst string) (string, string, error) {
	var in struct {
		URL    string `json:"url"`
		Sha256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
		Sig    string `json:"sig"`
	}
	b, _, status, err := c.raw("GET", "/m/snapshot-url", nil)
	if err != nil || status != 200 || json.Unmarshal(b, &in) != nil || in.URL == "" || in.Bytes <= 0 {
		// an older router, a bucket it can't sign for, or no snapshot: /m/snapshot says which
		prog := startRestoreLog("downloading", 0)
		sum, hdr, err := c.downloadTo2(dst, prog)
		prog.stop()
		return sum, hdr.Get("X-Snapshot-Sig"), err
	}
	prog := startRestoreLog("downloading", in.Bytes)
	err = getRanges(in.URL, in.Bytes, dst, &prog.done)
	prog.stop()
	if err != nil {
		return "", "", err
	}
	sum, err := fileSha256(dst)
	return sum, in.Sig, err
}

// downloadTo2: /m/snapshot through the router into dst, counted
func (c *client) downloadTo2(dst string, prog *restoreLog) (string, http.Header, error) {
	sum, hdr, _, err := c.downloadTo("/m/snapshot", func(r io.Reader) error {
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, countingReader{r, &prog.done})
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	})
	return sum, hdr, err
}

// getRanges: size bytes of url into dst, directWorkers ranges of rangeSize at once
var rangeSize = int64(16 << 20)

func getRanges(url string, size int64, dst string, done *atomic.Int64) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		return err
	}
	next := atomic.Int64{}
	var (
		mu   sync.Mutex
		ferr error
		wg   sync.WaitGroup
	)
	for range directWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				off := next.Add(rangeSize) - rangeSize
				mu.Lock()
				stop := ferr != nil
				mu.Unlock()
				if off >= size || stop {
					return
				}
				end := min(off+rangeSize, size)
				if err := getRange(url, f, off, end, done); err != nil {
					mu.Lock()
					if ferr == nil {
						ferr = fmt.Errorf("bytes %d-%d: %w", off, end-1, err)
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	if ferr != nil {
		return ferr
	}
	return f.Sync()
}

func getRange(url string, f *os.File, off, end int64, done *atomic.Int64) error {
	var last error
	for try := 1; try <= directTries; try++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, end-1))
		resp, err := bucketHTTP.Do(req)
		if err == nil {
			if resp.StatusCode == 206 {
				var n int64
				n, err = io.Copy(io.NewOffsetWriter(f, off), io.LimitReader(resp.Body, end-off))
				resp.Body.Close()
				done.Add(n)
				if err == nil && n == end-off {
					return nil
				}
				done.Add(-n)
				if err == nil {
					err = fmt.Errorf("%d of %d bytes", n, end-off)
				}
			} else {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				resp.Body.Close()
				err = fmt.Errorf("HTTP %d %s", resp.StatusCode, bytes.TrimSpace(b))
			}
		}
		last = err
		time.Sleep(time.Duration(try) * directBackoff)
	}
	return last
}

func fileSha256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n.Add(int64(n))
	return n, err
}

// restoreLog: a restore's progress in the supervisor's log every progressLogEvery (the Lifecycle shows it), so a
// machine that is downloading or unpacking a large snapshot is seen doing so
type restoreLog struct {
	what    string
	total   int64
	done    atomic.Int64
	started time.Time
	quit    chan struct{}
	wg      sync.WaitGroup
}

func startRestoreLog(what string, total int64) *restoreLog {
	l := &restoreLog{what: what, total: total, started: time.Now(), quit: make(chan struct{})}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		t := time.NewTicker(progressLogEvery)
		defer t.Stop()
		for {
			select {
			case <-l.quit:
				return
			case <-t.C:
				log.Printf("%s", l.line())
			}
		}
	}()
	return l
}

func (l *restoreLog) line() string {
	done := l.done.Load()
	s := "restore: " + l.what + " " + gb(done)
	if l.total > 0 {
		s += fmt.Sprintf("/%s (%d%%)", gb(l.total), done*100/l.total)
	}
	if el := time.Since(l.started).Seconds(); el >= 1 {
		s += fmt.Sprintf(", %.0f MB/s", float64(done)/el/1e6)
		if l.total > done && done > 0 {
			s += fmt.Sprintf(", %.0f s left", float64(l.total-done)/(float64(done)/el))
		}
	}
	return s
}

func (l *restoreLog) stop() {
	close(l.quit)
	l.wg.Wait()
	el := time.Since(l.started).Seconds()
	log.Printf("restore: %s done, %s in %.0f s (%.0f MB/s)", l.what, gb(l.done.Load()), el, float64(l.done.Load())/max(el, 0.001)/1e6)
}
