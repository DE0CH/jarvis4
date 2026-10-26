package main

// The harness's own words in the supervisor log (Deyao, 2026-10-26): the harness launcher (entrypoint.sh,
// harness-*.sh) writes its steps to stdout as tagged lines ("[dsh] dsh web exited …", "[entrypoint] …"); until now
// they reached only the machine's console, so a harness that never came up ("booting…" for ever) left nothing to
// read. The keeper copies those lines, and only those, into the supervisor log (tag "harness"), from where they go
// the way every supervisor line goes: through secretRedactor, to the router, shown only to Deyao's login.
// Anything else on the harness's stdout (a program's own output, which may quote a prompt) stays on the console.

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// harnessLineTag: a launcher's own line: "[name] text"
var harnessLineTag = regexp.MustCompile(`^\[[a-z0-9-]{2,24}\] `)

const (
	harnessLogBurst = 60 // lines at once, refilled at harnessLogRate a minute
	harnessLogRate  = 30
)

// harnessLog: the rate-limited sink of the harness's tagged lines
type harnessLog struct {
	mu      sync.Mutex
	out     io.Writer
	tokens  float64
	last    time.Time
	dropped int
}

func newHarnessLog(out io.Writer) *harnessLog {
	return &harnessLog{out: out, tokens: harnessLogBurst, last: time.Now()}
}

func (h *harnessLog) line(s string) {
	if !harnessLineTag.MatchString(s) {
		return
	}
	if len(s) > maxLogLine {
		s = s[:maxLogLine]
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.tokens = min(harnessLogBurst, h.tokens+now.Sub(h.last).Minutes()*harnessLogRate)
	h.last = now
	if h.tokens < 1 {
		h.dropped++
		return
	}
	h.tokens--
	if h.dropped > 0 {
		io.WriteString(h.out, "("+strconv.Itoa(h.dropped)+" harness lines left out: too many at once)\n")
		h.dropped = 0
	}
	io.WriteString(h.out, s+"\n")
}

// harnessLog: the keeper's sink, lines tagged "harness" in the supervisor log
func (k *keeperT) harnessLog() *harnessLog {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.hlog == nil {
		k.hlog = newHarnessLog(fileLog{supervisorLogPath, "harness"})
	}
	return k.hlog
}

// harnessStdout: the harness's stdout and stderr, a pipe whose lines go to the console as before and, when tagged,
// to sink. The write end goes to the harness (an *os.File, so exec hands it over as is and Wait never waits on a
// copy); the read end is drained until every holder of the write end (the harness's background loops too) is gone.
func harnessStdout(sink *harnessLog) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer r.Close()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			os.Stdout.Write(append(sc.Bytes(), '\n'))
			sink.line(sc.Text())
		}
		io.Copy(os.Stdout, r) // a line past the scanner's limit: the rest to the console only
	}()
	return w, nil
}
