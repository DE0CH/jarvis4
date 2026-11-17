package main

// What the Do's cost, said once a minute in the log ("state: last minute: …"). Every Do of every replica takes the
// same lock and, as built, reads the records again after another replica's change and marshals all of them to find
// its own: when the Do's of a minute take about a minute between them, every request waits its turn (2026-11-17: an
// approval's signature timed out on the phone, with nothing in the log to say why).

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// doCaller: the line that called State.Do ("flows.go:707")
func doCaller() string {
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		return "?"
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}

// doLoad: the Do's since `since` (all under State.mu)
type doLoad struct {
	since    time.Time
	n        int
	waited   time.Duration // asking → holding this replica's lock, in all
	maxWait  time.Duration
	held     time.Duration // holding this replica's lock, in all
	rowLock  time.Duration // of held: waiting for the other replicas (the state_version row)
	reloads  int           // all the records read again
	catchUps int           // only the records another replica changed read again (statedb.go catchUp)
	reload   time.Duration // of held: reading the records again
	writes   int
	write    time.Duration // of held: marshalling the records and writing what changed
	rows     int
	bytes    int
	by       map[string]*doCost // the line that asked → its Do's
}

type doCost struct {
	n    int
	held time.Duration
}

// doLoadTop: how many callers the line names (the ones that held the lock longest)
const doLoadTop = 8

// doLoadEvery: how often the load is said (a var: tests)
var doLoadEvery = time.Minute

// note: the size of the records as they were just marshalled
func (l *doLoad) note(now rows) {
	l.rows, l.bytes = 0, 0
	for _, m := range now {
		l.rows += len(m)
		for _, doc := range m {
			l.bytes += len(doc)
		}
	}
}

// done: one Do asked for at `asked` that got the lock at `got` has ended
func (l *doLoad) done(who string, asked, got time.Time) {
	end := time.Now()
	if l.by == nil {
		l.by = map[string]*doCost{}
	}
	c := l.by[who]
	if c == nil {
		c = &doCost{}
		l.by[who] = c
	}
	c.n++
	c.held += end.Sub(got)
	if l.since.IsZero() {
		l.since = asked
	}
	l.n++
	w := got.Sub(asked)
	l.waited += w
	if w > l.maxWait {
		l.maxWait = w
	}
	l.held += end.Sub(got)
	if end.Sub(l.since) < doLoadEvery {
		return
	}
	log.Print(l.line(end))
	*l = doLoad{since: end, rows: l.rows, bytes: l.bytes}
}

func (l *doLoad) line(end time.Time) string {
	ms := func(d time.Duration) int64 { return d.Milliseconds() }
	return fmt.Sprintf("state: last %s: %d changes asked for, holding the lock %d ms in all (%d ms of it waiting for the other replicas, "+
		"%d reloads and %d catch-ups %d ms, %d writes and every marshal %d ms); they waited %d ms in all for it here, the longest %d ms; "+
		"the records are %d rows, %d bytes; asked most by %s",
		end.Sub(l.since).Round(time.Second), l.n, ms(l.held), ms(l.rowLock), l.reloads, l.catchUps, ms(l.reload), l.writes, ms(l.write),
		ms(l.waited), ms(l.maxWait), l.rows, l.bytes, l.top())
}

// top: the callers that held the lock longest ("autopilot.go:88 ×120 3400 ms, …")
func (l *doLoad) top() string {
	who := make([]string, 0, len(l.by))
	for w := range l.by {
		who = append(who, w)
	}
	sort.Slice(who, func(i, j int) bool {
		a, b := l.by[who[i]], l.by[who[j]]
		return a.held > b.held || a.held == b.held && who[i] < who[j]
	})
	if len(who) > doLoadTop {
		who = who[:doLoadTop]
	}
	for i, w := range who {
		who[i] = fmt.Sprintf("%s ×%d %d ms", w, l.by[w].n, l.by[w].held.Milliseconds())
	}
	return strings.Join(who, ", ")
}
