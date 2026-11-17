package main

// What the Do's cost, said once a minute in the log ("state: last minute: …"). Every Do of every replica takes the
// same lock and, as built, reads the records again after another replica's change and marshals all of them to find
// its own: when the Do's of a minute take about a minute between them, every request waits its turn (2026-11-17: an
// approval's signature timed out on the phone, with nothing in the log to say why).

import (
	"fmt"
	"log"
	"time"
)

// doLoad: the Do's since `since` (all under State.mu)
type doLoad struct {
	since   time.Time
	n       int
	waited  time.Duration // asking → holding this replica's lock, in all
	maxWait time.Duration
	held    time.Duration // holding this replica's lock, in all
	rowLock time.Duration // of held: waiting for the other replicas (the state_version row)
	reloads int
	reload  time.Duration // of held: reading the records again
	writes  int
	write   time.Duration // of held: marshalling the records and writing what changed
	rows    int
	bytes   int
}

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
func (l *doLoad) done(asked, got time.Time) {
	end := time.Now()
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
		"%d reloads %d ms, %d writes and every marshal %d ms); they waited %d ms in all for it here, the longest %d ms; "+
		"the records are %d rows, %d bytes",
		end.Sub(l.since).Round(time.Second), l.n, ms(l.held), ms(l.rowLock), l.reloads, ms(l.reload), l.writes, ms(l.write),
		ms(l.waited), ms(l.maxWait), l.rows, l.bytes)
}
