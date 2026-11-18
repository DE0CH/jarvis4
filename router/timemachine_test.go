package main

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// a fake fabric hermit: the conversation's sandbox state, the calls it got
type fakeFabricHermit struct {
	mu    sync.Mutex
	state string
	calls []string
}

func (f *fakeFabricHermit) install(t *testing.T) {
	t.Setenv("FABRIC_HERMIT_URL", "http://hermit")
	old := fabricHermitCall
	t.Cleanup(func() { fabricHermitCall = old })
	fabricHermitCall = func(method, path string, body any) (int, []byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, _ := json.Marshal(body)
		f.calls = append(f.calls, method+" "+path+" "+string(b))
		switch {
		case strings.HasSuffix(path, "/freeze"):
			f.state = "frozen"
		case strings.HasSuffix(path, "/thaw"):
			f.state = "ready"
		}
		if f.state == "" {
			return 404, []byte(`{"code":"no_sandbox"}`), nil
		}
		out, _ := json.Marshal(map[string]string{"id": "0190f6c2-0000-7000-8000-000000000001", "state": f.state})
		return 200, out, nil
	}
}

func (f *fakeFabricHermit) saw(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func fabricSession(r *Router, id, machine string) {
	addSession(r, id, "started", machine, false)
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		s.Runner, s.Fabric = "fabric", &FabricLine{Conversation: "c-" + id, Machine: machine}
	})
}

// time-machine: the machine's ask freezes its fabric sandbox until then and the session is frozen; a delivery (here an
// Inbox decision's outcome, which goes only into a running session) thaws it first and the machine reads why it is
// back; Resume thaws too; only a fabric session has the time machine
func TestTheTimeMachineFreezesAndAnyDeliveryThaws(t *testing.T) {
	f := &fakeFabricHermit{state: "ready"}
	f.install(t)
	r := newTestRouter(t)
	fabricSession(r, "sT", "x01")
	m := newTestMachine(r, "x01")
	h := r.MachineHandler()

	code, out := m.do(t, h, "POST", "/m/api/time-machine", `{"seconds": 7200}`)
	if code != 202 || out["frozen"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if st, _ := r.sessionState("sT"); st != "frozen" {
		t.Fatalf("state %q", st)
	}
	if !f.saw("POST /v1/conversations/c-sT/sandbox/freeze {\"until\":\"") {
		t.Fatalf("%v", f.calls)
	}
	if _, out := m.do(t, h, "GET", "/m/api/time-machine", ""); out["frozen"] != true {
		t.Fatalf("%v", out)
	}
	// a frozen session is not frozen again, and a delivery thaws it before it goes in (the machine here answers
	// nothing, so the delivery itself fails after the thaw: what is checked is the thaw)
	if code, _ := m.do(t, h, "POST", "/m/api/time-machine", `{"seconds": 60}`); code != 409 {
		t.Fatalf("frozen twice: %d", code)
	}
	_ = r.deliverVouchedRunning("sT", Delivery{Kind: "request-outcome"})
	if !f.saw("POST /v1/conversations/c-sT/sandbox/thaw") {
		t.Fatalf("an outcome did not thaw it: %v", f.calls)
	}
	if st, _ := r.sessionState("sT"); st != "started" {
		t.Fatalf("state %q after the thaw", st)
	}
	_, out = m.do(t, h, "GET", "/m/api/time-machine", "")
	if out["frozen"] != false || out["why"] != "a decision on an Inbox request" || out["back"] == nil {
		t.Fatalf("%v", out)
	}

	// Resume (the app, or hermit-jarvis for the chat) thaws a frozen session
	if code, _ := m.do(t, h, "POST", "/m/api/time-machine", `{"seconds": 60}`); code != 202 {
		t.Fatal("not frozen again")
	}
	if err := r.Resume("sT", false); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		if st, _ := r.sessionState("sT"); st == "started" {
			break
		} else if i > 100 {
			t.Fatalf("state %q after Resume", st)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// a session on Fly or AWS has none
	addSession(r, "sF", "started", "m2", false)
	m2 := newTestMachine(r, "m2")
	if code, out := m2.do(t, h, "POST", "/m/api/time-machine", `{"seconds": 60}`); code != 409 || !strings.Contains(out["error"].(string), "fabric") {
		t.Fatalf("%d %v", code, out)
	}
	// nor a time out of range
	if code, _ := m.do(t, h, "POST", "/m/api/time-machine", `{"seconds": 0}`); code != 409 {
		t.Fatal("0 s taken")
	}
}

// hermit thaws a frozen sandbox at its until by itself: the router's loop finds it running again (back, "the time");
// one hermit no longer has fails the session (Resume starts it from its files)
func TestFrozenVerdict(t *testing.T) {
	for _, c := range []struct {
		state      string
		back, lost bool
	}{{"ready", true, false}, {"frozen", false, false}, {"starting", false, false}, {"releasing", false, false}, {"gone", false, true}, {"", false, true}} {
		if b, l := frozenVerdict(c.state); b != c.back || l != c.lost {
			t.Fatalf("%q: %v %v", c.state, b, l)
		}
	}
	r := newTestRouter(t)
	fabricSession(r, "sB", "x02")
	r.st.Do(func(d *persisted) {
		d.Sessions["sB"].State = "frozen"
		d.Sessions["sB"].TimeMachine = &TimeMachine{Since: time.Now()}
	})
	r.back("sB", "the time")
	r.st.Read(func(d *persisted) {
		s := d.Sessions["sB"]
		if s.State != "started" || s.TimeMachine.Why != "the time" || s.TimeMachine.Back == nil {
			t.Fatalf("%+v %+v", s.State, s.TimeMachine)
		}
	})
}
