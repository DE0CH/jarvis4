package main

// A session line on the kernel (DESIGN "Target design", docs/PLAN-grants.md §3, §5): its lifecycles as the router
// runs them, each step a cert the notarizer checked and the grant moved along it.
//
//	new session  the phone signs (sink, source-x, P), P = the line's stores and session:<id>; notarized; the root's
//	             ⊤ on the sink moves along it (→ P on source-x); then a spawn
//	spawn        the spawner starts a machine from the line's source and signs (source, fly-M, ⊤) once it gave its
//	             keys; notarized; the grant moves onto M (its keys)
//	pause        the machine's final snapshot (as for a core line); the spawner kills it and signs (fly-M, source-y,
//	             ⊤), source-y holding the snapshot's hash; notarized; the grant moves onto source-y
//	resume       a spawn from source-y
//	destroy      after the archive, (source-y, sink) by the gullible signer, notarized: the source ends
//
// The old core's lines go on beside these (D7): a session is the kernel's when Session.Kernel is set, and every
// lifecycle of it goes here.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/DE0CH/jarvis4/kernel/doc"
	"github.com/DE0CH/jarvis4/kernel/gv"
	"github.com/DE0CH/jarvis4/kernel/perm"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// KernelLine: where a kernel line is, as documents
type KernelLine struct {
	Source       doc.Object `json:"source"`                     // the source the line rests in, or its machine came from
	SourceCert   *sig.Doc   `json:"sourceCert"`                 // the cert into it
	SourceNz     *sig.Doc   `json:"sourceNotarized"`            // and its notarization
	Grant        *gv.Signed `json:"grant"`                      // the main grant: on the source, or on the machine
	MachineCert  *sig.Doc   `json:"machineCert,omitempty"`      // (source, fly-M, ⊤) while a machine runs
	MachineNz    *sig.Doc   `json:"machineNotarized,omitempty"` // and its notarization
	Burned       bool       `json:"burned,omitempty"`
	kernelSource *doc.Source
}

// kernelApprovalKind: the Inbox approval whose answer is the phone's signature over a cert into a new source
const kernelApprovalKind = "kernel-source"

// kernelServes: new sessions start on the kernel (it is reachable and the root's grant is here)
func (r *Router) kernelServes() bool {
	if r.kernel == nil {
		return false
	}
	ok := false
	r.st.Do(func(d *persisted) { ok = d.KernelRoot != nil })
	return ok
}

// kernelSettings: a source's settings, the guard's to read (machine/kernelboot.go): the harness, the permission mode
// (fixed for the line's life, D3) and the session's config as the old core's cert carried it
func kernelSettings(s *Session, config string) (json.RawMessage, error) {
	var cfg any = map[string]any{}
	if config != "" {
		if err := json.Unmarshal([]byte(config), &cfg); err != nil {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"v": 1, "harness": s.Harness, "permissionMode": normMode(s.PermissionMode), "config": cfg})
}

// kernelPair: what a line's grant allows: its stores, for its session
func kernelPair(s *Session) perm.Pair {
	allowed := []string{}
	for _, st := range s.Stores {
		allowed = append(allowed, "store:"+st)
	}
	return perm.Pair{Allowed: perm.Only(allowed...), Conditions: []string{"session:" + s.ID}}
}

// kernelSourceDraft: the cert the phone signs for a new source of the line (sink → source) with this image and
// snapshot ("" = none)
func (r *Router) kernelSourceDraft(s *Session, config, image, snapshot string) (sig.Doc, error) {
	settings, err := kernelSettings(s, config)
	if err != nil {
		return sig.Doc{}, err
	}
	b := make([]byte, 16)
	rand.Read(b)
	c := doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: doc.NewSource(b), Pair: kernelPair(s),
		Source: &doc.Source{Image: image, Settings: settings, Snapshot: snapshot}, Signer: doc.ByIPhone, IssuedAt: doc.Now()}
	if err := c.Check(); err != nil {
		return sig.Doc{}, err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return sig.Doc{}, err
	}
	return sig.Doc{Payload: string(p)}, nil
}

// kernelNewSessionApproval: the new session's Inbox approval (the phone signs the draft's payload)
func (r *Router) kernelNewSessionApproval(s *Session, config string, opts map[string]string, in NewSession, snapshot string) error {
	draft, err := r.kernelSourceDraft(s, config, r.cfg.SessionImage, snapshot)
	if err != nil {
		return err
	}
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[s.ID]; x != nil {
			x.Kernel = &KernelLine{}
		}
	})
	go r.addApproval(&Approval{Kind: kernelApprovalKind, Session: s.ID, Label: s.Label, Challenge: &Doc{Payload: draft.Payload},
		Options: opts, Origin: in.Origin, Explanation: in.Explanation, Batch: in.Batch})
	return nil
}

// respondKernel: the phone's signature over the draft → the source, then a spawn
func (r *Router) respondKernel(a *Approval, signature string) (*Doc, string, error) {
	cert := sig.Doc{Payload: a.Challenge.Payload, Sig: signature}
	// the start is a job (jobs.go "starting"): a replica that dies after the source is kept leaves it to another,
	// which spawns from the kept source (kernelContinue)
	done, err := r.lock(a.Session, "starting")
	if err != nil {
		return nil, "", err
	}
	nz, err := r.kernel.Notarize(cert)
	if err != nil {
		done()
		return nil, "", err
	}
	var root *gv.Signed
	r.st.Do(func(d *persisted) { root = d.KernelRoot })
	if root == nil {
		done()
		return nil, "", errors.New("the kernel has no root grant yet")
	}
	g, err := r.kernel.Move(*root, cert, nz)
	if err != nil {
		done()
		return nil, "", err
	}
	c, _ := doc.PeekCert(cert)
	r.kernelBurn(a.Session) // a resume on another image: the source it replaces ends (no-op for a new line)
	r.st.Do(func(d *persisted) {
		delete(d.Approvals, a.ID)
		if s := d.Sessions[a.Session]; s != nil {
			s.Kernel = &KernelLine{Source: c.Succ, SourceCert: &cert, SourceNz: &nz, Grant: &g}
		}
		if a.Origin != nil {
			noteOutcome(d, a.Origin, "new-session", a.Session, outcomeApproved, 0, &Doc{Payload: nz.Payload, Sig: nz.Sig})
		}
	})
	go func() {
		defer done()
		r.kernelSpawn(a.Session)
	}()
	return &Doc{Payload: nz.Payload, Sig: nz.Sig}, a.Session, nil
}

// kernelInitMax: how long a spawn waits for its machine's keys
var kernelInitMax, kernelInitStep = 10 * time.Minute, 2 * time.Second

// kernelSpawn: a machine from the line's source; the session runs on it once the grant is on it
func (r *Router) kernelSpawn(sid string) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	op := r.lcCurrent(sid)
	if op == nil {
		op = r.lcBegin(sid, "boot")
	}
	op.run.handed.Store(true)
	fail := func(msg string) {
		r.setState(sid, "failed", msg)
		op.note("", msg)
		op.endJoined("failed", msg)
	}
	l := s.Kernel
	if l == nil || l.SourceCert == nil || l.Grant == nil {
		fail("start: the line has no source")
		return
	}
	r.setState(sid, "starting", "")
	nzID, err := r.kernel.Identity("notarizer")
	if err != nil {
		fail("start: " + err.Error())
		return
	}
	size := s.Size
	if size == "" {
		size = "medium"
	}
	in := map[string]any{"cert": l.SourceCert, "notarized": l.SourceNz, "notarizer": nzID, "region": r.cfg.Region, "size": size, "diskGb": s.DiskGB}
	op.note("", "asked the kernel's spawner to start a machine from "+string(l.Source)+" ("+size+")")
	d, err := r.kernel.Doc("spawner", "/spawn", in)
	if err != nil {
		if strings.Contains(err.Error(), "no Fly token") && r.kernelTokenDMed.CompareAndSwap(false, true) {
			// a restarted spawner: its token comes again with the app's Recover of the kernel, or from the setup session
			r.DM("🔴 Jarvis 4 needs you — the kernel's spawner has no Fly token (it restarted), so no kernel session starts. Settings → Kernel → Recover gives it the token again (or the setup session: infra/setup.py kernel-fly-token).")
		}
		fail("start: " + err.Error())
		return
	}
	var created struct {
		ID     string `json:"id"`
		Volume string `json:"volume"`
		DiskGB int    `json:"diskGb"`
	}
	json.Unmarshal([]byte(d.Payload), &created)
	id := created.ID
	op.machine(id)
	pred := ""
	if sc, err := doc.PeekCert(*l.SourceCert); err == nil && sc.Pred.Kind() == "fly" {
		pred = sc.Pred.FlyID()
	}
	r.st.Do(func(d *persisted) {
		d.Machines[id] = sid
		d.Started[id] = &Started{ID: id, KernelPred: pred, Volume: &Volume{ID: created.Volume, SizeGB: created.DiskGB, Path: "/data"}}
	})
	var mcert sig.Doc
	for deadline := time.Now().Add(kernelInitMax); ; {
		mcert, err = r.kernel.Doc("spawner", "/init", map[string]string{"id": id})
		if err == nil {
			break
		}
		var ke *KernelError
		if !(errors.As(err, &ke) && (ke.Status == 409 || ke.Status == 502)) || time.Now().After(deadline) {
			r.kernel.Doc("spawner", "/kill", map[string]any{"id": id})
			fail("start: " + err.Error())
			return
		}
		time.Sleep(kernelInitStep)
	}
	mnz, err := r.kernel.Notarize(mcert)
	if err == nil {
		var g gv.Signed
		if g, err = r.kernel.Move(*l.Grant, mcert, mnz); err == nil {
			mc, _ := doc.PeekCert(mcert)
			r.st.Do(func(d *persisted) {
				d.Started[id].Image, d.Started[id].SigningKey, d.Started[id].EncryptionKey = mc.Machine.Image, mc.Machine.SigningKey, mc.Machine.EncryptionKey
				d.Started[id].KernelCert = &Doc{Payload: mcert.Payload, Sig: mcert.Sig}
				if x := d.Sessions[sid]; x != nil && x.Kernel != nil {
					x.Kernel.MachineCert, x.Kernel.MachineNz, x.Kernel.Grant = &mcert, &mnz, &g
					x.MachineID, x.Image, x.State, x.Error, x.PausedAt = id, mc.Machine.Image, "initialising", "", nil
				}
			})
		}
	}
	if err != nil {
		r.kernel.Doc("spawner", "/kill", map[string]any{"id": id})
		fail("start: " + err.Error())
		return
	}
	op.note(id, "the spawner's cert for "+id+" is notarized and the line's grant is on it; it boots now")
	go r.lcAwaitBoot(op, sid, id)
}

// kernelKill: the spawner kills the machine with its snapshot (required: keep it rather than lose its state), the
// cert into the new source is notarized and the grant moves onto it. The snapshot hash it names ("" = none).
// destroying: the line ends here, so the grant isn't moved (nothing takes it from the source, which the burn ends):
// a grant signed by a mover that has since restarted (new keys) no longer opens, and must not block a destroy; a
// repeat after the notarization went through finds the source already defined, which is the same outcome
func (r *Router) kernelKill(sid, machine string, required, destroying bool) (string, error) {
	in := map[string]any{"id": machine}
	if s := r.snap(machine); s != nil && s.State == "committed" {
		in["snapshot"] = map[string]any{"sha256": s.Sha256, "sig": s.Sig, "required": required}
	} else if required {
		in["snapshot"] = map[string]any{"required": true}
	}
	var d sig.Doc
	var err error
	for i := 0; ; i++ {
		d, err = r.kernel.Doc("spawner", "/kill", in)
		var ke *KernelError
		if err == nil || !(errors.As(err, &ke) && ke.Status == 409 && strings.Contains(ke.Msg, "not destroyed yet")) || i > 120 {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if err != nil {
		return "", err
	}
	c, perr := doc.PeekCert(d)
	if perr != nil { // a machine never up: a kill record, nothing goes on from it
		return "", nil
	}
	nz, err := r.kernel.Notarize(d)
	var ke *KernelError
	if destroying && err != nil && errors.As(err, &ke) && ke.Status == 409 && strings.Contains(ke.Msg, string(c.Succ)+" is already defined") {
		err = nil // an earlier try of this destroy notarized it (the spawner's kill cert, and its source id, are kept)
	}
	if err != nil {
		return "", fmt.Errorf("the kill's cert: %w", err)
	}
	if destroying {
		r.st.Do(func(dd *persisted) {
			if x := dd.Sessions[sid]; x != nil && x.Kernel != nil {
				x.Kernel.Source, x.Kernel.SourceCert, x.Kernel.Grant = c.Succ, &d, nil
				x.Kernel.SourceNz = nil
				if nz.Sig != "" {
					x.Kernel.SourceNz = &nz
				}
				x.Kernel.MachineCert, x.Kernel.MachineNz = nil, nil
			}
		})
		log.Printf("session %s: %s killed into %s for its destroy (snapshot %q)", sid, machine, c.Succ, c.Source.Snapshot)
		return c.Source.Snapshot, nil
	}
	var cur *gv.Signed
	r.st.Do(func(dd *persisted) {
		if x := dd.Sessions[sid]; x != nil && x.Kernel != nil {
			cur = x.Kernel.Grant
		}
	})
	if cur == nil {
		return "", errors.New("the line has no grant")
	}
	g, err := r.kernel.Move(*cur, d, nz)
	if err != nil {
		return "", fmt.Errorf("moving the grant onto %s: %w", c.Succ, err)
	}
	r.st.Do(func(dd *persisted) {
		if x := dd.Sessions[sid]; x != nil && x.Kernel != nil {
			x.Kernel.Source, x.Kernel.SourceCert, x.Kernel.SourceNz, x.Kernel.Grant = c.Succ, &d, &nz, &g
			x.Kernel.MachineCert, x.Kernel.MachineNz = nil, nil
		}
	})
	log.Printf("session %s: %s killed into %s (snapshot %q)", sid, machine, c.Succ, c.Source.Snapshot)
	return c.Source.Snapshot, nil
}

// kernelBurn: the line's source ends, (source, sink) by the gullible signer, notarized
func (r *Router) kernelBurn(sid string) error {
	var l *KernelLine
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			l = x.Kernel
		}
	})
	if l == nil || l.Burned || l.Source.Kind() != "source" {
		return nil
	}
	c, err := r.kernel.Doc("gullible", "/sign", map[string]any{"pred": l.Source, "succ": doc.Sink, "pair": perm.Top()})
	if err != nil {
		return err
	}
	if _, err := r.kernel.Notarize(c); err != nil {
		return err
	}
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil && x.Kernel != nil {
			x.Kernel.Burned = true
		}
	})
	return nil
}

// kernelBoot: what a kernel machine reads at boot (machine/kernelboot.go): its grant, the spawner's cert naming it,
// the cert into its source, each notarization, and the identities that check them
func (r *Router) kernelBoot(machine string) (map[string]any, error) {
	var l *KernelLine
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil && x.MachineID == machine {
			l = x.Kernel
		}
	})
	if l == nil || l.MachineCert == nil {
		return nil, errors.New("no kernel line for this machine yet")
	}
	out := map[string]any{"grant": l.Grant, "machineCert": l.MachineCert, "machineNotarized": l.MachineNz,
		"sourceCert": l.SourceCert, "sourceNotarized": l.SourceNz}
	// secrets' signed statements the machine reads the phone's key and the stores' sensitivity from (its phone
	// grants and message approvals, as a core cert's phone and sensitive fields)
	ks, _, err := r.kernel.Keys()
	if err != nil {
		return nil, err
	}
	sl, err := r.kernel.Doc("secrets", "/stores", map[string]string{"nonce": randID()})
	if err != nil {
		return nil, err
	}
	out["keys"], out["stores"] = ks, sl
	for _, role := range []string{"notary", "notarizer", "mover", "merger", "spawner", "secrets"} {
		id, err := r.kernel.Identity(role)
		if err != nil {
			return nil, err
		}
		out[role] = id
	}
	return out, nil
}

// kernelPull: the machine's secrets, from the kernel's secrets with the line's grant
func (r *Router) kernelPull(machine string) (*Doc, error) {
	var l *KernelLine
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil && x.MachineID == machine {
			l = x.Kernel
		}
	})
	if l == nil || l.Grant == nil {
		return nil, errors.New("no kernel line for this machine")
	}
	d, err := r.kernel.Doc("secrets", "/pull", l.Grant)
	if err != nil {
		var ke *KernelError
		if errors.As(err, &ke) {
			return nil, &CoreError{Status: ke.Status, Msg: ke.Msg}
		}
		return nil, err
	}
	return &Doc{Payload: d.Payload, Sig: d.Sig}, nil
}

// isKernelMachine: the machine is a kernel line's
func (r *Router) isKernelMachine(machine string) bool {
	k := false
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil {
			k = x.Kernel != nil
		}
	})
	return k
}

// kernelKillDone: snapsafe.go's kill for a kernel machine (after its final snapshot, or past a failed one with force)
func (r *Router) kernelKillDone(id, machine string, destroying bool, serr error, ok *bool) bool {
	r.lcNote(id, machine, "asked the kernel's spawner to kill the machine into the line's next source")
	snap, err := r.kernelKill(id, machine, !destroying && serr == nil, destroying)
	if err != nil {
		r.lcNote(id, machine, "the kill failed: "+err.Error())
		r.killFailed(id, machine, true, destroying, err)
		return false
	}
	r.st.Do(func(d *persisted) {
		s := d.Sessions[id]
		if s == nil {
			return
		}
		s.SnapshotFailed = ""
		if snap == "" && s.Booted == machine {
			why := "it sent none"
			if serr != nil {
				why = serr.Error()
			}
			s.NoSnapshot = fmt.Sprintf("machine %s left no snapshot (%s)", machine, why)
		} else {
			s.NoSnapshot = ""
		}
	})
	r.lcNote(id, machine, "the spawner confirmed the machine destroyed on Fly")
	*ok = true
	return true
}

// kernelResume: a kernel line's resume. A machine still there (a pause cut off) is paused first; then a spawn from the
// line's source, or, on another image (D8), the phone signs a new source with that image and the same settings and
// snapshot. A line whose first source the phone never signed gets its approval again.
func (r *Router) kernelResume(s Session, upgrade bool, unlock func(), op *lcHandle) error {
	id := s.ID
	r.setState(id, "resuming", "")
	go func() {
		defer unlock()
		defer op.endFromState()
		defer r.settleFollowups(id)
		if s.Lost != nil && s.MachineID == s.Lost.Machine && !upgrade { // lostmachine.go: it stopped outside Jarvis
			if r.kernelResumeLost(s, op) {
				return
			}
			r.st.Do(func(d *persisted) {
				if x := d.Sessions[id]; x != nil {
					s = *x
				}
			})
		}
		if s.MachineID != "" {
			op.machine(s.MachineID)
			op.note(s.MachineID, "finishing the machine's pause first")
			if !r.finalSnapshotAndKillNext(id, s.MachineID, nil) {
				return
			}
			now := time.Now().UTC()
			r.st.Do(func(d *persisted) {
				if x := d.Sessions[id]; x != nil {
					x.MachineID, x.PausedAt, x.Status = "", &now, ""
					s = *x
				}
			})
		}
		l := s.Kernel
		if l.SourceCert == nil || upgrade {
			config, err := r.sessionConfig(&s)
			if err != nil {
				r.setState(id, "failed", "resume: "+err.Error())
				return
			}
			snap := ""
			if l.SourceCert != nil {
				if c, err := doc.PeekCert(*l.SourceCert); err == nil {
					snap = c.Source.Snapshot
				}
			}
			draft, err := r.kernelSourceDraft(&s, config, r.cfg.SessionImage, snap)
			if err != nil {
				r.setState(id, "failed", "resume: "+err.Error())
				return
			}
			r.setState(id, "approval", "")
			r.addApproval(&Approval{Kind: kernelApprovalKind, Session: id, Label: s.Label, Challenge: &Doc{Payload: draft.Payload},
				Options: map[string]string{"permissionMode": normMode(s.PermissionMode), "image": r.cfg.SessionImage}, Again: l.SourceCert == nil})
			op.note("", "waiting for Deyao's approval in the Inbox: a new source on image "+r.cfg.SessionImage)
			return
		}
		r.kernelSpawn(id)
	}()
	return nil
}

// kernelContinue: a kernel line's start or resume whose job another replica held when it died, carried on from where
// the records say it is (every step is safe to repeat: the spawner answers a repeated spawn of a source with the
// machine it made for it, kernel/spawner; its keys, the notarization and the move come again):
//
//	resuming with its old machine still on it  → the pause first, then the spawn (as kernelResume)
//	starting / resuming with no machine         → the spawn from the kept source
//	initialising / started on the new machine  → nothing left but waiting for it to boot
func (r *Router) kernelContinue(sid string, unlock func()) {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[sid]; x != nil {
			s = *x
		}
	})
	op := r.lcBegin(sid, "boot")
	op.note("", "carried on by another router replica: its holder stopped")
	switch {
	case s.Kernel == nil || (s.Kernel.SourceCert == nil && s.State != "resuming"):
		unlock()
		op.endJoined("failed", "nothing to carry on")
		r.cutOffSession(sid)
	case s.State == "initialising" || s.State == "started":
		unlock()
		go r.lcAwaitBoot(op, sid, s.MachineID)
	case s.State == "resuming" && s.MachineID != "" && (s.Kernel.MachineCert == nil || doc.Object("fly-"+s.MachineID) != mustSucc(s.Kernel.MachineCert)):
		r.kernelResume(s, false, unlock, op)
	default:
		go func() {
			defer unlock()
			r.kernelSpawn(sid)
		}()
	}
}

func mustSucc(d *sig.Doc) doc.Object {
	c, _ := doc.PeekCert(*d)
	return c.Succ
}

// registerKernel: the app's side of the kernel
//
//	GET  /api/kernel                    {configured, core, serves, root, roster}: whether this box has a kernel, whether
//	                                    it also runs the old core (NO_CORE=1: no; the app's first launch then sets up
//	                                    the kernel, never the core), whether new
//	                                    sessions start on it, whether the root's grant is here, and the roster's
//	                                    state (roster.go: none, pending, current, stale + "roster stale: component X
//	                                    restarted" per component that refused it), and its health (kernelhealth.go)
//	GET  /api/kernel/root-grant/draft   {payload}: what the root key signs
//	POST /api/kernel/root-grant         {grant}: the root key's ⊤ on the sink (the app signs it once, after
//	                                    secrets' claim, behind the root key's own warning screen); kept, passed on
//	GET|POST /api/kernel/secrets/{path} secrets' own API, relayed as is (claim, identity, unlock, lock, …):
//	                                    every answer is signed by secrets, which the app checks
func (r *Router) registerKernel(app func(string, http.HandlerFunc)) {
	app("GET /api/kernel", func(w http.ResponseWriter, req *http.Request) {
		root := false
		r.st.Do(func(d *persisted) { root = d.KernelRoot != nil })
		writeJSON(w, 200, map[string]any{"configured": r.kernel != nil, "core": !r.cfg.NoCore, "serves": r.kernelServes(), "root": root, "roster": r.rosterStatus(),
			"health": r.kernelHealthView()})
	})
	// the grant the root key signs once: ⊤ on the sink with the sink's keys (hashed from its name: the app can't
	// compute them; a draft naming other keys is refused by every component that takes the grant)
	app("GET /api/kernel/root-grant/draft", func(w http.ResponseWriter, req *http.Request) {
		ik, _ := doc.IdealKeys(doc.Sink)
		b, _ := json.Marshal(doc.Grant{Kind: "grant", Machine: doc.Sink, Keys: ik, Pair: perm.Top(), From: []string{}, At: doc.Now()})
		writeJSON(w, 200, map[string]string{"payload": string(b)})
	})
	app("POST /api/kernel/root-grant", func(w http.ResponseWriter, req *http.Request) {
		var in struct {
			Grant sig.Doc `json:"grant"`
		}
		if json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&in) != nil {
			writeJSON(w, 400, map[string]string{"error": "{grant}"})
			return
		}
		var g doc.Grant
		if r.kernel == nil || sig.StrictJSON([]byte(in.Grant.Payload), &g) != nil || g.Machine != doc.Sink || !perm.Top().Leq(g.Pair) {
			writeJSON(w, 400, map[string]string{"error": "not the root's ⊤ on the sink (or no kernel here)"})
			return
		}
		// checked the way the mover will check it: signed by the root key secrets names
		ks, sid, err := r.kernel.Keys()
		if err != nil {
			writeErr(w, err)
			return
		}
		s := gv.Signed{Grant: in.Grant, By: "root", Keys: &ks, Secrets: &sid}
		var k struct{ Root string }
		json.Unmarshal([]byte(ks.Payload), &k)
		if !sig.Verify(k.Root, []byte(in.Grant.Payload), in.Grant.Sig) {
			writeJSON(w, 403, map[string]string{"error": "not signed by the root key secrets holds"})
			return
		}
		s.Keys, s.Secrets = nil, nil // the mover gets secrets' current statement with every move
		r.st.Do(func(d *persisted) { d.KernelRoot = &s })
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	relay := func(w http.ResponseWriter, req *http.Request) {
		if r.kernel == nil {
			writeJSON(w, 503, map[string]string{"error": "this box runs no kernel yet"})
			return
		}
		path := "/" + req.PathValue("path")
		role := "secrets"
		if req.URL.Query().Get("secrets") == "next" { // the next secrets (blue/green, kernel.go): Recover alongside
			role = "secrets-next"
		}
		var body any
		if req.Method == "POST" {
			var raw json.RawMessage
			if json.NewDecoder(io.LimitReader(req.Body, 4<<20)).Decode(&raw) != nil {
				raw = json.RawMessage("{}")
			}
			body = raw
		}
		b, err := r.kernel.call(role, req.Method, path, body)
		if err != nil {
			var ke *KernelError
			if errors.As(err, &ke) {
				writeJSON(w, ke.Status, map[string]string{"error": ke.Msg})
				return
			}
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
	// the spawner's Fly token from the app's Recover (the kit opens the core store's backup): sealed to the spawner's
	// box-vouched key, which the app checks; relayed as is
	app("GET /api/kernel/spawner/identity", func(w http.ResponseWriter, req *http.Request) {
		if r.kernel == nil {
			writeJSON(w, 503, map[string]string{"error": "this box runs no kernel yet"})
			return
		}
		b, err := r.kernel.call("spawner", "GET", "/identity", nil)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
	app("POST /api/kernel/spawner/fly-token", func(w http.ResponseWriter, req *http.Request) {
		var in json.RawMessage
		if r.kernel == nil || json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&in) != nil {
			writeJSON(w, 400, map[string]string{"error": "{sealed}, on a box with a kernel"})
			return
		}
		b, err := r.kernel.call("spawner", "POST", "/fly-token", in)
		if err != nil {
			var ke *KernelError
			if errors.As(err, &ke) {
				writeJSON(w, ke.Status, map[string]string{"error": ke.Msg})
				return
			}
			writeErr(w, err)
			return
		}
		r.kernelTokenDMed.Store(false)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
	app("GET /api/kernel/secrets/{path...}", relay)
	app("POST /api/kernel/secrets/{path...}", relay)
}

// hasLine: the session has a certified line: a core cert, or a kernel source the phone signed
func (s *Session) hasLine() bool {
	return s.Cert != nil || s.Kernel != nil && s.Kernel.SourceCert != nil
}

// attestInput: an input's entry in the log before it reaches a machine: the old core's input log, or, for a kernel
// machine, the log notary's challenge over (its object, the kind, the input's sha256) (machine/kernelboot.go
// KernelInputSubject)
func (r *Router) attestInput(machine, kind, origin, sum string) (*Doc, error) {
	if !r.isKernelMachine(machine) {
		a, err := r.core.Call("/attest", map[string]string{"machine": machine, "input": kind, "origin": origin, "sha256": sum})
		if err == nil {
			r.logInputs(a)
		}
		return a, err
	}
	h := sha256.Sum256([]byte("jarvis2-input\n" + "fly-" + machine + "\n" + kind + "\n" + sum))
	d, err := r.kernel.Doc("notary", "/challenge", map[string]string{"subject": hex.EncodeToString(h[:]), "about": "input"})
	if err != nil {
		return nil, err
	}
	return &Doc{Payload: d.Payload, Sig: d.Sig}, nil
}

// sessionLine: the line id a phone grant names: a core line's first machine (its cert's line), a kernel line's session
// id (its grant's session: condition, which the machine reads as its line)
func sessionLine(s *Session) string {
	if s.Kernel != nil {
		return s.ID
	}
	return certField(s.Cert, "line")
}

// kernelDowngrade: the machine keeps only these stores: the identity signer's (fly-M, fly-M, P), P the kept stores
// for the session, notarized; the main grant moves along it (a move only narrows); the machine pulls again
func (r *Router) kernelDowngrade(machine string, keep []string) error {
	var s Session
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[d.Machines[machine]]; x != nil && x.MachineID == machine {
			s = *x
		}
	})
	if s.Kernel == nil || s.Kernel.Grant == nil {
		return errors.New("this machine isn't a running kernel line")
	}
	allowed := []string{}
	for _, st := range keep {
		allowed = append(allowed, "store:"+st)
	}
	p := perm.Pair{Allowed: perm.Only(allowed...), Conditions: []string{"session:" + s.ID}}
	c, err := r.kernel.Doc("identity", "/sign", map[string]any{"machine": "fly-" + machine, "pair": p})
	if err != nil {
		return err
	}
	nz, err := r.kernel.Notarize(c)
	if err != nil {
		return err
	}
	g, err := r.kernel.Move(*s.Kernel.Grant, c, nz)
	if err != nil {
		return err
	}
	r.st.Do(func(d *persisted) {
		if x := d.Sessions[s.ID]; x != nil && x.Kernel != nil && x.MachineID == machine {
			x.Kernel.Grant, x.Stores = &g, keep
		}
	})
	return nil
}

// kernelAddApprovalKind: an add-store on a kernel line: the phone signs two certs under one Face ID, the cert into a
// new source holding the store (sink → source-a, P_add = the store for the session) and the cert from it onto the
// running machine (source-a → fly-M, ⊤); the answer is the two signatures, one per line, in that order
const kernelAddApprovalKind = "kernel-add-store"

func (r *Router) kernelAddStoreApproval(s Session, store string, o Origin, explanation, batch string) (string, error) {
	l := s.Kernel
	if l == nil || l.MachineCert == nil || l.SourceCert == nil {
		return "", errors.New("this machine isn't a running kernel line")
	}
	mc, err := doc.PeekCert(*l.MachineCert)
	if err != nil {
		return "", err
	}
	sc, err := doc.PeekCert(*l.SourceCert)
	if err != nil {
		return "", err
	}
	b := make([]byte, 16)
	rand.Read(b)
	add := doc.NewSource(b)
	src := *sc.Source
	src.Snapshot = ""
	c1 := doc.Cert{Kind: "succession", Pred: doc.Sink, Succ: add, Pair: perm.Pair{Allowed: perm.Only("store:" + store), Conditions: []string{"session:" + s.ID}},
		Source: &src, Signer: doc.ByIPhone, IssuedAt: doc.Now()}
	c2 := doc.Cert{Kind: "succession", Pred: add, Succ: mc.Succ, Pair: perm.Top(), Machine: mc.Machine, Signer: doc.ByIPhone, IssuedAt: doc.Now()}
	if err := c1.Check(); err != nil {
		return "", err
	}
	if err := c2.Check(); err != nil {
		return "", err
	}
	p1, _ := json.Marshal(c1)
	p2, _ := json.Marshal(c2)
	a := &Approval{Kind: kernelAddApprovalKind, Session: s.ID, Machine: s.MachineID, Label: s.Label, Challenge: &Doc{Payload: string(p1)},
		Earlier: []*Doc{{Payload: string(p2)}}, Options: map[string]string{"store": store}, Origin: &o, Explanation: explanation, Batch: batch}
	r.addApproval(a)
	return a.ID, nil
}

// respondKernelAdd: the two signatures → the store's grant moved onto the machine and merged with the main grant
// (both carry exactly session:<id>), then the machine pulls again
func (r *Router) respondKernelAdd(a *Approval, signatures string) (*Doc, string, error) {
	sigs := strings.Fields(signatures)
	if len(sigs) != 2 || len(a.Earlier) != 1 {
		return nil, "", errors.New("an add-store on a kernel line takes two signatures (one per line)")
	}
	c1 := sig.Doc{Payload: a.Challenge.Payload, Sig: sigs[0]}
	c2 := sig.Doc{Payload: a.Earlier[0].Payload, Sig: sigs[1]}
	var root, main *gv.Signed
	r.st.Do(func(d *persisted) {
		root = d.KernelRoot
		if s := d.Sessions[a.Session]; s != nil && s.Kernel != nil && s.MachineID == a.Machine {
			main = s.Kernel.Grant
		}
	})
	if root == nil || main == nil {
		return nil, "", errors.New("the machine isn't running on the kernel any more")
	}
	nz1, err := r.kernel.Notarize(c1)
	if err != nil {
		return nil, "", err
	}
	g, err := r.kernel.Move(*root, c1, nz1)
	if err != nil {
		return nil, "", err
	}
	nz2, err := r.kernel.Notarize(c2)
	if err != nil {
		return nil, "", err
	}
	if g, err = r.kernel.Move(g, c2, nz2); err != nil {
		return nil, "", err
	}
	mid, err := r.kernel.Identity("merger")
	if err != nil {
		return nil, "", err
	}
	md, err := r.kernel.Doc("merger", "/merge", map[string]any{"a": main, "b": g})
	if err != nil {
		return nil, "", err
	}
	merged := gv.Signed{Grant: md, By: "merger", Signer: &mid}
	store := a.Options["store"]
	r.st.Do(func(d *persisted) {
		delete(d.Approvals, a.ID)
		if s := d.Sessions[a.Session]; s != nil && s.Kernel != nil && s.MachineID == a.Machine {
			s.Kernel.Grant = &merged
			if !slices.Contains(s.Stores, store) {
				s.Stores = append(s.Stores, store)
				slices.Sort(s.Stores)
			}
		}
		if a.Origin != nil {
			noteOutcome(d, a.Origin, "add-store", a.Session, outcomeApproved, 0, &Doc{Payload: nz2.Payload, Sig: nz2.Sig})
		}
	})
	r.send(a.Machine, "refresh-secrets")
	return &Doc{Payload: md.Payload, Sig: md.Sig}, a.Session, nil
}
