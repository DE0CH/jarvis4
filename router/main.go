// The Jarvis 4 router (docs/API.md): chains the core's primitives into sessions and serves the app, the web
// page and the session machines. It is untrusted by design (docs/DESIGN.md): a
// bug here can fail or stall an action, but every document that matters is signed by the core or the
// iPhone and checked at the far end, so it can't move a store to a machine nobody approved.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type Config struct {
	CoreURL         string            // the core, inside the cluster
	KernelURL       string            // the kernel's components, %s = the role (KERNEL_URL; "" = no kernel on this box)
	DataDir         string            // snapshots and the other files (a volume); the records are in Postgres (statedb.go)
	WebDir          string            // the web page (expo export), served at /
	SessionImage    string            // the image new sessions get (a tag; resume pins what Fly reported)
	SessionImageSig string            // CI's signature over it (images.yml; keys/ci.pub)
	ImageSigs       map[string]string // every earlier CI-pinned session image → its signature (SESSION_IMAGE_SIGS_FILE)
	ImageOrder      []string          // the same images in pin order (the file's line order)
	Region          string            // Fly region for session machines
	MachineURL      string            // how machines reach the router (JARVIS2_URL on the machine): its Fly private-network address
	AccessTeam      string            // e.g. de0ch.cloudflareaccess.com
	AppAUD          string            // the Access app audience for /api and /
	SetupAUD        string            // the Access app audience for /setup (service token jarvis2-setup)
	SetupKey        string            // the setup session's public key: it signs every /setup call
	AllowedEmail    string            // the only person
	NoAccess        bool              // CI only: no Cloudflare in front, skip the JWT checks
	SnapshotStall   time.Duration     // snapwait.go: a pause stops waiting for the machine's snapshot after this long with no progress
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "restore-backup" {
		restoreCommand(os.Args[2:]) // backup.go
		return
	}
	stall, _ := strconv.Atoi(env("SNAPSHOT_STALL_SECONDS", "600"))
	cfg := Config{
		CoreURL:         env("CORE_URL", "http://core.jarvis2-core.svc.cluster.local:8090"),
		KernelURL:       os.Getenv("KERNEL_URL"),
		DataDir:         env("DATA_DIR", "/data"),
		WebDir:          env("WEB_DIR", "/web"),
		SessionImage:    env("SESSION_IMAGE", "ghcr.io/de0ch/jarvis4-session:latest"),
		SessionImageSig: os.Getenv("SESSION_IMAGE_SIG"),
		ImageSigs:       loadImageSigs(os.Getenv("SESSION_IMAGE_SIGS_FILE")),
		ImageOrder:      loadImageOrder(os.Getenv("SESSION_IMAGE_SIGS_FILE")),
		Region:          env("FLY_REGION", "lhr"),
		MachineURL:      os.Getenv("MACHINE_URL"),
		AccessTeam:      env("ACCESS_TEAM", "de0ch.cloudflareaccess.com"),
		AppAUD:          os.Getenv("ACCESS_APP_AUD"),
		SetupAUD:        os.Getenv("ACCESS_SETUP_AUD"),
		SetupKey:        os.Getenv("SETUP_KEY"),
		AllowedEmail:    env("ALLOWED_EMAIL", "chendeyao000@gmail.com"),
		NoAccess:        os.Getenv("NO_ACCESS") == "1",
		SnapshotStall:   time.Duration(stall) * time.Second,
	}
	if cfg.NoAccess {
		log.Printf("NO_ACCESS=1: Cloudflare Access checks are OFF (CI only)")
	} else if cfg.AppAUD == "" || cfg.SetupAUD == "" {
		log.Fatal("ACCESS_APP_AUD and ACCESS_SETUP_AUD are required (or NO_ACCESS=1 in CI)")
	}
	if cfg.MachineURL == "" {
		log.Printf("MACHINE_URL unset: machines will have no router address")
	}
	// the records are in Postgres (statedb.go): the database first, before this pod listens or stands by, so a pod that
	// can't reach it (a wrong password, the database down) never becomes ready or takes over from a working leader
	if os.Getenv("DATABASE_URL") == "" {
		log.Fatal("DATABASE_URL is required: the router's records are in Postgres (docs/STATE.md)")
	}
	db := openDBWait(os.Getenv("DATABASE_URL"))
	// the blobs are in object storage (objstore.go); only a throwaway router (CI's stand-ins, e2e) keeps them in memory
	if os.Getenv("OBJECTS_ACCESS_KEY") == "" && os.Getenv("ROUTER_THROWAWAY") != "1" {
		log.Fatal("OBJECTS_ACCESS_KEY / OBJECTS_SECRET_KEY are required (Secret router-secrets-objects), or ROUTER_THROWAWAY=1 for a throwaway router")
	}
	// leader.go: one router process owns the state; a rollout's new pod waits as a standby that proxies to it
	addr, maddr := env("ADDR", ":8080"), env("MACHINE_ADDR", ":8081")
	lock, err := openLeaderLock(cfg.DataDir)
	if err != nil {
		log.Fatal(err)
	}
	self := selfURL(addr)
	public := &swapHandler{}
	listening := false
	listen := func() {
		if !listening {
			listening = true
			go func() { log.Fatal(http.ListenAndServe(addr, public)) }()
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	// move.go: this box's router moved to another box: only a proxy to it, whoever holds the lock
	proxyOnly := func(to string) {
		log.Printf("[move] this router moved to %s: proxying everything there, no state loaded", to)
		public.set(proxyTo(self, to))
		listen()
		<-sig
		time.Sleep(time.Duration(handoverLingerSeconds()) * time.Second)
		os.Exit(0)
	}
	if to := movedTo(cfg.DataDir); to != "" {
		proxyOnly(to)
	}
	// move.go: the move listener (old box, MOVE_KEY) from the start, on every pod: a standby passes the calls on to the
	// leader's, so one Service with both ports may select every router pod
	moveListener := &swapHandler{}
	if os.Getenv("MOVE_KEY") != "" && os.Getenv("MOVE_FROM") == "" {
		moveListener.set(moveLeaderProxy(lock, self))
		go func() { log.Fatal(http.ListenAndServe(env("MOVE_ADDR", ":8082"), moveListener)) }()
	}
	standby := !lock.tryLock()
	if standby {
		// listening (and so ready: a TCP probe) at once, every request proxied to the leader
		log.Printf("standby: another router leads (%s); proxying to it until it hands over", lock.leaderAddr())
		public.set(newLeaderProxy(lock, self, public))
		listen()
	}
	// a standby stopped before it leads (a rollout replaced again) just goes
	got := make(chan error, 1)
	go func() { got <- lock.lock() }() // immediate for the leader (flock is re-entrant per open file)
	select {
	case err := <-got:
		if err != nil {
			log.Fatal(err)
		}
	case <-sig:
		log.Printf("standby stopped before leading")
		os.Exit(0)
	}
	if to := movedTo(cfg.DataDir); to != "" {
		proxyOnly(to) // the leader that moved is gone, its lock with it: this pod stays a proxy too
	}
	coreClient := &CoreClient{base: cfg.CoreURL, http: &http.Client{}} // each core call has its own deadline (core.go coreCallTimeout)
	// move.go: the new box's router copies the old one's /data and proxies to it until it moves
	joiner := moveJoinerFromEnv(cfg.DataDir)
	if joiner != nil {
		joiner.handoff, joiner.core = httpHandoff{}, coreClient
		joiner.serveWG = func(path string, h http.Handler) (*wgServer, error) { return serveWG(path, 8081, h) }
		listen()
		if !joiner.candidate(lock, self, public, sig) {
			time.Sleep(time.Duration(handoverLingerSeconds()) * time.Second)
			os.Exit(0)
		}
	}
	maybeRestore(cfg.DataDir) // backup.go: a rebuilt box (ROUTER_RESTORE=1)
	// the machines' peer comes up first, before the state loads: a handover's gap for the machines is then only the time
	// between the old peer going and this one's handshake (wg.go); its requests wait in the holding handler meanwhile
	var earlyPeer *wgServer
	var earlyHold *holdHandler
	if joiner == nil {
		if p := wgConfigPath(cfg.DataDir); p != "" {
			earlyHold = newHoldHandler()
			peer, err := serveWG(p, 8081, earlyHold)
			if err != nil {
				log.Fatal(err)
			}
			earlyPeer = peer
		}
	}

	// the first start against an empty database imports state.json (statedb.go)
	seal, err := sealerFromEnv() // sealed.go
	if err != nil {
		log.Fatal(err)
	}
	st, err := OpenState(context.Background(), db, cfg.DataDir, seal) // after the lock: the previous leader's last writes
	if err != nil {
		log.Fatal(err)
	}
	policy, err := LoadPolicy(env("POLICY_FILE", "/policy/stores.json"))
	if err != nil {
		log.Fatal(err)
	}
	r := NewRouter(cfg, st, coreClient, policy)
	r.db.Store(db)
	if err := r.importBlobFiles(); err != nil { // objstore.go: the volume's uploads and task runs, once
		log.Fatal(err)
	}
	if err := r.probeObjects(); err != nil {
		log.Fatal("objects: ", err)
	}
	r.applyActiveCore() // nextcore.go: the core a flip left serving
	r.startFeatures()
	r.startStateBackups()
	drainMax, _ := strconv.Atoi(env("DRAIN_SECONDS", "1740"))
	go r.rosterLoop(time.Minute) // roster.go: a restarted component gets the roster again, or it is stale
	go r.nextCoreLoop(30*time.Second, time.Duration(drainMax)*time.Second)
	ld := &leadership{lock: lock, self: self, handler: public}
	log.Printf("router on %s (core %s), leader at %s", addr, coreClient.URL(), self)
	// two listeners: the public one (cloudflared → app, web, setup) and the machines' one, which only
	// Fly's private network reaches (the WireGuard peer); /m exists only on the second. The peer that came with a
	// move (/data/wg.conf) wins over the box's own (move.go).
	wgPath := wgConfigPath(cfg.DataDir)
	var startWG func() (stop, quiesce func(), err error)
	if joiner != nil && joiner.peer != nil {
		// move.go: the moved peer is up already, holding the machines' requests; from now on they are served
		ld.stopWG, ld.quiesce, ld.prepare = joiner.peer.Stop, joiner.peer.Quiesce, joiner.peer.Prepare
		startWG = func() (func(), func(), error) {
			p, err := serveWG(wgPath, 8081, r.MachineHandler())
			if err != nil {
				return nil, nil, err
			}
			return p.Stop, p.Quiesce, nil
		}
		joiner.machine.serve(r.MachineHandler())
		log.Printf("machines: the moved WireGuard peer (%s) serves, port 8081", wgPath)
	} else if wgPath != "" {
		// production: only on the Fly private network (wg.go)
		startWG = func() (func(), func(), error) {
			p, err := serveWG(wgPath, 8081, r.MachineHandler())
			if err != nil {
				return nil, nil, err
			}
			return p.Stop, p.Quiesce, nil
		}
		ld.stopWG, ld.quiesce, ld.prepare = earlyPeer.Stop, earlyPeer.Quiesce, earlyPeer.Prepare
		earlyHold.serve(r.MachineHandler())
		log.Printf("machines: WireGuard peer from %s, port 8081", wgPath)
	} else {
		go func() { log.Fatal(http.ListenAndServe(maddr, r.MachineHandler())) }()
	}
	public.set(r.Handler())
	listen() // the first leader listens once it serves (ready from here)
	lock.setAddr(self)
	if joiner != nil {
		joiner.finish() // move.go: the old box proxies here from now on
	}
	// move.go: the old box's side of a move (only with MOVE_KEY)
	var sender *moveSender
	if key := os.Getenv("MOVE_KEY"); key != "" && joiner == nil {
		sender = &moveSender{r: r, st: st, ld: ld, lock: lock, self: self, public: public, dir: cfg.DataDir, key: key,
			wgPath: wgPath, startWG: startWG, drain: time.Duration(drainMax) * time.Second, handoff: httpHandoff{}}
		setMove(func(m *moveStatus) { m.Role, m.Phase = "sender", "serving" })
		moveListener.set(sender.Handler())
	}
	// SIGTERM (a rollout): drain (drain.go): new lifecycle actions get 503 "router updating, try again shortly", the
	// running ones finish, while both listeners keep serving reads, the machines' reports and the login's long
	// polls (directly, and through the next pod's standby proxy). Then a Claude login refresh in flight is let
	// finish, so its answer reaches the volume (the old refresh token is dead the moment the token endpoint answers).
	// Then the handover (leader.go): the next pod leads, and what still reaches this one is proxied there.
	// DRAIN_SECONDS stays under the pod's terminationGracePeriodSeconds (k8s/control/apps/router/router.yaml).
	<-sig
	if sender != nil && sender.moved() {
		time.Sleep(time.Duration(handoverLingerSeconds()) * time.Second)
		os.Exit(0) // moved: the state stays frozen, the lock is released by the exit (the next pod sees router.moved)
	}
	if sender != nil {
		sender.abort() // a frozen move that never finished: serve again for the drain below
	}
	prepared := time.Now()
	if ld.prepare != nil {
		ld.prepare() // wg.go: the machines' connections become one-shot while this router still serves
	}
	r.Drain(time.Duration(drainMax) * time.Second)
	r.BackupState("drain")
	r.drainLogins(20 * time.Second)
	if r.lines != nil {
		r.lines.flush() // linestate.go: the newest line state into the bucket before the router goes
	}
	if ld.prepare != nil {
		time.Sleep(time.Until(prepared.Add(oneShotLead))) // move.go: pooled machine connections closed cleanly first
	}
	// movegate.go: deliveries in flight finish here, long polls end at once (an unanswered GET goes to the next leader)
	r.stopDeliveries(90 * time.Second)
	public.set(newLeaderProxy(lock, self, nil))
	if ld.quiesce != nil {
		ld.quiesce() // wg.go: the machines' next dials wait for the next leader's peer
	}
	r.freezeRequests(newLeaderProxy(lock, self, nil), 10*time.Second)
	ld.handOver(st)
	time.Sleep(time.Duration(handoverLingerSeconds()) * time.Second)
	os.Exit(0)
}

// handoverLingerSeconds: how long a pod that handed over keeps proxying what still reaches it (cloudflared's kept-alive
// connections) before it exits
func handoverLingerSeconds() int {
	n, _ := strconv.Atoi(env("HANDOVER_LINGER_SECONDS", "15"))
	return n
}
