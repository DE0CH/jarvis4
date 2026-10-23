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
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	CoreURL         string            // the core, inside the cluster
	NoCore          bool              // NO_CORE=1: this box runs no core, only the kernel (Jarvis 4); GET /api/kernel says so
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
	if len(os.Args) > 1 && os.Args[1] == "m-gateway" {
		mGatewayCommand() // mgateway.go: the machines' WireGuard peer, in its own Deployment
		return
	}
	stall, _ := strconv.Atoi(env("SNAPSHOT_STALL_SECONDS", "600"))
	cfg := Config{
		CoreURL:         env("CORE_URL", "http://core.jarvis2-core.svc.cluster.local:8090"),
		KernelURL:       os.Getenv("KERNEL_URL"),
		NoCore:          os.Getenv("NO_CORE") == "1",
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
	if os.Getenv("WG_CONFIG") != "" {
		log.Fatal("WG_CONFIG: the machines' WireGuard peer runs in m-gateway (`router m-gateway`), not in the router")
	}
	addr, maddr := env("ADDR", ":8080"), env("MACHINE_ADDR", ":8081")
	coreClient := &CoreClient{base: cfg.CoreURL, http: &http.Client{}} // each core call has its own deadline (core.go coreCallTimeout)
	seal, err := sealerFromEnv()                                       // sealed.go
	if err != nil {
		log.Fatal(err)
	}
	st, err := OpenState(context.Background(), db, cfg.DataDir, seal) // statedb.go
	if err != nil {
		log.Fatal(err)
	}
	policy, err := LoadPolicy(env("POLICY_FILE", "/policy/stores.json"))
	if err != nil {
		log.Fatal(err)
	}
	r := NewRouter(cfg, st, coreClient, policy)
	r.db.Store(db)
	if err := r.probeObjects(); err != nil {
		log.Fatal("objects: ", err)
	}
	r.applyActiveCore() // nextcore.go: the core a flip left serving
	r.startFeatures()
	r.leaseOnce()                            // leaderlease.go: the scheduler's lease (one replica runs the loops)
	go r.leaseLoopScheduler()                // and kept
	go r.mqSweepLoop()                       // mq.go: the machines' queue rows older than a day
	go r.jobsLoop(5 * time.Second)           // jobs.go: a job whose holder died is carried on here
	go r.rosterLoop(time.Minute)             // roster.go: a restarted component gets the roster again, or it is stale
	go r.kernelHealthLoop(kernelHealthEvery) // kernelhealth.go: what the app warns about on a box with no core
	drainMax, _ := strconv.Atoi(env("DRAIN_SECONDS", "1740"))
	go r.nextCoreLoop(30*time.Second, time.Duration(drainMax)*time.Second)
	// two listeners, both in the pod network: the public one (cloudflared → app, web, setup; GET /readyz for the
	// probe) and the machines' one (only m-gateway reaches it, mgateway.go). Every replica serves both: the records are
	// in Postgres, the machines' queue too (mq.go), the jobs carry on anywhere (jobs.go).
	var stopping atomic.Bool
	public := http.NewServeMux()
	public.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if stopping.Load() {
			writeJSON(w, 503, map[string]string{"state": "stopping"})
			return
		}
		writeJSON(w, 200, map[string]string{"state": "serving"})
	})
	public.Handle("/", r.Handler())
	pubSrv := &http.Server{Addr: addr, Handler: public}
	mSrv := &http.Server{Addr: maddr, Handler: r.MachineHandler()}
	go func() {
		if err := pubSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := mSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	log.Printf("router %s on %s and %s (core %s)", routerID, addr, maddr, coreClient.URL())
	// SIGTERM (a rollout, a node drain): this replica leaves the Service (readyz 503), hands the scheduler's lease on,
	// lets its running jobs end (up to JOB_GRACE_SECONDS, under the pod's terminationGracePeriodSeconds: a job still
	// running then is carried on by another replica once its lease lapses, jobs.go), lets a Claude login refresh in
	// flight finish, then closes its listeners (a long poll ends; the machine polls again, through the gateway, on
	// another replica).
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	stopping.Store(true)
	log.Printf("stopping: out of the Service, the scheduler's lease handed on, waiting for this replica's jobs")
	r.releaseLead()
	time.Sleep(5 * time.Second) // the readiness probe sees it first
	grace, _ := strconv.Atoi(env("JOB_GRACE_SECONDS", "1740"))
	for end := time.Now().Add(time.Duration(grace) * time.Second); time.Now().Before(end) && r.myRunningJobs() > 0; {
		time.Sleep(time.Second)
	}
	if n := r.myRunningJobs(); n > 0 {
		log.Printf("stopping with %d job(s) running: another replica carries them on once their lease lapses", n)
	}
	r.drainLogins(20 * time.Second)
	if r.lines != nil {
		r.lines.flush() // linestate.go: the newest line state into the bucket before the router goes
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mSrv.Shutdown(ctx)
	pubSrv.Shutdown(ctx)
	log.Printf("stopped")
}
