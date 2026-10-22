package main

// The machines' gateway (docs/STATE.md 5, step 9): `router m-gateway` runs the Fly org's WireGuard peer (the address
// the machines know: KERNEL_MACHINE_URL / MACHINE_URL, http://<peer>._peer.internal:8081) and passes every request it
// takes there to the router's machines' port (M_GATEWAY_TO, the router Service's :8081), streamed both ways (snapshot
// uploads, long polls). It holds no state and checks nothing: every /m request is signed by the machine's key and the
// router checks it, on whichever replica the Service picks. The router's rollouts never touch the peer.
//
//	WG_CONFIG      the peer's wg.conf (Secret router-wg)
//	M_GATEWAY_TO   e.g. http://router.jarvis4-router.svc.cluster.local:8081
//	HEALTH_ADDR    :8080 by default: GET /healthz answers once the peer is up (the pod's readiness)

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func mGatewayCommand() {
	to, err := url.Parse(os.Getenv("M_GATEWAY_TO"))
	if err != nil || to.Host == "" {
		log.Fatal("M_GATEWAY_TO: the router's machines' URL, e.g. http://router.jarvis4-router.svc.cluster.local:8081")
	}
	path := os.Getenv("WG_CONFIG")
	if path == "" {
		log.Fatal("WG_CONFIG: the peer's wg.conf")
	}
	peer, err := serveWG(path, 8081, mGatewayProxy(to))
	if err != nil {
		log.Fatal("m-gateway: ", err)
	}
	log.Printf("m-gateway: the WireGuard peer from %s serves port 8081, passed on to %s", path, to)
	h := http.NewServeMux()
	h.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	go func() { log.Fatal(http.ListenAndServe(env("HEALTH_ADDR", ":8080"), h)) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	// the machines' pooled connections close cleanly, then the peer goes (the next gateway pod takes the address)
	peer.Prepare()
	time.Sleep(5 * time.Second)
	peer.Stop()
	log.Printf("m-gateway: stopped")
}

// mGatewayProxy: every request passed on to the router's machines' port as it is, streamed both ways
func mGatewayProxy(to *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(to)
	proxy.FlushInterval = -1 // a long poll's answer and a stream's bytes go through at once
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		log.Printf("m-gateway: %s %s: %v", req.Method, req.URL.Path, err)
		writeJSON(w, 502, map[string]string{"error": "the router can't be reached from the gateway: try again"})
	}
	return proxy
}
