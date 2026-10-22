package main

// The machines' gateway (docs/STATE.md 5, step 9): `router m-gateway` runs the Fly org's WireGuard peer (the address
// the machines know: KERNEL_MACHINE_URL / MACHINE_URL, http://<peer>._peer.internal:8081) and passes every request it
// takes there to the router's machines' port (M_GATEWAY_TO, the router Service's :8081), streamed both ways (snapshot
// uploads, long polls). It holds no state and checks nothing: every /m request is signed by the machine's key and the
// router checks it, on whichever replica the Service picks. The router's rollouts never touch the peer.
//
//	WG_CONFIGS     the peers' wg.conf files, comma-separated; the pod's ordinal (POD_NAME m-gateway-<n>, a StatefulSet)
//	               picks the n-th: two gateways, two peers (jarvis4-box, jarvis4-gw-b), replaced one at a time
//	M_GATEWAY_TO   e.g. http://router.jarvis4-router.svc.cluster.local:8081
//	HEALTH_ADDR    :8080 by default: GET /healthz answers once the peer is up (the pod's readiness)
//
// SIGTERM: no new connection (the machines' dials go to the other gateway, machine/routerdial.go), the requests it
// carries end (up to M_GATEWAY_GRACE_SECONDS), then the peer goes. A rollout replaces one gateway at a time
// (OrderedReady), so the machines always have one.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func mGatewayCommand() {
	to, err := url.Parse(os.Getenv("M_GATEWAY_TO"))
	if err != nil || to.Host == "" {
		log.Fatal("M_GATEWAY_TO: the router's machines' URL, e.g. http://router.jarvis4-router.svc.cluster.local:8081")
	}
	path, err := gatewayConfig(os.Getenv("WG_CONFIGS"), os.Getenv("POD_NAME"))
	if err != nil {
		log.Fatal("m-gateway: ", err)
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
	grace, _ := strconv.Atoi(env("M_GATEWAY_GRACE_SECONDS", "1740"))
	log.Printf("m-gateway: stopping: no new connections, waiting up to %d s for the requests in flight", grace)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(grace)*time.Second)
	defer cancel()
	peer.Shutdown(ctx)
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

// gatewayConfig: the peer of this pod: the ordinal of POD_NAME (…-<n>) picks the n-th of WG_CONFIGS
func gatewayConfig(configs, pod string) (string, error) {
	list := strings.Split(configs, ",")
	if configs == "" {
		return "", fmt.Errorf("WG_CONFIGS: the peers' wg.conf files")
	}
	i := strings.LastIndex(pod, "-")
	n, err := strconv.Atoi(pod[i+1:])
	if i < 0 || err != nil || n < 0 || n >= len(list) {
		return "", fmt.Errorf("POD_NAME %q: no ordinal within the %d peers of WG_CONFIGS", pod, len(list))
	}
	return strings.TrimSpace(list[n]), nil
}
