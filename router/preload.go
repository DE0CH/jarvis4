package main

// The fly-preload runner's golden volumes (docs/PLAN-one-image.md, kernel/spawner/preload.go). The router asks the
// kernel's preloader to step the golden volume of the image fly-preload sessions run, in each region they start in,
// until it is ready: a deploy that moves PRELOAD_SESSION_IMAGE begins the next ones, so making them is part of the
// deploy with no credentials of its own. The preloader keeps a region's newest three and deletes the rest.
//
//	PRELOAD_SESSION_IMAGE  the image fly-preload sessions run (ghcr.io/de0ch/jarvis4-session@sha256:…); unset: nothing here runs
//	PRELOAD_REGIONS        the regions they start in, comma-separated (default: the router's region)
//	PRELOAD_DISK_GB        every session volume forked from a golden (default 20: aviary's image with the agent's
//	                       tools and room to work; a session asking for more gets an empty volume)

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

const preloadDefaultDisk = 20

var preloadEvery = time.Minute

type preloadConfig struct {
	image   string
	regions []string
	diskGB  int
}

// preloadConfigFrom: the configuration read with get (os.Getenv); ok false when PRELOAD_SESSION_IMAGE is unset
func preloadConfigFrom(get func(string) string, region string) (preloadConfig, bool) {
	c := preloadConfig{image: strings.TrimSpace(get("PRELOAD_SESSION_IMAGE")), diskGB: preloadDefaultDisk}
	if c.image == "" {
		return c, false
	}
	for _, r := range strings.Split(get("PRELOAD_REGIONS"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			c.regions = append(c.regions, r)
		}
	}
	if len(c.regions) == 0 && region != "" {
		c.regions = []string{region}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(get("PRELOAD_DISK_GB"))); err == nil && n > 0 {
		c.diskGB = n
	}
	return c, true
}

// preloadSteps: the preloader's POST /golden bodies, one per region
func preloadSteps(c preloadConfig) []map[string]any {
	out := []map[string]any{}
	for _, r := range c.regions {
		out = append(out, map[string]any{"region": r, "image": c.image, "diskGb": c.diskGB})
	}
	return out
}

// goldenState: the preloader's answer (a document it signed over the golden volume) in a few words
func goldenState(b []byte) string {
	var d sig.Doc
	var g struct{ State, Volume, Error string }
	if json.Unmarshal(b, &d) != nil || json.Unmarshal([]byte(d.Payload), &g) != nil {
		return "an answer that isn't the preloader's"
	}
	return strings.TrimSpace(g.State + " " + g.Volume + " " + g.Error)
}

// preloadLoop: the golden volumes stepped every minute (the leader only); what each answers is logged when it changes
func (r *Router) preloadLoop() {
	last := map[string]string{}
	for {
		awaitLead() // leaderlease.go
		c, ok := preloadConfigFrom(os.Getenv, r.cfg.Region)
		if ok && r.kernel != nil {
			for _, in := range preloadSteps(c) {
				region := in["region"].(string)
				b, err := r.kernel.call("preloader", "POST", "/golden", in)
				state := ""
				if err != nil {
					state = "error: " + err.Error()
				} else {
					state = goldenState(b)
				}
				if last[region] != state {
					log.Printf("preload: the golden volume of %s in %s: %s", c.image, region, state)
					last[region] = state
				}
			}
		}
		time.Sleep(preloadEvery)
	}
}
