package main

// `jarvis-machine sign-request METHOD PATH < body`: this machine's signature over a request for a service outside
// Jarvis 4, printed as the router's three headers (JSON: X-Machine, X-Time, X-Sig) — the same signature every /m call
// carries. The service asks the router whose it is (router/machinesig.go, POST /api/machine-signatures/verify), which
// never checks one over a path under /m: a signature made here can't stand in for a router call. Today's user:
// aviary-gateway's boot (harness-aviary.sh, aviary/README.md).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var signMethodRE = regexp.MustCompile(`^[A-Z]{3,7}$`)

func signRequestCmd(args []string) error {
	if len(args) != 2 || !signMethodRE.MatchString(args[0]) || !strings.HasPrefix(args[1], "/") ||
		args[1] == "/m" || strings.HasPrefix(args[1], "/m/") {
		return fmt.Errorf("usage: jarvis-machine sign-request METHOD PATH < body (a path outside /m)")
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<20))
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	h, err := c.signed(args[0], args[1], hex.EncodeToString(sum[:]))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(h)
}
