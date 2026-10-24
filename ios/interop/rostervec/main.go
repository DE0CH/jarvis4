// rostervec: kernel/sig's roster on the Go side, for the app's interop test (ios/interop Kernel) and
// infra/setup_roster_test.py: reads {"copy", "members": [{role, signingKey, agreementKey}…], "retired": […],
// "secretsBoot": {…}} on stdin and prints sig.Roster.Payload; with a payload and a signature (-open ROOTPUB, stdin
// {"payload","sig"}) prints the roster sig.OpenRoster reads, or fails.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

func main() {
	open := flag.String("open", "", "the root key's public half: open a signed roster instead")
	flag.Parse()
	if *open != "" {
		var d sig.Doc
		if err := json.NewDecoder(os.Stdin).Decode(&d); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		r, err := sig.OpenRoster(d, *open)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	var in sig.Roster
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	p, err := in.Payload()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(p)
}
