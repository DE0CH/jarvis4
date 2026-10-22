// rostervec: sig.RosterPayload of {copy, members} read on stdin, for infra/setup_roster_test.py (the setup session's
// Python must make the payload byte for byte as Go does: both the setup key and the root key sign it). Not in the image.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

func main() {
	var in struct {
		Copy    string         `json:"copy"`
		Members []sig.Identity `json:"members"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	p, err := sig.RosterPayload(in.Copy, in.Members)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.WriteString(p)
}
