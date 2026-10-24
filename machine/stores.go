package main

// jarvis stores [--keys | --json]: every store and the key NAMES it holds (never a value), with what each key is for,
// from the router's GET /m/stores (router/storedocs.go), so a session knows which store to ask for with
// `jarvis add-store <name>`. The store list, sensitivity and key names are the core's signed list, checked here
// against the core's key; the explanations are the router's record (words, not a trust decision).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type keyRow struct {
	Name        string `json:"name"`
	Explanation string `json:"explanation,omitempty"`
	At          string `json:"at,omitempty"`
	Writer      *struct {
		By           string `json:"by"`
		Session      string `json:"session,omitempty"`
		SessionLabel string `json:"sessionLabel,omitempty"`
	} `json:"writer,omitempty"`
}

type storeRow struct {
	Name      string   `json:"name"`
	Sensitive bool     `json:"sensitive"`
	Empty     bool     `json:"empty"`
	Unlocked  bool     `json:"unlocked"`
	About     string   `json:"about,omitempty"`
	Keys      []string `json:"keys"`    // names, as the core lists them
	KeyInfo   []keyRow `json:"keyInfo"` // the same keys with what each is for
	KeysFrom  string   `json:"keysFrom"`
}

func (s storeRow) keyNames() string { return strings.Join(s.Keys, " ") }

// coreRow: a row of the core's signed list
type coreRow struct {
	Name      string `json:"name"`
	Sensitive bool   `json:"sensitive"`
	Empty     bool   `json:"empty"`
	Keys      []struct {
		Name string `json:"name"`
	} `json:"keys"`
}

func storesCmd(args []string) error {
	asJSON := len(args) == 1 && args[0] == "--json"
	withKeys := len(args) == 1 && args[0] == "--keys"
	if len(args) > 0 && !asJSON && !withKeys {
		return fmt.Errorf("usage: jarvis stores [--keys | --json]   (--keys: each key on its own line with what it is for)")
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	var out struct {
		Stores []storeRow `json:"stores"`
		Signed *SignedDoc `json:"signed"`
	}
	if err := c.json("GET", "/m/stores", nil, &out); err != nil {
		return err
	}
	// the store list and sensitivity: only as the core signed them
	if coreKey, err := readTrim(coreKeyPath); err == nil && out.Signed != nil {
		var list struct {
			Kind   string    `json:"kind"`
			Stores []coreRow `json:"stores"`
		}
		if err := verifyDoc(coreKey, out.Signed, &list); err != nil || list.Kind != "stores" {
			return fmt.Errorf("the store list isn't signed by the core")
		}
		signed := map[string]coreRow{}
		for _, s := range list.Stores {
			signed[s.Name] = s
		}
		if len(signed) != len(out.Stores) {
			return fmt.Errorf("the store list differs from the core's")
		}
		for _, s := range out.Stores {
			c, ok := signed[s.Name]
			if !ok || c.Sensitive != s.Sensitive || c.Empty != s.Empty {
				return fmt.Errorf("store %s differs from the core's list", s.Name)
			}
			names := []string{}
			for _, k := range c.Keys {
				names = append(names, k.Name)
			}
			if strings.Join(names, " ") != s.keyNames() {
				return fmt.Errorf("store %s's keys differ from the core's list", s.Name)
			}
		}
	}
	// this session's own stores: from its core-signed cert
	mine := map[string]bool{}
	var certs struct {
		Cert *SignedDoc `json:"cert"`
	}
	if coreKey, err := readTrim(coreKeyPath); err == nil && c.json("GET", "/m/cert", nil, &certs) == nil && certs.Cert != nil {
		var cert struct {
			Stores []string `json:"stores"`
		}
		if verifyDoc(coreKey, certs.Cert, &cert) == nil {
			for _, n := range cert.Stores {
				mine[n] = true
			}
		}
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(out.Stores)
	}
	for _, s := range out.Stores {
		var flags []string
		if mine[s.Name] {
			flags = append(flags, "in this session")
		}
		if s.Sensitive {
			flags = append(flags, "sensitive")
		}
		if s.Empty {
			flags = append(flags, "empty")
		} else if !s.Unlocked {
			flags = append(flags, "locked")
		}
		keys := s.keyNames()
		fmt.Printf("%s", s.Name)
		if len(flags) > 0 {
			fmt.Printf(" [%s]", strings.Join(flags, ", "))
		}
		if !withKeys {
			fmt.Printf(": %s\n", keys)
			continue
		}
		fmt.Println()
		if s.About != "" {
			fmt.Printf("  %s\n", s.About)
		}
		for _, k := range s.KeyInfo {
			what := k.Explanation
			if what == "" {
				what = "(no explanation yet)"
			}
			by := ""
			if k.Writer != nil && k.Writer.By == "machine" {
				by = " [written by session " + k.Writer.SessionLabel + " " + k.Writer.Session + "]"
			}
			fmt.Printf("  %s: %s%s\n", k.Name, what, by)
		}
	}
	return nil
}
