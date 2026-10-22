// The log notary's process (kernel/notary): its log in KERNEL_DATA (its own volume).
package main

import (
	"os"
	"path/filepath"

	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/notary"
)

func main() {
	serve.Main("notary", func(s *serve.Server) error {
		n, err := notary.Open(filepath.Join(os.Getenv("KERNEL_DATA"), "notary-log.jsonl"), s.C.Signer)
		if err != nil {
			return err
		}
		notary.Register(s, n)
		return nil
	})
}
