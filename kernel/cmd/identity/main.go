// The identity signer's process (kernel/signers): no state.
package main

import (
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/signers"
)

func main() {
	serve.Main("identity", func(s *serve.Server) error {
		signers.RegisterIdentity(s)
		return nil
	})
}
