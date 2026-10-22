// The grant merger's process (kernel/merger): no state.
package main

import (
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/merger"
)

func main() {
	serve.Main("merger", func(s *serve.Server) error {
		merger.Register(s, merger.New(s.C.Signer, s.Trust))
		return nil
	})
}
