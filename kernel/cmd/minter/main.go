// The minter's process (kernel/minter): no state; the only kernel component with GitHub egress.
package main

import (
	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/minter"
)

func main() {
	serve.Main("minter", func(s *serve.Server) error {
		minter.Register(s, minter.New(s.C, s.Trust, minter.NewGitHubAPI()))
		return nil
	})
}
