// The spawner's process (kernel/spawner): its state in KERNEL_DATA (its own volume); KERNEL_MACHINE_URL is the
// router's address its machines get (on Fly's private network).
package main

import (
	"os"
	"path/filepath"

	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/spawner"
)

func main() {
	serve.Main("spawner", func(s *serve.Server) error {
		var env map[string]string
		if u := os.Getenv("KERNEL_MACHINE_URL"); u != "" {
			env = map[string]string{"JARVIS2_URL": u}
		}
		sp, err := spawner.Open(filepath.Join(os.Getenv("KERNEL_DATA"), "spawner.json"), s.C, s.Trust, spawner.NewFlyAPI(), env)
		if err != nil {
			return err
		}
		spawner.Register(s, sp)
		return nil
	})
}
