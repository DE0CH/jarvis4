// The preloader's process (kernel/spawner/preload.go, docs/PLAN-one-image.md): the spawner's code as the second Fly
// signer, for the fly-preload runner, in its own Fly app (spawner.PreloadFlyApp) with its own token. Its state in
// KERNEL_DATA (its own volume); KERNEL_MACHINE_URL is the router's address its machines get (on Fly's private network).
package main

import (
	"os"
	"path/filepath"

	"github.com/DE0CH/jarvis4/kernel/internal/serve"
	"github.com/DE0CH/jarvis4/kernel/spawner"
)

func main() {
	serve.Main("preloader", func(s *serve.Server) error {
		var env map[string]string
		if u := os.Getenv("KERNEL_MACHINE_URL"); u != "" {
			env = map[string]string{"JARVIS2_URL": u}
		}
		sp, err := spawner.OpenRole(spawner.PreloaderRole, filepath.Join(os.Getenv("KERNEL_DATA"), "preloader.json"), s.C, s.Trust,
			spawner.NewFlyAPIApp(spawner.PreloadFlyApp), nil, env, nil)
		if err != nil {
			return err
		}
		spawner.Register(s, sp)
		return nil
	})
}
