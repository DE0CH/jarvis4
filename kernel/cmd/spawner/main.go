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
		var awsEnv map[string]string
		if u := os.Getenv("KERNEL_AWS_MACHINE_URL"); u != "" { // the m-gateway on the tailnet (docs/PLAN-aws.md)
			awsEnv = map[string]string{"JARVIS2_URL": u}
		}
		sp, err := spawner.Open(filepath.Join(os.Getenv("KERNEL_DATA"), "spawner.json"), s.C, s.Trust, spawner.NewFlyAPI(), spawner.NewAWSAPI(), env, awsEnv)
		if err != nil {
			return err
		}
		// the fabric runner (docs/PLAN-fabric.md): the fabric hermit's address inside the cluster, and the router's
		// address as a fabric machine reaches it (the fabric's egress address)
		if h, u := os.Getenv("KERNEL_FABRIC_HERMIT_URL"), os.Getenv("KERNEL_FABRIC_MACHINE_URL"); h != "" && u != "" {
			sp.SetFabric(spawner.NewFabricAPI(h), map[string]string{"JARVIS2_URL": u})
		}
		spawner.Register(s, sp)
		return nil
	})
}
