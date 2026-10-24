// Secrets' process (kernel/secrets): empty until the app claims it (Reset or Recover); a wipe ends the process.
// KERNEL_ROOT: the root key's public half (keys/root.pub), which its roster is checked against. KERNEL_MINTER_URL:
// the minter (kernel/minter), where an approved deploy-key call goes; secrets itself reaches nothing outside the cluster.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/DE0CH/jarvis4/kernel/minter"
	"github.com/DE0CH/jarvis4/kernel/secrets"
)

func main() {
	root := os.Getenv("KERNEL_ROOT")
	if root == "" {
		log.Fatal("KERNEL_ROOT (the root key's public half, keys/root.pub) isn't set")
	}
	c, err := secrets.New(root, minter.NewClient(os.Getenv("KERNEL_MINTER_URL")))
	if err != nil {
		log.Fatal(err)
	}
	c.SetExit(func() { time.Sleep(500 * time.Millisecond); log.Printf("wiped: exiting"); os.Exit(0) })
	addr := os.Getenv("KERNEL_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("secrets up, empty")
	log.Fatal(http.ListenAndServe(addr, secrets.Handler(c)))
}
