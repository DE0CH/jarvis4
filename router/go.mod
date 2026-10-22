module github.com/DE0CH/jarvis4/router

go 1.25.1

require golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f

require (
	filippo.io/nistec v0.0.4 // indirect
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

require (
	filippo.io/age v1.2.1
	github.com/DE0CH/jarvis4/kernel v0.0.0
)

replace github.com/DE0CH/jarvis4/kernel => ../kernel
