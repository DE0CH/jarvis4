module github.com/DE0CH/jarvis4/machine

go 1.25.1

require golang.org/x/crypto v0.43.0

require (
	filippo.io/nistec v0.0.4 // indirect
	golang.org/x/sys v0.37.0 // indirect
)

require github.com/DE0CH/jarvis4/kernel v0.0.0

replace github.com/DE0CH/jarvis4/kernel => ../kernel
