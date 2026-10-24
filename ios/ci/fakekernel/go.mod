module fakekernel

go 1.25.1

require github.com/DE0CH/jarvis4/kernel v0.0.0

require (
	filippo.io/nistec v0.0.4 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

replace github.com/DE0CH/jarvis4/kernel => ../../../kernel
