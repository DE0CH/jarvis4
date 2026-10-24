package main

import (
	"net"
	"testing"
	"time"
)

func TestWaitAPIProxy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JARVIS_API_ADDR", l.Addr().String())
	t0 := time.Now()
	waitAPIProxy(5 * time.Second)
	if time.Since(t0) > 2*time.Second {
		t.Fatal("waited for a listening proxy")
	}
	l.Close()
	t0 = time.Now()
	waitAPIProxy(600 * time.Millisecond)
	if time.Since(t0) < 500*time.Millisecond {
		t.Fatal("didn't wait for a missing proxy")
	}
}
