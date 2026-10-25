package main

// A snapshot's compression (machine/snapformat.go, DECISIONS 241): S2 from 2026-10-25 on, gzip before; every
// reader tells them apart by their first bytes. The archive around a snapshot stays gzip.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"

	"github.com/klauspost/compress/s2"
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	s2Magic   = []byte("\xff\x06\x00\x00S2sTwO") // the stream identifier chunk
)

// openSnapReader: a snapshot's tar, from its S2 or (older) gzip bytes
func openSnapReader(r io.Reader) (io.ReadCloser, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	head, err := br.Peek(len(s2Magic))
	if err != nil && len(head) < 2 {
		return nil, errors.New("not a snapshot: too short")
	}
	switch {
	case bytes.HasPrefix(head, s2Magic):
		return io.NopCloser(s2.NewReader(br)), nil
	case bytes.HasPrefix(head, gzipMagic):
		return gzip.NewReader(br)
	}
	return nil, errors.New("not a snapshot: neither S2 nor gzip")
}
