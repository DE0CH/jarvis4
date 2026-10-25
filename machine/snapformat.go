package main

// The snapshot's compression (DECISIONS 241): S2 (Snappy's successor). The CPU per byte is what sets the pace of a
// final snapshot on Fly's shared CPUs: a machine that spent its burst on a build gets about a quarter of a core
// (2026-10-25, the Deepseek session's Upgrade: 1.3 cores of steal, 0.2 left to the snapshot). Measured on a throttled
// machine over node_modules and a Go tree: S2 186 MB per CPU-second to compress and 690 to decompress, ratio 2.7; zstd's
// fastest 110 and 210, ratio 3.6; gzip 55 and 105, ratio 3.5. The bytes S2 adds cost little now that they go straight
// to the bucket (snapdirect.go). Snapshots made before are gzip: every reader tells the two apart by their first
// bytes. The files and objects keep their names (snapshot.tar.gz: the role, not the format).

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

// snapWriter: the compressor a snapshot is written through (Flush: what it holds goes out as a block of its own;
// Close ends the stream, not w)
type snapWriter interface {
	io.WriteCloser
	Flush() error
}

func newSnapWriter(w io.Writer) (snapWriter, error) {
	return s2.NewWriter(w), nil
}

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
