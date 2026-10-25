package main

// The router's blobs in object storage (docs/STATE.md 2.2): the bucket jarvis4-snapshots-de0ch through the credential
// jarvis4-objects (infra/objects-key.py: it can reach that bucket only), env OBJECTS_ACCESS_KEY / OBJECTS_SECRET_KEY
// (Secret router-secrets-objects), OBJECTS_ENDPOINT / OBJECTS_REGION / OBJECTS_BUCKET. Keys:
//
//	uploads/<id>/<name>        a first-prompt attachment (uploads.go)
//	task-runs/<run>.log|.output  a task run's log and output (tasks.go)
//
// A router outside the cluster with no credential (tests, CI's stand-ins, e2e) keeps them in memory (memObjects);
// main refuses to start that way.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// errNoObject: no object under that key
var errNoObject = errors.New("no such object")

// objectReader: an object's bytes, seekable (http.ServeContent)
type objectReader interface {
	io.ReadSeekCloser
}

type ObjStore interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) error // size -1: unknown (streamed in parts)
	Get(ctx context.Context, key string) (objectReader, error)          // errNoObject when there is none
	Delete(ctx context.Context, key string) error
	DeletePrefix(ctx context.Context, prefix string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// objDirect: a store the machines reach themselves (snapdirect.go): a multipart upload whose parts they put through
// signed URLs, and signed reads. The bucket has it; the memory stand-in doesn't (its machines stream through the router).
type objDirect interface {
	StartUpload(ctx context.Context, key string) (string, error) // → the upload id (earlier unfinished ones of key aborted)
	PartURL(ctx context.Context, key, upload string, part int, ttl time.Duration) (string, error)
	FinishUpload(ctx context.Context, key, upload string, etags []string) error // etags[i] is part i+1's
	AbortUpload(ctx context.Context, key, upload string) error
	GetURL(ctx context.Context, key string, ttl time.Duration) (string, error)
}

// objectsFromEnv: the bucket, or nil when no credential is set
func objectsFromEnv() (ObjStore, error) {
	ak, sk := os.Getenv("OBJECTS_ACCESS_KEY"), os.Getenv("OBJECTS_SECRET_KEY")
	if ak == "" || sk == "" {
		return nil, nil
	}
	u, err := url.Parse(env("OBJECTS_ENDPOINT", "https://fsn1.your-objectstorage.com"))
	if err != nil {
		return nil, err
	}
	c, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4(ak, sk, ""), Secure: u.Scheme == "https",
		Region: env("OBJECTS_REGION", "fsn1"), BucketLookup: minio.BucketLookupPath})
	if err != nil {
		return nil, err
	}
	return &s3Objects{c: c, bucket: env("OBJECTS_BUCKET", "jarvis4-snapshots-de0ch")}, nil
}

type s3Objects struct {
	c      *minio.Client
	bucket string
}

func (o *s3Objects) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	_, err := o.c.PutObject(ctx, o.bucket, key, r, size, minio.PutObjectOptions{ContentType: "application/octet-stream", PartSize: 16 << 20})
	return err
}

func (o *s3Objects) Get(ctx context.Context, key string) (objectReader, error) {
	obj, err := o.c.GetObject(ctx, o.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := obj.Stat(); err != nil {
		obj.Close()
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, errNoObject
		}
		return nil, err
	}
	return obj, nil
}

func (o *s3Objects) core() minio.Core { return minio.Core{Client: o.c} }

func (o *s3Objects) StartUpload(ctx context.Context, key string) (string, error) {
	// a machine that died mid-upload left its parts (stored, and billed): its successor's start ends them
	if res, err := o.core().ListMultipartUploads(ctx, o.bucket, key, "", "", "", 100); err == nil {
		for _, u := range res.Uploads {
			if u.Key == key {
				o.core().AbortMultipartUpload(ctx, o.bucket, key, u.UploadID)
			}
		}
	}
	return o.core().NewMultipartUpload(ctx, o.bucket, key, minio.PutObjectOptions{ContentType: "application/octet-stream"})
}

func (o *s3Objects) PartURL(ctx context.Context, key, upload string, part int, ttl time.Duration) (string, error) {
	u, err := o.c.Presign(ctx, "PUT", o.bucket, key, ttl, url.Values{"partNumber": {strconv.Itoa(part)}, "uploadId": {upload}})
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (o *s3Objects) FinishUpload(ctx context.Context, key, upload string, etags []string) error {
	parts := make([]minio.CompletePart, len(etags))
	for i, e := range etags {
		parts[i] = minio.CompletePart{PartNumber: i + 1, ETag: e}
	}
	_, err := o.core().CompleteMultipartUpload(ctx, o.bucket, key, upload, parts, minio.PutObjectOptions{})
	return err
}

func (o *s3Objects) AbortUpload(ctx context.Context, key, upload string) error {
	return o.core().AbortMultipartUpload(ctx, o.bucket, key, upload)
}

func (o *s3Objects) GetURL(ctx context.Context, key string, ttl time.Duration) (string, error) {
	u, err := o.c.PresignedGetObject(ctx, o.bucket, key, ttl, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (o *s3Objects) Delete(ctx context.Context, key string) error {
	return o.c.RemoveObject(ctx, o.bucket, key, minio.RemoveObjectOptions{})
}

func (o *s3Objects) List(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	for oi := range o.c.ListObjects(ctx, o.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if oi.Err != nil {
			return nil, oi.Err
		}
		out = append(out, oi.Key)
	}
	return out, nil
}

func (o *s3Objects) DeletePrefix(ctx context.Context, prefix string) error {
	keys, err := o.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := o.Delete(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

// memObjects: objects in memory (a router with no bucket: tests, CI's stand-ins)
type memObjects struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemObjects() *memObjects { return &memObjects{m: map[string][]byte{}} }

func (o *memObjects) Put(_ context.Context, key string, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[key] = b
	return nil
}

type nopSeekCloser struct{ *bytes.Reader }

func (nopSeekCloser) Close() error { return nil }

func (o *memObjects) Get(_ context.Context, key string) (objectReader, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	b, ok := o.m[key]
	if !ok {
		return nil, errNoObject
	}
	return nopSeekCloser{bytes.NewReader(b)}, nil
}

func (o *memObjects) Delete(_ context.Context, key string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.m, key)
	return nil
}

func (o *memObjects) List(_ context.Context, prefix string) ([]string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []string
	for k := range o.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (o *memObjects) DeletePrefix(ctx context.Context, prefix string) error {
	keys, _ := o.List(ctx, prefix)
	for _, k := range keys {
		o.Delete(ctx, k)
	}
	return nil
}

// objCtx: the context of one object call (a large object's own reads and writes run under the request's context)
func objCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

// objPutBytes / objGetBytes: small objects whole
func (r *Router) objPutBytes(key string, b []byte) error {
	ctx, cancel := objCtx()
	defer cancel()
	return r.objects.Put(ctx, key, bytes.NewReader(b), int64(len(b)))
}

func (r *Router) objGetBytes(key string) ([]byte, error) {
	ctx, cancel := objCtx()
	defer cancel()
	rd, err := r.objects.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

// objSha256: an object's sha256 (hex) and size, read through
func (r *Router) objSha256(key string) (string, int64, error) {
	ctx, cancel := objCtx()
	defer cancel()
	rd, err := r.objects.Get(ctx, key)
	if err != nil {
		return "", 0, err
	}
	defer rd.Close()
	h := sha256.New()
	n, err := io.Copy(h, rd)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// importBlobFiles: what the volume still holds under uploads/ and task-runs/ into the bucket (same keys), once; the
// directories are then set aside (.imported)
func (r *Router) importBlobFiles() error {
	for _, sub := range []string{"uploads", "task-runs"} {
		d := filepath.Join(r.cfg.DataDir, sub)
		if _, err := os.Stat(d); os.IsNotExist(err) {
			continue
		}
		n := 0
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || strings.HasPrefix(e.Name(), ".part-") {
				return err
			}
			rel, _ := filepath.Rel(r.cfg.DataDir, p)
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			fi, _ := f.Stat()
			ctx, cancel := objCtx()
			defer cancel()
			n++
			return r.objects.Put(ctx, filepath.ToSlash(rel), f, fi.Size())
		})
		if err != nil {
			return fmt.Errorf("import %s: %v", d, err)
		}
		if err := os.Rename(d, d+".imported"); err != nil {
			return err
		}
		log.Printf("objects: %s: %d files into the bucket", d, n)
	}
	return nil
}

// probeObjects: a small object written, read back and deleted (the credential and the bucket work)
func (r *Router) probeObjects() error {
	key := "probe/" + randID()
	if err := r.objPutBytes(key, []byte("ok")); err != nil {
		return err
	}
	b, err := r.objGetBytes(key)
	if err != nil || string(b) != "ok" {
		return fmt.Errorf("read back: %q %v", b, err)
	}
	ctx, cancel := objCtx()
	defer cancel()
	if err := r.objects.Delete(ctx, key); err != nil {
		return err
	}
	if _, mem := r.objects.(*memObjects); mem {
		log.Printf("objects: in memory (ROUTER_THROWAWAY=1: a throwaway router)")
	} else {
		log.Printf("objects: the bucket %s answers (put, get, delete)", env("OBJECTS_BUCKET", "jarvis4-snapshots-de0ch"))
	}
	return nil
}
