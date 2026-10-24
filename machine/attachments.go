package main

// First-prompt attachments (router/uploads.go). The router stages the files the New Session form uploaded and
// binds them to this session; the first machine fetches them over the machine-signed /m/attachments before
// the harness starts, then the router drops them. Jarvis 1's session-attachments script (run by the
// supervisor for the first prompt) still does the rest exactly as in Jarvis 1 — copies them into ~/uploads,
// writes the paths into the first message, images inline — reading from a local file:// "box" instead of the
// Storage Box: SESSION_ATTACH_DAV_BASE=file://$HOME, SESSION_ATTACH_DIR=.jarvis-uploads. (Not ~/uploads
// itself: the script opens its source and then truncates its destination, which must not be the same file.)
//
// Each file is taken only when (1) its bytes hash to the sha256 and size the cert names (the phone signed them with the
// new line) and (2) it carries the core's attestation over (this machine, "attachment", that sha256): every attachment
// is an entry in the core's hash-chained input log, as every other input (deliver.go). A file failing either is
// refused alone: the verified ones are kept, and the first message names the refused ones and why
// (SESSION_ATTACHMENTS_REFUSED, session-attachments), so the agent doesn't look for a file that isn't there.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const attachStaging = ".jarvis-uploads"

// fetchAttachments: env for the harness, or nil when no file matches the cert. Only the files the cert names
// (name, sha256, size: the phone approved them with the new line), each checked against its hash and attested; a file
// that doesn't check is left out and named in SESSION_ATTACHMENTS_REFUSED.
func fetchAttachments(c *client, coreKey string, refs []AttachmentRef) []string {
	home, _ := os.UserHomeDir()
	taken, refused, err := downloadAttachments(c, coreKey, filepath.Join(home, attachStaging), refs)
	if err != nil {
		log.Printf("attachments: %v", err)
		os.RemoveAll(filepath.Join(home, attachStaging))
		return refusedEnv(refused)
	}
	log.Printf("attachments: %d file(s) fetched, each the one the cert names; %d refused", len(taken), len(refused))
	if len(refused) == 0 { // a refused one stays with the router, for a look by hand
		if _, _, st, err := c.raw("DELETE", "/m/attachments", nil); err != nil || st != 200 {
			log.Printf("attachments: the router kept its copy (HTTP %d %v)", st, err)
		}
	}
	if len(taken) == 0 {
		os.RemoveAll(filepath.Join(home, attachStaging))
		return refusedEnv(refused)
	}
	list := make([]string, 0, len(taken))
	for _, r := range taken {
		list = append(list, fmt.Sprintf(`{"name":%q,"isImage":%t}`, r.Name, isImageName(r.Name)))
	}
	return append(append(attachmentEnv(home), "SESSION_ATTACHMENTS_JSON=["+strings.Join(list, ",")+"]"), refusedEnv(refused)...)
}

// refusedEnv: the refused files (names from the cert, reasons from this machine), for the first message
func refusedEnv(refused []string) []string {
	if len(refused) == 0 {
		return nil
	}
	b, _ := json.Marshal(refused)
	return []string{"SESSION_ATTACHMENTS_REFUSED=" + string(b)}
}

func isImageName(n string) bool {
	switch strings.ToLower(filepath.Ext(n)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".heif":
		return true
	}
	return false
}

func attachmentEnv(home string) []string {
	u := url.URL{Scheme: "file", Path: home}
	return []string{"SESSION_ATTACH_DAV_BASE=" + u.String(), "SESSION_ATTACH_DIR=" + attachStaging,
		"SESSION_ATTACH_DAV_USER=", "SESSION_ATTACH_DAV_PASS="}
}

// downloadAttachments: the files that check (written into dir) and "name: why" for each that doesn't; an error only
// when nothing could be fetched at all (the listing, the directory)
func downloadAttachments(c *client, coreKey, dir string, refs []AttachmentRef) (taken []AttachmentRef, refused []string, err error) {
	// the listing carries the core's attestation of each file (the router asked the core for it: the input log)
	var list struct {
		Attest map[string]*SignedDoc `json:"attest"`
	}
	refuseAll := func(why string) []string {
		out := []string{}
		for _, f := range refs {
			out = append(out, f.Name+": "+why)
		}
		return out
	}
	if err := c.json("GET", "/m/attachments", nil, &list); err != nil {
		return nil, refuseAll("the router's listing wasn't readable"), fmt.Errorf("the listing: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, refuseAll("no room on this machine"), err
	}
	for _, f := range refs {
		if !plainName(f.Name) {
			refused = append(refused, fmt.Sprintf("%q: not a plain file name", f.Name))
			continue
		}
		// the signature covers the decoded path (as the router checks it); the URL carries it escaped
		st, _, body, err := c.signedDo("GET", "/m/attachments/"+f.Name, "/m/attachments/"+url.PathEscape(f.Name), "", nil, "")
		if err == nil && st != 200 {
			err = fmt.Errorf("HTTP %d", st)
		}
		switch {
		case err != nil:
			refused = append(refused, fmt.Sprintf("%s: not fetched (%v)", f.Name, err))
		case hexSum256(body) != f.Sha256 || int64(len(body)) != f.Size:
			refused = append(refused, f.Name+": not the file Deyao approved (its bytes differ)")
		case checkAttest(coreKey, c.me, "attachment", body, list.Attest[f.Name]) != nil:
			refused = append(refused, f.Name+": not in the core's input log")
		default:
			if err := os.WriteFile(filepath.Join(dir, f.Name), body, 0o600); err != nil {
				refused = append(refused, fmt.Sprintf("%s: not written (%v)", f.Name, err))
				continue
			}
			taken = append(taken, f)
		}
	}
	for _, r := range refused {
		log.Printf("attachments: refused %s", r)
	}
	return taken, refused, nil
}

func hexSum256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// plainName: one path segment (the router's safeName output)
func plainName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\\x00") && len(n) <= 200
}
