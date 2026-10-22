package main

// First-prompt attachments (Jarvis 1's /api/uploads + session-attachments). The New Session form uploads each
// picked file here BEFORE creating the session (x-upload-id groups a form's files, x-upload-name names one);
// they are staged on the router's volume (DATA_DIR/uploads/<uploadId>/<name>), not on the Storage Box, so no
// machine needs Storage Box creds. POST /api/sessions {attachments: {uploadId, files: [{name, isImage}]}}
// binds the upload to that one session; only that session's machines can fetch it (machine-signed
// GET /m/attachments, /m/attachments/{name}), and its machine drops it once fetched (DELETE /m/attachments).
// Each file's sha256 and size go into the new line's signed config (vouch.go sessionConfig), so the phone signs them;
// the listing carries the core's attestation of each (input "attachment", origin "cert"), so each is in the input log,
// and the machine takes a file only with both (machine/attachments.go). The app can read a staged file back
// (GET /api/sessions/{id}/attachments/{name}) to show it on the approval page, checked against the signed hash there.
// A session proposing a new session stages its files the same way (PUT /m/api/sessions/{id}/uploads/{upload}/{name}):
// such an upload is owned by that session (Upload.Owner), only its own proposals can bind it, and from there it is
// the same line: signed by hash, attested, fetched by the new session's first machine.
// The first machine fetches them before the harness starts (machine/attachments.go) and hands Jarvis 1's
// session-attachments script a local file:// "box", so ~/uploads and the first message come out exactly as in
// Jarvis 1.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	attachMaxFiles = 20
	attachMaxBytes = 25 << 20 // per file, as Jarvis 1 (the tunnel's request cap)
	uploadTTL      = 24 * time.Hour
	// unbound uploads a session may hold at once (each becomes one proposal's attachments)
	maxSessionUploads = 5
)

type Upload struct {
	ID      string       `json:"id"`
	Created time.Time    `json:"created"`
	Session string       `json:"session,omitempty"` // bound by POST /api/sessions
	Owner   string       `json:"owner,omitempty"`   // the session that staged it (a proposal's attachments); "" = the app
	Files   []AttachFile `json:"files"`
}

type AttachFile struct {
	Name    string `json:"name"`
	Size    int64  `json:"size,omitempty"`
	IsImage bool   `json:"isImage"`
}

type AttachmentsIn struct {
	UploadID string       `json:"uploadId"`
	Files    []AttachFile `json:"files"`
}

var uploadIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var ctrlRE = regexp.MustCompile(`[\x00-\x1f]`)

// safeName: Jarvis 1's lib/uploads.js safeName (a basename, no control characters, whitespace → "_",
// ≤ 200 bytes; a space would split a pasted path in the TUI). "." and ".." become "file".
func safeName(raw string) string {
	if i := strings.LastIndexAny(raw, `/\`); i >= 0 {
		raw = raw[i+1:]
	}
	s := strings.TrimSpace(spaceRE.ReplaceAllString(ctrlRE.ReplaceAllString(raw, ""), "_"))
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" || s == "." || s == ".." {
		return "file"
	}
	return s
}

// isImageName: the extensions Claude Code's TUI attaches inline
func isImageName(n string) bool {
	switch strings.ToLower(filepath.Ext(n)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp":
		return true
	}
	return false
}

// an upload's files are objects uploads/<id>/<name> (objstore.go)
func uploadKey(id, name string) string { return "uploads/" + id + "/" + name }

// StageUpload: one file of a form's upload, streamed to the volume. owner: the session staging it ("" = the app);
// an upload takes files from its owner only.
func (r *Router) StageUpload(uploadID, owner, rawName string, body io.Reader) (AttachFile, error) {
	if !uploadIDRE.MatchString(uploadID) {
		return AttachFile{}, bad("missing or bad x-upload-id")
	}
	name := safeName(rawName)
	r.ops.uploadMu.Lock()
	defer r.ops.uploadMu.Unlock()
	var err error
	r.st.Do(func(d *persisted) {
		u := uploads(d)[uploadID]
		switch {
		case u == nil && owner != "":
			n := 0
			for _, x := range uploads(d) {
				if x.Owner == owner && x.Session == "" {
					n++
				}
			}
			if n >= maxSessionUploads {
				err = bad("this session already holds %d uploads no proposal uses yet: attach them to a proposal (or wait 24 h for them to go) before starting another", n)
			}
		case u == nil:
		case u.Owner != owner:
			err = bad("this upload id is taken: pick another")
		case u.Session != "" && d.Sessions[u.Session] != nil:
			err = bad("this upload belongs to a session already: its files are fixed in that session's signed hashes, so start a new upload (a new upload id) for these files")
		case len(u.Files) >= attachMaxFiles && !hasFile(u, name):
			err = bad("too many attachments (max %d)", attachMaxFiles)
		}
	})
	if err != nil {
		return AttachFile{}, err
	}
	// read whole (at most attachMaxBytes) before it is stored: a file over the cap never becomes an object
	b, err := io.ReadAll(io.LimitReader(body, attachMaxBytes+1))
	if err == nil && int64(len(b)) > attachMaxBytes {
		err = &httpStatusErr{413, fmt.Sprintf("%s is larger than %d MB", name, attachMaxBytes>>20)}
	}
	if err == nil {
		err = r.objPutBytes(uploadKey(uploadID, name), b)
	}
	if err != nil {
		return AttachFile{}, err
	}
	n := int64(len(b))
	af := AttachFile{Name: name, Size: n, IsImage: isImageName(name)}
	r.st.Do(func(d *persisted) {
		m := uploads(d)
		u := m[uploadID]
		if u == nil {
			u = &Upload{ID: uploadID, Created: time.Now().UTC(), Owner: owner}
			m[uploadID] = u
		}
		out := u.Files[:0]
		for _, x := range u.Files {
			if x.Name != name {
				out = append(out, x)
			}
		}
		u.Files = append(out, af)
	})
	return af, nil
}

type httpStatusErr struct {
	status int
	msg    string
}

func (e *httpStatusErr) Error() string { return e.msg }

func uploads(d *persisted) map[string]*Upload {
	if d.Uploads == nil {
		d.Uploads = map[string]*Upload{}
	}
	return d.Uploads
}

func hasFile(u *Upload, name string) bool {
	for _, f := range u.Files {
		if f.Name == name {
			return true
		}
	}
	return false
}

// bindUpload: under the state lock (admitSession). The files named must be in the upload; the upload must be the
// caller's own (owner: the proposing session, "" = the app) and not belong to another live session. isImage is the
// router's own reading of the name.
func bindUpload(d *persisted, sid, owner string, in *AttachmentsIn) ([]AttachFile, error) {
	files, u, err := checkUpload(d, sid, owner, in)
	if err != nil {
		return nil, err
	}
	u.Session = sid
	return files, nil
}

// checkUpload: bindUpload's checks without binding (sid "" = not yet made: checkProposal, before a batch is filed)
func checkUpload(d *persisted, sid, owner string, in *AttachmentsIn) ([]AttachFile, *Upload, error) {
	if !uploadIDRE.MatchString(in.UploadID) {
		return nil, nil, bad("attachments: missing uploadId")
	}
	if len(in.Files) > attachMaxFiles {
		return nil, nil, bad("too many attachments (max %d)", attachMaxFiles)
	}
	u := uploads(d)[in.UploadID]
	if u == nil || u.Owner != owner {
		return nil, nil, bad("attachments: no upload %s", in.UploadID)
	}
	if u.Session != "" && u.Session != sid && d.Sessions[u.Session] != nil {
		return nil, nil, bad("attachments: the upload belongs to another session")
	}
	var out []AttachFile
	seen := map[string]bool{}
	for _, f := range in.Files {
		n := safeName(f.Name)
		if seen[n] {
			continue
		}
		seen[n] = true
		found := false
		for _, x := range u.Files {
			if x.Name == n {
				out, found = append(out, x), true
			}
		}
		if !found {
			return nil, nil, bad("attachments: %s wasn't uploaded", n)
		}
	}
	if len(out) == 0 {
		return nil, nil, bad("attachments: no files named")
	}
	return out, u, nil
}

// attachEnv: the first machine only (no cert yet). session-attachments (Jarvis 1) reads the names from
// SESSION_ATTACHMENTS_JSON; the machine fills in where they are (machine/attachments.go).
func attachEnv(s *Session, e map[string]string) {
	if s.Cert != nil || len(s.Ops.Attach) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("[")
	for i, f := range s.Ops.Attach {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":%q,"isImage":%t}`, f.Name, f.IsImage)
	}
	b.WriteString("]")
	e["SESSION_ATTACHMENTS_JSON"] = b.String()
}

// machineUpload: the upload bound to the calling machine's session
func (r *Router) machineUpload(machine string) (*Upload, error) {
	sid, err := r.machineSession(machine)
	if err != nil {
		return nil, err
	}
	var u *Upload
	r.st.Do(func(d *persisted) {
		s := d.Sessions[sid]
		if s != nil && s.Ops != nil && s.Ops.Upload != "" {
			if x := uploads(d)[s.Ops.Upload]; x != nil && x.Session == sid {
				c := *x
				c.Files = append([]AttachFile{}, s.Ops.Attach...)
				u = &c
			}
		}
	})
	if u == nil {
		return nil, errors.New("no attachments for this session")
	}
	return u, nil
}

// attestAttachments: the core's input-log entry for each file as it is on the volume now (machine, "attachment",
// origin "cert", its sha256), kept in the router's copy of the log. The machine checks each against the bytes it gets.
func (r *Router) attestAttachments(machine string, u *Upload) (map[string]*Doc, error) {
	out := map[string]*Doc{}
	for _, f := range u.Files {
		sum, _, err := r.objSha256(uploadKey(u.ID, f.Name))
		if err != nil {
			return nil, fmt.Errorf("attachment %s: %v", f.Name, err)
		}
		a, err := r.attestInput(machine, "attachment", "cert", sum)
		if err != nil {
			return nil, err
		}
		out[f.Name] = a
	}
	return out, nil
}

func (r *Router) dropUpload(id string) {
	if !uploadIDRE.MatchString(id) {
		return
	}
	r.ops.uploadMu.Lock()
	defer r.ops.uploadMu.Unlock()
	r.st.Do(func(d *persisted) { delete(uploads(d), id) })
	ctx, cancel := objCtx()
	defer cancel()
	if err := r.objects.DeletePrefix(ctx, "uploads/"+id+"/"); err != nil {
		log.Printf("[uploads] %s: %v", id, err)
	}
}

// sweepUploads: unbound uploads older than a day, uploads whose session is gone, and unbound ones whose owner is gone
func (r *Router) sweepUploads(now time.Time) {
	var drop []string
	r.st.Do(func(d *persisted) {
		for id, u := range uploads(d) {
			gone := (u.Session != "" && d.Sessions[u.Session] == nil) || (u.Session == "" && u.Owner != "" && d.Sessions[u.Owner] == nil)
			if gone || (u.Session == "" && now.Sub(u.Created) > uploadTTL) {
				drop = append(drop, id)
			}
		}
	})
	for _, id := range drop {
		r.dropUpload(id)
	}
}

func init() {
	onDestroy = append(onDestroy, func(r *Router, s Session) {
		if s.Ops != nil && s.Ops.Upload != "" {
			r.dropUpload(s.Ops.Upload)
		}
	})
}

func writeUpload(w http.ResponseWriter, af AttachFile, err error) {
	var he *httpStatusErr
	if errors.As(err, &he) {
		writeJSON(w, he.status, map[string]string{"error": he.msg})
		return
	}
	if err != nil {
		scheduleErr(w, err)
		return
	}
	writeJSON(w, 200, af)
}

func (r *Router) uploadsLoop() {
	for {
		time.Sleep(time.Hour)
		r.sweepUploads(time.Now())
	}
}

func (r *Router) registerUploads(app appRoute, m machineRoute) {
	app("POST /api/uploads", func(w http.ResponseWriter, req *http.Request) {
		name := req.Header.Get("x-upload-name")
		if n, err := url.PathUnescape(name); err == nil {
			name = n
		}
		af, err := r.StageUpload(req.Header.Get("x-upload-id"), "", name, req.Body)
		writeUpload(w, af, err)
	})
	// a session stages a file for a new session it will propose (jarvis2-request new-session --attach): the raw bytes,
	// the upload id and name in the path (the machine signs the path and the body's hash)
	m("PUT /m/api/sessions/{id}/uploads/{upload}/{name}", func(w http.ResponseWriter, req *http.Request, machine string, body []byte) {
		sid, err := r.machineSession(machine)
		if err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		if req.PathValue("id") != sid {
			writeJSON(w, 403, map[string]string{"error": fmt.Sprintf("this machine is session %s, not %s", sid, req.PathValue("id"))})
			return
		}
		af, err := r.StageUpload(req.PathValue("upload"), sid, req.PathValue("name"), bytes.NewReader(body))
		writeUpload(w, af, err)
	})
	m("GET /m/attachments", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		u, err := r.machineUpload(machine)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		attest, err := r.attestAttachments(machine, u)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"files": u.Files, "attest": attest})
	})
	// the app: a staged file of a session not yet started (the approval page shows it, checked against the signed hash)
	app("GET /api/sessions/{id}/attachments/{name}", func(w http.ResponseWriter, req *http.Request) {
		sid, name := req.PathValue("id"), req.PathValue("name")
		var upID string
		r.st.Do(func(d *persisted) {
			if s := d.Sessions[sid]; s != nil && s.Ops != nil && s.Ops.Upload != "" {
				if u := uploads(d)[s.Ops.Upload]; u != nil && u.Session == sid {
					for _, f := range s.Ops.Attach {
						if f.Name == name {
							upID = u.ID
						}
					}
				}
			}
		})
		if upID == "" || safeName(name) != name {
			writeJSON(w, 404, map[string]string{"error": "no such attachment (a started session's attachments are gone from the router)"})
			return
		}
		f, err := r.objects.Get(req.Context(), uploadKey(upID, name))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no such attachment"})
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, req, "", time.Time{}, f)
	})
	m("GET /m/attachments/{name}", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		u, err := r.machineUpload(machine)
		name := req.PathValue("name")
		if err != nil || !hasFile(u, name) || safeName(name) != name {
			writeJSON(w, 404, map[string]string{"error": "no such attachment"})
			return
		}
		f, err := r.objects.Get(req.Context(), uploadKey(u.ID, name))
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "no such attachment"})
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, req, "", time.Time{}, f) // not ServeFile: it redirects ".../index.html"
	})
	m("DELETE /m/attachments", func(w http.ResponseWriter, req *http.Request, machine string, _ []byte) {
		u, err := r.machineUpload(machine)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		r.dropUpload(u.ID)
		log.Printf("session upload %s fetched and dropped", u.ID)
		writeJSON(w, 200, map[string]bool{"ok": true})
	})
}
