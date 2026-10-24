package secrets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DE0CH/jarvis4/kernel/internal/kt"
	"github.com/DE0CH/jarvis4/kernel/minter"
	"github.com/DE0CH/jarvis4/kernel/sig"
)

// a GitHub stand-in: deploy keys per repo; tokens other than the one it knows, and repos it was told to refuse,
// answer 403 like GitHub does for a token without Administration on the repo
type testGitHub struct {
	token  string
	n      int64
	keys   map[string][]minter.DeployKey
	refuse map[string]bool
	seen   []string // every token it was called with
	onAdd  func()   // runs inside an add (another add finishing meanwhile)
}

func newTestGitHub() *testGitHub {
	return &testGitHub{token: "gh-admin-token", n: 100, keys: map[string][]minter.DeployKey{}, refuse: map[string]bool{}}
}
func (g *testGitHub) check(token, repo string) error {
	g.seen = append(g.seen, token)
	if token != g.token || g.refuse[repo] {
		return &minter.GitHubError{Status: 403, Msg: "GitHub: HTTP 403 Resource not accessible by personal access token"}
	}
	return nil
}
func (g *testGitHub) AddDeployKey(token, repo, title, pub string) (minter.DeployKey, error) {
	if err := g.check(token, repo); err != nil {
		return minter.DeployKey{}, err
	}
	g.n++
	k := minter.DeployKey{ID: g.n, Title: title, Key: pub}
	g.keys[repo] = append(g.keys[repo], k)
	if g.onAdd != nil {
		g.onAdd()
	}
	return k, nil
}
func (g *testGitHub) DeleteDeployKey(token, repo string, id int64) error {
	if err := g.check(token, repo); err != nil {
		return err
	}
	var out []minter.DeployKey
	for _, k := range g.keys[repo] {
		if k.ID != id {
			out = append(out, k)
		}
	}
	g.keys[repo] = out
	return nil
}

// withMinter: the world's minter, in process on a GitHub stand-in, in c's roster (c takes the roster naming it)
func withMinter(t *testing.T, w *kt.World, c *Secrets) *testGitHub {
	t.Helper()
	rosterFor(t, w, c)
	g := newTestGitHub()
	c.minter = minter.New(w.C["minter"], w.Trust, g)
	return g
}

// a set-up secrets with the token store written (sensitive: the setup session never creates it) and its minter
func deployKeyCore(t *testing.T) (*Secrets, *testGitHub, *phone) {
	t.Helper()
	k := newKernel(t)
	g := withMinter(t, k.w, k.c)
	pl(t)(writeStore(t, k.c, k.p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: g.token}))
	return k.c, g, k.p
}

// what the shell does: check the begin document, sign it and share the token store, under one Face ID
func (p *phone) answerDeployKey(t *testing.T, begin SignedDoc) (string, Sealed, string) {
	t.Helper()
	var b struct{ Pending, E, T string }
	json.Unmarshal([]byte(begin.Payload), &b)
	return b.Pending, p.shareOf(b.E, b.T), p.sign(begin.Payload)
}

// the app's names for a repo (ios Checks.repoStore, Checks.deployKeyTitle, OpenSSH.storeValues): the store github-<name>
// for DE0CH's repos, else github-<owner>-<name> (lower case, anything outside [a-z0-9-] as "-"), and the two env keys
// suffixed OWNER_NAME (upper case, anything outside [A-Z0-9] as "_")
func repoStore(repo string) string {
	owner, name, _ := strings.Cut(strings.ToLower(repo), "/")
	slug := name
	if owner != "de0ch" {
		slug = owner + "-" + name
	}
	b := []byte(slug)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			b[i] = '-'
		}
	}
	return "github-" + strings.Trim(string(b), "-")
}

func envSlug(repo string) string {
	b := []byte(strings.ToUpper(repo))
	for i, ch := range b {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

const (
	deployRepoPrefix = "GITHUB_DEPLOY_REPO_" // "owner/name"
	deployKeyPrefix  = "GITHUB_DEPLOY_KEY_"  // base64 of the OpenSSH private key file
)

// keyRequest: what the app sends to deploy_key_begin — the store and title it names, and for an add the key pair it
// made (appKey)
func keyRequest(t *testing.T, c *Secrets, p *phone, action, repo string, sensitive bool) DeployKeyRequest {
	t.Helper()
	store := repoStore(repo)
	r := DeployKeyRequest{Action: action, Repo: repo, Sensitive: sensitive, Store: store, Title: "jarvis4 " + store}
	if action == "add" && c.phoneSigning != "" {
		r.PublicKey, r.Keys, _ = appKey(t, c, p, repo, store)
	}
	return r
}

func deployKey(t *testing.T, c *Secrets, p *phone, action, repo string, sensitive bool) (map[string]any, error) {
	t.Helper()
	return deployKeyReq(t, c, p, keyRequest(t, c, p, action, repo, sensitive))
}

func deployKeyReq(t *testing.T, c *Secrets, p *phone, r DeployKeyRequest) (map[string]any, error) {
	t.Helper()
	b, err := c.DeployKeyBegin(r)
	if err != nil {
		return nil, err
	}
	id, s, sig := p.answerDeployKey(t, b)
	d, err := c.DeployKeyFinish(id, s, sig)
	if err != nil {
		return nil, err
	}
	if !VerifyWith(c.Key()["signingKey"], []byte(d.Payload), d.Sig) {
		t.Fatal("the answer isn't secrets-signed")
	}
	var m map[string]any
	json.Unmarshal([]byte(d.Payload), &m)
	return m, nil
}

// storeValues: a store's contents, opened the way a session gets them (unlocked by the phone)
func storeValues(t *testing.T, c *Secrets, p *phone, name string) map[string]string {
	t.Helper()
	unlock(t, c, p, name)
	return c.unlocked[name].values
}

func TestDeployKeyAddMakesAKeyAStoreAndAGitHubKey(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)
	c, g, p := deployKeyCore(t)
	m, err := deployKey(t, c, p, "add", "DE0CH/china-train", false)
	if err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "deploy-key-added" || m["store"] != "github-china-train" || m["sensitive"] != false || m["title"] != "jarvis4 github-china-train" {
		t.Fatalf("answer: %v", m)
	}
	ks := g.keys["DE0CH/china-train"]
	if len(ks) != 1 || ks[0].Title != "jarvis4 github-china-train" || !strings.HasPrefix(ks[0].Key, "ssh-ed25519 ") {
		t.Fatalf("GitHub keys: %+v", ks)
	}
	if m["keyId"] != float64(ks[0].ID) || c.repoKeyID["github-china-train"] != ks[0].ID {
		t.Fatalf("the key's id isn't recorded: %v %v", m["keyId"], c.repoKeyID)
	}
	if len(g.seen) != 1 || g.seen[0] != g.token {
		t.Fatalf("GitHub calls: %d (exactly one, with the token)", len(g.seen))
	}
	if _, open := c.unlocked[DeployKeyTokenStore]; open {
		t.Fatal("the token store stayed unlocked after the call")
	}
	if !c.notSensitive["github-china-train"] {
		t.Fatal("the repo's store came out sensitive")
	}
	v := storeValues(t, c, p, "github-china-train")
	if v["GITHUB_DEPLOY_REPO_DE0CH_CHINA_TRAIN"] != "DE0CH/china-train" || len(v) != 2 {
		t.Fatalf("store keys: %v", keysOf(v))
	}
	pem, err := b64.DecodeString(v["GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN"])
	if err != nil || !strings.HasPrefix(string(pem), "-----BEGIN OPENSSH PRIVATE KEY-----\n") {
		t.Fatal("the store doesn't hold an OpenSSH private key")
	}
	if strings.Contains(logs.String(), g.token) {
		t.Fatal("the token reached the log")
	}
	// the private half is the public key GitHub got (an independent implementation: ssh-keygen)
	if kg, err := exec.LookPath("ssh-keygen"); err == nil {
		f := filepath.Join(t.TempDir(), "k")
		os.WriteFile(f, pem, 0o600)
		out, err := exec.Command(kg, "-y", "-f", f).Output()
		if err != nil {
			t.Fatalf("ssh-keygen can't read the key: %v", err)
		}
		if strings.Fields(string(out))[1] != strings.Fields(ks[0].Key)[1] {
			t.Fatal("the stored private key isn't the deploy key on GitHub")
		}
	} else {
		t.Log("no ssh-keygen: skipped the independent check of the key format")
	}
}

func keysOf(m map[string]string) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

// a re-add is one GitHub call (the new key): the earlier key is answered as replacedKeyId, an orphan the router has
// the phone remove by id (the store stays); a remove deletes the recorded key by id and the store
func TestDeployKeyReAddLeavesAnOrphanAndRemoveDeletesByID(t *testing.T) {
	c, g, p := deployKeyCore(t)
	g.keys["DE0CH/claude-env"] = []minter.DeployKey{{ID: 7, Title: "someone else's key"}}
	m1, err := deployKey(t, c, p, "add", "DE0CH/claude-env", false)
	if err != nil {
		t.Fatal(err)
	}
	first := int64(m1["keyId"].(float64))
	m2, err := deployKey(t, c, p, "add", "DE0CH/claude-env", false)
	if err != nil {
		t.Fatal(err)
	}
	second := int64(m2["keyId"].(float64))
	if len(g.keys["DE0CH/claude-env"]) != 3 || m2["replacedKeyId"] != float64(first) || c.repoKeyID["github-claude-env"] != second {
		t.Fatalf("a re-add: %v %+v", m2, g.keys)
	}
	calls := len(g.seen)
	// the orphan, removed by id: the store stays
	r := keyRequest(t, c, p, "remove", "DE0CH/claude-env", false)
	r.KeyID = first
	b := pl(t)(c.DeployKeyBegin(r))
	if b["keyId"] != float64(first) || b["orphan"] != true {
		t.Fatalf("the begin names the orphan: %v", b)
	}
	m, err := deployKeyReq(t, c, p, r)
	if err != nil || m["kind"] != "deploy-key-removed" || m["orphan"] != true || len(g.seen) != calls+1 {
		t.Fatal(m, err)
	}
	if _, ok := c.stores["github-claude-env"]; !ok || len(g.keys["DE0CH/claude-env"]) != 2 {
		t.Fatal("the orphan's remove took the store, or left the orphan")
	}
	m, err = deployKey(t, c, p, "remove", "DE0CH/claude-env", false)
	if err != nil || m["kind"] != "deploy-key-removed" || m["deleted"] != float64(1) || m["keyId"] != float64(second) {
		t.Fatal(m, err)
	}
	if ks := g.keys["DE0CH/claude-env"]; len(ks) != 1 || ks[0].ID != 7 {
		t.Fatal("remove touched another key or left ours", ks)
	}
	if _, ok := c.stores["github-claude-env"]; ok || c.repoKeyID["github-claude-env"] != 0 {
		t.Fatal("remove left the store")
	}
}

// sensitivity is what the app asks for (the app insists on it for Jarvis's own repos: Checks.deployKeyBegin);
// secrets only keeps an existing sensitive store sensitive
func TestDeployKeySensitivity(t *testing.T) {
	c, _, p := deployKeyCore(t)
	if m, _ := deployKey(t, c, p, "add", "DE0CH/private-thing", true); m["sensitive"] != true {
		t.Fatal(m)
	}
	if m, _ := deployKey(t, c, p, "add", "DE0CH/private-thing", false); m["sensitive"] != true || c.notSensitive["github-private-thing"] {
		t.Fatal("a re-add downgraded a sensitive store")
	}
	b, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/private-thing", false))
	var bd deployKeyBegin
	json.Unmarshal([]byte(b.Payload), &bd)
	if !bd.Sensitive || !bd.Replaces || bd.Store != "github-private-thing" || bd.TokenStore != DeployKeyTokenStore {
		t.Fatalf("begin: %+v", bd)
	}
}

func TestDeployKeyNeedsThePhone(t *testing.T) {
	c, g, p := deployKeyCore(t)
	other := newPhone()
	b, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false))
	id, s, _ := p.answerDeployKey(t, b)
	if _, err := c.DeployKeyFinish(id, s, other.sign(b.Payload)); err == nil {
		t.Fatal("another key's signature was accepted")
	}
	if _, err := c.DeployKeyFinish(id, s, p.sign(b.Payload)); err == nil {
		t.Fatal("a pending was usable twice")
	}
	b1, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false))
	b2, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/y", false))
	id2, s2, _ := p.answerDeployKey(t, b2)
	if _, err := c.DeployKeyFinish(id2, s2, p.sign(b1.Payload)); err == nil {
		t.Fatal("a signature over another request was accepted")
	}
	b3, _ := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false))
	id3, s3, _ := other.answerDeployKey(t, b3)
	if _, err := c.DeployKeyFinish(id3, s3, p.sign(b3.Payload)); err == nil {
		t.Fatal("another phone's share opened the token store")
	}
	if len(g.seen) != 0 || len(g.keys) != 0 {
		t.Fatal("GitHub was called without the phone's approval")
	}
}

// the minter checks the phone-signed request itself: ✱ a begin secrets didn't sign, ✱ the phone's signature over
// another begin, ✱ a keys statement another key signed, ✱ the token sealed for another request, ✱ one approval twice
func TestTheMinterChecksThePhoneItself(t *testing.T) {
	k := newKernel(t)
	g := withMinter(t, k.w, k.c)
	pl(t)(writeStore(t, k.c, k.p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: g.token}))
	m := k.c.minter
	keys := pl2(t)(k.c.KeysStatement())
	mid := k.w.C["minter"].Identity
	begin := func(repo string) (SignedDoc, string) {
		b := pl2(t)(k.c.DeployKeyBegin(keyRequest(t, k.c, k.p, "add", repo, false)))
		var x struct{ Pending string }
		json.Unmarshal([]byte(b.Payload), &x)
		return b, x.Pending
	}
	token := func(pending string) sig.Sealed {
		s, _ := sig.SealTo(mid.AgreementKey, []byte(g.token), minter.TokenInfo+pending)
		return s
	}
	b, pend := begin("DE0CH/x")
	other, _ := sig.NewSigner()
	forged, _ := other.SignJSON(json.RawMessage(b.Payload))
	b2, pend2 := begin("DE0CH/y")
	otherKeys, _ := other.SignJSON(map[string]string{"kind": "keys", "phone": k.p.signingKey()})
	for name, req := range map[string]minter.Request{
		"a begin secrets didn't sign":        {Begin: forged, PhoneSig: k.p.sign(b.Payload), Keys: keys, Token: token(pend)},
		"the phone's signature over another": {Begin: b, PhoneSig: k.p.sign(b2.Payload), Keys: keys, Token: token(pend)},
		"another phone's signature":          {Begin: b, PhoneSig: newPhone().sign(b.Payload), Keys: keys, Token: token(pend)},
		"keys another key signed":            {Begin: b, PhoneSig: k.p.sign(b.Payload), Keys: otherKeys, Token: token(pend)},
		"the token for another request":      {Begin: b2, PhoneSig: k.p.sign(b2.Payload), Keys: keys, Token: token(pend)},
	} {
		if _, err := m.Mint(req); err == nil {
			t.Fatalf("%s: minted", name)
		}
	}
	if len(g.seen) != 0 {
		t.Fatal("GitHub was called for a refused request")
	}
	good := minter.Request{Begin: b2, PhoneSig: k.p.sign(b2.Payload), Keys: keys, Token: token(pend2)}
	if _, err := m.Mint(good); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Mint(good); err == nil || len(g.seen) != 1 {
		t.Fatal("one approval reached GitHub twice")
	}
}

func TestDeployKeyRefusals(t *testing.T) {
	c, p, _ := setup(t)
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false)); err == nil || !strings.Contains(err.Error(), DeployKeyTokenStore) {
		t.Fatal("began without the token store:", err)
	}
	pl(t)(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{"OTHER": "x"}))
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false)); err == nil || !strings.Contains(err.Error(), DeployKeyTokenStore) {
		t.Fatal("a token store without the token:", err)
	}
	pl(t)(writeStore(t, c, p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: "t"}))
	for _, bad := range []string{"", "x", "DE0CH/", "/x", "DE0CH/a/b", "DE0CH/..", "-x/y", "DE0CH/a b", "DE0CH/."} {
		if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", bad, false)); err == nil {
			t.Fatalf("repo %q accepted", bad)
		}
	}
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "rotate", "DE0CH/x", false)); err == nil {
		t.Fatal("an unknown action")
	}
	// no minter in the roster: refused before anything leaves secrets
	b := pl2(t)(c.DeployKeyBegin(keyRequest(t, c, p, "add", "DE0CH/x", false)))
	id, s, sg := p.answerDeployKey(t, b)
	if _, err := c.DeployKeyFinish(id, s, sg); err == nil || !strings.Contains(err.Error(), "minter") {
		t.Fatal("finished with no minter:", err)
	}
	empty, _ := newSecrets(t)
	if _, err := empty.DeployKeyBegin(keyRequest(t, empty, p, "add", "DE0CH/x", false)); err == nil {
		t.Fatal("an empty secrets began")
	}
}

func TestDeployKeyTokenWithoutAdministration(t *testing.T) {
	c, g, p := deployKeyCore(t)
	g.refuse["DE0CH/x"] = true
	_, err := deployKey(t, c, p, "add", "DE0CH/x", false)
	if err == nil || !strings.Contains(err.Error(), "github: HTTP 403") {
		t.Fatal("no GitHub status:", err)
	}
	if e, ok := err.(*Err); !ok || e.Status != 502 {
		t.Fatal("not a 502:", err)
	}
	if _, ok := c.stores["github-x"]; ok {
		t.Fatal("a store was made though GitHub refused")
	}
}

func TestOpenSSHKeyFormat(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pem := OpenSSHPrivateKey(priv, "c")
	body := strings.Join(strings.Split(strings.TrimSpace(string(pem)), "\n")[1:len(strings.Split(strings.TrimSpace(string(pem)), "\n"))-1], "")
	raw, err := b64.DecodeString(body)
	if err != nil || !strings.HasPrefix(string(raw), "openssh-key-v1\x00") {
		t.Fatal("not an openssh-key-v1 file")
	}
	if !strings.Contains(string(raw), string(pub)) {
		t.Fatal("the public key isn't in the file")
	}
}

// colliding repos share a store name: the second repo's add (or remove) is refused with 409 naming the owner, and
// GitHub is never called for it; the owning repo still re-adds and removes, after which the name is free
func TestDeployKeyStoreClashRefused(t *testing.T) {
	c, g, p := deployKeyCore(t)
	if repoStore("DE0CH/foo-bar") != repoStore("foo/bar") || repoStore("DE0CH/my.repo") != repoStore("DE0CH/My-Repo") {
		t.Fatal("the test's repos don't collide")
	}
	if _, err := deployKey(t, c, p, "add", "DE0CH/foo-bar", false); err != nil {
		t.Fatal(err)
	}
	calls := len(g.seen)
	for _, action := range []string{"add", "remove"} {
		_, err := c.DeployKeyBegin(keyRequest(t, c, p, action, "foo/bar", false))
		if e, ok := err.(*Err); !ok || e.Status != 409 || !strings.Contains(err.Error(), "store github-foo-bar belongs to DE0CH/foo-bar") {
			t.Fatalf("%s for a colliding repo: %v", action, err)
		}
	}
	// a begin taken before the store was owned is refused at finish, before GitHub
	c2, g2, p2 := deployKeyCore(t)
	early, _ := c2.DeployKeyBegin(keyRequest(t, c2, p2, "add", "DE0CH/My-Repo", false))
	if _, err := deployKey(t, c2, p2, "add", "DE0CH/my.repo", false); err != nil {
		t.Fatal(err)
	}
	n2 := len(g2.seen)
	id, s, sig := p2.answerDeployKey(t, early)
	if _, err := c2.DeployKeyFinish(id, s, sig); err == nil || !strings.Contains(err.Error(), "belongs to DE0CH/my.repo") {
		t.Fatal("a pending add for a colliding repo finished:", err)
	}
	if len(g.seen) != calls || len(g2.seen) != n2 || len(g2.keys["DE0CH/My-Repo"]) != 0 {
		t.Fatal("GitHub was called for a refused repo")
	}
	if v := storeValues(t, c2, p2, "github-my-repo"); v["GITHUB_DEPLOY_REPO_DE0CH_MY_REPO"] != "DE0CH/my.repo" {
		t.Fatal("the owner's store was replaced:", keysOf(v))
	}
	if _, err := deployKey(t, c, p, "add", "de0ch/FOO-BAR", false); err != nil {
		t.Fatal("the owner's re-add:", err)
	}
	if m, err := deployKey(t, c, p, "remove", "DE0CH/foo-bar", false); err != nil || m["kind"] != "deploy-key-removed" {
		t.Fatal("the owner's remove:", m, err)
	}
	if _, err := deployKey(t, c, p, "add", "foo/bar", false); err != nil {
		t.Fatal("the freed name:", err)
	}
	if c.repoOwner["github-foo-bar"] != "foo/bar" {
		t.Fatal(c.repoOwner)
	}
}

// a Recover keeps each deploy-key store's owner: the bundle's owners (the app reads them from the stores), for
// stores the bundle holds and repos that are repos. A bundle carries no key ids: a remove then deletes only the store
// (GitHub isn't called; the router finds the orphan)
func TestDeployKeyRecoverKeepsTheOwner(t *testing.T) {
	w := kt.New(t)
	c, _ := New(w.Root.PublicKey(), nil)
	master, p := newPhone(), newPhone()
	rb := recoverBundle(t, c, p)
	rb.Stores = append(rb.Stores, "github-foo-bar", "github-odd", DeployKeyTokenStore)
	rb.Keys = append(append(append(rb.Keys,
		appWrap(t, c, p, "github-foo-bar", map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_FOO_BAR": "DE0CH/foo-bar", "GITHUB_DEPLOY_KEY_DE0CH_FOO_BAR": "x"})...),
		appWrap(t, c, p, "github-odd", map[string]string{"GITHUB_DEPLOY_REPO_DE0CH_OTHER": "DE0CH/other"})...),
		appWrap(t, c, p, DeployKeyTokenStore, map[string]string{DeployKeyTokenKey: "gh-admin-token"})...)
	rb.Owners = map[string]string{"github-foo-bar": "DE0CH/foo-bar", "github-odd": "not a repo", "github-gone": "DE0CH/gone"}
	s, sg, b := claimFor(c, master, p, newPhone(), rb)
	pl(t)(c.Claim(s, sg, b))
	g := withMinter(t, w, c)
	if len(c.repoOwner) != 1 || c.repoOwner["github-foo-bar"] != "DE0CH/foo-bar" {
		t.Fatalf("owners after Recover: %v", c.repoOwner)
	}
	if _, err := c.DeployKeyBegin(keyRequest(t, c, p, "add", "foo/bar", false)); err == nil || !strings.Contains(err.Error(), "belongs to DE0CH/foo-bar") {
		t.Fatal("a Recover lost the owner:", err)
	}
	if m, err := deployKey(t, c, p, "remove", "DE0CH/foo-bar", false); err != nil || m["deleted"] != float64(0) || len(g.seen) != 0 {
		t.Fatal("a remove with no key id known:", m, err, len(g.seen))
	}
	if _, err := deployKey(t, c, p, "add", "DE0CH/foo-bar", false); err != nil {
		t.Fatal("the re-add after Recover:", err)
	}
}

// two colliding adds in flight: the one that loses is refused naming its new key, an orphan on GitHub, and writes nothing
func TestDeployKeyClashRaceLeavesAnOrphan(t *testing.T) {
	c, g, p := deployKeyCore(t)
	g.onAdd = func() {
		c.mu.Lock()
		c.repoOwner["github-foo-bar"] = "foo/bar"
		c.mu.Unlock()
	}
	_, err := deployKey(t, c, p, "add", "DE0CH/foo-bar", false)
	if err == nil || !strings.Contains(err.Error(), "belongs to foo/bar") || !strings.Contains(err.Error(), "orphan") {
		t.Fatal("the losing add went through:", err)
	}
	if len(g.keys["DE0CH/foo-bar"]) != 1 || len(g.seen) != 1 {
		t.Fatal("the losing add made more than its one GitHub call")
	}
	if _, ok := c.stores["github-foo-bar"]; ok {
		t.Fatal("the losing add wrote the store")
	}
}

// ---- the app's form: the app makes the key pair and wraps the store to the store key P + K ------------------------

// appKey: what the app does before Face ID — an ed25519 pair, the store's values (the same format as the app's), the
// data key wrapped to the store key it computes (P + K)
func appKey(t *testing.T, c *Secrets, p *phone, repo, store string) (string, []KeyEntry, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := appWrap(t, c, p, store, map[string]string{deployRepoPrefix + envSlug(repo): repo,
		deployKeyPrefix + envSlug(repo): b64.EncodeToString(OpenSSHPrivateKey(priv, "jarvis4 "+store))})
	return "ssh-ed25519 " + b64.EncodeToString(sshPublicWire(pub)), keys, priv
}

func TestDeployKeyFromTheAppsKeyPair(t *testing.T) {
	c, g, p := deployKeyCore(t)
	pub, keys, priv := appKey(t, c, p, "DE0CH/china-train", "github-china-train")
	req := DeployKeyRequest{Action: "add", Repo: "DE0CH/china-train", Store: "github-china-train", Title: "jarvis4 github-china-train", PublicKey: pub, Keys: keys}
	moved := func(to string) []KeyEntry {
		out := append([]KeyEntry{}, keys...)
		for i := range out {
			out[i].Store = to
		}
		return out
	}
	for name, bad := range map[string]func(*DeployKeyRequest){
		"no public key":    func(r *DeployKeyRequest) { r.PublicKey = "" },
		"no keys":          func(r *DeployKeyRequest) { r.Keys = nil },
		"keys for another": func(r *DeployKeyRequest) { r.Keys = moved("github-other") },
		"a key twice":      func(r *DeployKeyRequest) { r.Keys = append(append([]KeyEntry{}, keys...), keys[0]) },
		"the token store":  func(r *DeployKeyRequest) { r.Store, r.Keys = DeployKeyTokenStore, moved(DeployKeyTokenStore) },
		"no store":         func(r *DeployKeyRequest) { r.Store = "" },
		"an add by id":     func(r *DeployKeyRequest) { r.KeyID = 5 },
	} {
		in := req
		bad(&in)
		if _, err := c.DeployKeyBegin(in); err == nil {
			t.Fatalf("%s: began", name)
		}
	}
	b := pl(t)(c.DeployKeyBegin(req))
	named, _ := b["keys"].([]any)
	if b["publicKey"] != pub || len(named) != 2 || named[0].(map[string]any)["e"] != keys[0].Wrapped.E || named[0].(map[string]any)["dataSha256"] != sha256Hex(keys[0].Data) {
		t.Fatalf("the begin document doesn't name the key pair: %v", b)
	}
	d, _ := c.DeployKeyBegin(req)
	id, s, sig := p.answerDeployKey(t, d)
	a := pl(t)(c.DeployKeyFinish(id, s, sig))
	if a["kind"] != "deploy-key-added" || a["publicKey"] != pub || a["fingerprint"] != nil {
		t.Fatalf("answer %v", a)
	}
	if ks := g.keys["DE0CH/china-train"]; len(ks) != 1 || ks[0].Key != pub {
		t.Fatalf("GitHub got %v", ks)
	}
	if got := c.stores["github-china-train"][keys[0].Key]; got == nil || got.Data != keys[0].Data || got.Writer.By != "core" {
		t.Fatal("the store isn't the app's blob, vouched by secrets")
	}
	v := storeValues(t, c, p, "github-china-train")
	k, _ := b64.DecodeString(v["GITHUB_DEPLOY_KEY_DE0CH_CHINA_TRAIN"])
	if !strings.Contains(string(k), "OPENSSH PRIVATE KEY") || priv == nil {
		t.Fatal("the store doesn't hold the app's private key")
	}
}

// ---- the app's OpenSSH key (ios OpenSSH.ed25519), as a Go stand-in for the tests ----------------------------------

func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// sshPublicWire: the public key blob (RFC 8709): string "ssh-ed25519", string key
func sshPublicWire(pub ed25519.PublicKey) []byte {
	return append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
}

// OpenSSHPrivateKey: the key as an unencrypted OpenSSH private key file (PROTOCOL.key), what `ssh -i` reads
func OpenSSHPrivateKey(priv ed25519.PrivateKey, comment string) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	check := make([]byte, 4)
	rand.Read(check)
	var sec []byte
	sec = append(sec, check...)
	sec = append(sec, check...)
	sec = append(sec, sshString([]byte("ssh-ed25519"))...)
	sec = append(sec, sshString(pub)...)
	sec = append(sec, sshString(priv)...) // seed || public, 64 bytes
	sec = append(sec, sshString([]byte(comment))...)
	for i := byte(1); len(sec)%8 != 0; i++ {
		sec = append(sec, i)
	}
	var b []byte
	b = append(b, "openssh-key-v1\x00"...)
	b = append(b, sshString([]byte("none"))...)
	b = append(b, sshString([]byte("none"))...)
	b = append(b, sshString(nil)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, sshString(sshPublicWire(pub))...)
	b = append(b, sshString(sec)...)
	enc := b64.EncodeToString(b)
	var out strings.Builder
	out.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return []byte(out.String())
}
