package main

// The Claude accounts in the core (DECISIONS 185, 190). Each account is the core store claude-<name>: the router, its
// only refresher, writes the account's pair (CLAUDE_CREDENTIALS, ~/.claude/.credentials.json) and record
// (CLAUDE_ACCOUNT, ~/.claude.json's oauthAccount) into it whenever they change, as the per-key write does, sealed to the
// store key P + K, with no approval (the core's writer `router`, allowed for claude-* stores only and named "router"
// on every unlock). A session whose cert names its account's store gets the pair through its store like any other
// secret, the account vouched for by the phone at Start; its machine then keeps in step through the router's long
// poll (claudelogin.go), since the pair rotates every 8 hours with nobody there to unlock it.
//
// What is still the router's: the working copy it refreshes with (the core can't hand a store back without the phone),
// on its volume as before. These writes have no bucket backup and file no Inbox refresh: an earlier pair is worthless
// once rotated, a Recover leaves the claude-* stores to this router (it writes them again within a minute of seeing a
// core without them), and running sessions take refreshes from the long poll.
//
// The loop (loginLoop, every minute) writes an account whose pair or record changed since it was last written to this
// core (or to any core: a new core, a Recover, the move). A core that has no router writer (from before 190) refuses;
// that is logged once per account and retried every 10 minutes.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DE0CH/jarvis4/kernel/sig"
)

// claudeStoreInCert: a new session's cert names its account's store (claude-<name>), so the phone vouches for the
// account and the session gets its pair from its store. The router's env CLAUDE_STORE_IN_CERT=1 (k8s/control/apps/router/router.yaml),
// set only once Deyao's iPhone runs an app that accepts the router as a key's writer (ios Checks.keyWriter "router"):
// an older app refuses to unlock such a store, so Start would fail. Like SIGN_CLAUDE_ACCOUNT.
var claudeStoreInCert = os.Getenv("CLAUDE_STORE_IN_CERT") == "1"

// accountStoreState: what was last written for one account (router memory only: a restart writes once more)
type accountStoreState struct {
	written string    // sha256 of core key + pair + record last written
	retry   time.Time // after a failure
	lastErr string
}

var (
	accountStoreMu sync.Mutex
	accountStores  = map[string]*accountStoreState{}
)

// withAccountStore: a new line's stores plus its account's store (when certs name it)
func withAccountStore(stores []string, account string) []string {
	if !claudeStoreInCert || account == "" || containsStr(stores, account) {
		return stores
	}
	out := append(append([]string{}, stores...), account)
	sort.Strings(out)
	return out
}

// syncAccountStores: every account whose pair or record changed since it was last written into this core
func (r *Router) syncAccountStores() {
	if r.storeCore() == nil {
		return
	}
	key, err := r.storeCore().Key()
	if err != nil {
		return
	}
	for _, h := range r.accounts().all() {
		v := h.current()
		if v.Credentials == "" {
			continue
		}
		sum := sha256.Sum256([]byte(key["signingKey"] + "\n" + v.Credentials + "\n" + v.Account))
		want := fmt.Sprintf("%x", sum)
		accountStoreMu.Lock()
		st := accountStores[h.store]
		if st == nil {
			st = &accountStoreState{}
			accountStores[h.store] = st
		}
		skip := st.written == want || time.Now().Before(st.retry)
		accountStoreMu.Unlock()
		if skip {
			continue
		}
		err := r.writeAccountStore(h.store, v.Credentials, v.Account)
		accountStoreMu.Lock()
		if err != nil {
			if err.Error() != st.lastErr {
				log.Printf("[accounts] %s: writing it into the core: %v (tried again every 10 minutes)", h.store, err)
			}
			st.retry, st.lastErr = time.Now().Add(10*time.Minute), err.Error()
		} else {
			if st.written == "" || st.lastErr != "" {
				log.Printf("[accounts] %s: written into the core's store %s", h.store, h.store)
			}
			st.written, st.retry, st.lastErr = want, time.Time{}, ""
		}
		accountStoreMu.Unlock()
	}
}

// forgetAccountStore: a removed account's keys leave its core store (a store itself can't be deleted)
func (r *Router) forgetAccountStore(store string) {
	if r.storeCore() == nil {
		return
	}
	for _, k := range []string{"CLAUDE_CREDENTIALS", "CLAUDE_ACCOUNT"} {
		if err := r.writeRouterKey(store, k, nil, true); err != nil {
			log.Printf("[accounts] %s: deleting %s from the core: %v", store, k, err)
		}
	}
	accountStoreMu.Lock()
	delete(accountStores, store)
	accountStoreMu.Unlock()
}

// writeAccountStore: the store made (not sensitive: a Claude login can't reach a code push) if the core lacks it, then
// both keys
func (r *Router) writeAccountStore(store, credentials, account string) error {
	if _, err := r.storeCore().Call("/stores/create", map[string]string{"name": store}); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("making the store: %w", err)
	}
	if err := r.writeRouterKey(store, "CLAUDE_CREDENTIALS", []byte(credentials), false); err != nil {
		return err
	}
	if account == "" {
		return nil
	}
	return r.writeRouterKey(store, "CLAUDE_ACCOUNT", []byte(account), false)
}

// writeRouterKey: one key sealed to the core's store key and written as the router (core/keys.go writer "router")
func (r *Router) writeRouterKey(store, key string, value []byte, del bool) error {
	in := map[string]any{"store": store, "key": key, "writer": "router", "delete": del}
	if !del {
		storeKey, err := r.routerStoreKey()
		if err != nil {
			return err
		}
		dk := make([]byte, 32)
		rand.Read(dk)
		e, wrapped, err := sealToPoint(storeKey, dk, "jarvis2/store-data-key", nil)
		if err != nil {
			return fmt.Errorf("the store key: %w", err)
		}
		in["wrapped"] = map[string]string{"e": e, "wrapped": wrapped}
		in["data"] = base64.StdEncoding.EncodeToString(gcmSealKey(dk, value, []byte(store+"\n"+key)))
	}
	d, err := r.storeCore().Call("/stores/write-key", in)
	if err != nil && del && strings.Contains(err.Error(), "has no key") {
		return nil
	}
	if err == nil { // storeversions.go: the version this write makes (a box with no core)
		var entry *verEntry
		if !del {
			wb, _ := json.Marshal(in["wrapped"])
			entry = &verEntry{Wrapped: wb, Data: in["data"].(string)}
		}
		r.recordKeyWrite(store, key, entry, d)
	}
	return err
}

// routerStoreKey: P + K for the router's own writes — the core's signed store key, or on a box with no core computed
// from secrets' identity (its agreement key and the phone its signed state names)
func (r *Router) routerStoreKey() (string, error) {
	t, err := r.storeKeyFor()
	if err != nil {
		return "", err
	}
	if r.secretsStores != nil {
		var id struct {
			AgreementKey string `json:"agreementKey"`
			State        *Doc   `json:"state"`
		}
		var st struct {
			Phone struct {
				AgreementKey string `json:"agreementKey"`
			} `json:"phone"`
		}
		raw, _ := t["identity"].(json.RawMessage)
		if json.Unmarshal(raw, &id) != nil || id.State == nil || id.State.Decode(&st) != nil {
			return "", fmt.Errorf("secrets' identity isn't readable")
		}
		return sig.StoreKey(st.Phone.AgreementKey, id.AgreementKey)
	}
	var sk struct {
		StoreKey string `json:"storeKey"`
	}
	d, _ := t["storeKey"].(*Doc)
	if d == nil || d.Decode(&sk) != nil || sk.StoreKey == "" {
		return "", fmt.Errorf("the core answered no store key")
	}
	return sk.StoreKey, nil
}

// sealToPoint: ephemeral ECDH with the recipient point, HKDF-SHA256(info), AES-256-GCM (nonce ‖ ciphertext ‖ tag),
// as machine/putkey.go sealParts and core WrapToPoint
func sealToPoint(recipientB64 string, plain []byte, info string, aad []byte) (string, string, error) {
	rb, err := base64.StdEncoding.DecodeString(recipientB64)
	if err != nil {
		return "", "", err
	}
	rk, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		return "", "", err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	x, err := e.ECDH(rk)
	if err != nil {
		return "", "", err
	}
	k, err := hkdf.Key(sha256.New, x, nil, info, 32)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(e.PublicKey().Bytes()), base64.StdEncoding.EncodeToString(gcmSealKey(k, plain, aad)), nil
}

func gcmSealKey(key, plain, aad []byte) []byte {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}
