package spawner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const serialTestID = "i-0123456789abcdef0"

var serialTestKeys = `{"encryptionKey":"ZW5j","signingKey":"c2ln"}`

// fakeSerial: EC2 Instance Connect's push and the serial console's SSH endpoint, as AWS runs them: a pushed key opens
// one session for its instance's port 0, and the session streams the console
type fakeSerial struct {
	t        *testing.T
	api      *httptest.Server
	ln       net.Listener
	hostKey  ssh.Signer
	mu       sync.Mutex
	pushed   map[string]bool // authorized keys, by their marshalled form
	pushes   []*http.Request
	bodies   []string
	refuse   string        // a push answered with this exception
	console  func() string // what the session streams (then it stays open)
	written  atomic.Int64  // bytes the client wrote to the console
	sessions atomic.Int32
	closed   chan struct{} // a session's connection ended
}

func newFakeSerial(t *testing.T) *fakeSerial {
	f := &fakeSerial{t: t, pushed: map[string]bool{}, closed: make(chan struct{}, 8),
		console: func() string {
			return "[   13.8] systemd[1]: booting\r\nip-10-40-0-9 login: JARVIS2-KEYS " + serialTestKeys + "\r\n"
		}}
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	f.hostKey, _ = ssh.NewSignerFromKey(hk)
	f.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.pushes = append(f.pushes, r)
		f.bodies = append(f.bodies, string(b))
		refuse := f.refuse
		f.mu.Unlock()
		if refuse != "" {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"__type":"com.amazon.aws.ec2instanceconnect#%s","Message":"refused"}`, refuse)
			return
		}
		var in struct {
			InstanceId   string
			SerialPort   int
			SSHPublicKey string
		}
		if json.Unmarshal(b, &in) != nil || in.InstanceId != serialTestID || in.SerialPort != 0 {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		f.pushed[in.SSHPublicKey] = true
		f.mu.Unlock()
		fmt.Fprint(w, `{"RequestId":"r","Success":true}`)
	}))
	t.Cleanup(f.api.Close)
	var err error
	if f.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.ln.Close() })
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		m := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
		if c.User() != serialTestID+".port0" || !f.pushed[m] {
			return nil, fmt.Errorf("no key pushed for %s", c.User())
		}
		delete(f.pushed, m) // one session per push
		return nil, nil
	}}
	cfg.AddHostKey(f.hostKey)
	go func() {
		for {
			c, err := f.ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, cfg)
		}
	}()
	return f
}

func (f *fakeSerial) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer func() { f.closed <- struct{}{} }()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		f.sessions.Add(1)
		go func() {
			for r := range creqs {
				r.Reply(r.Type == "pty-req" || r.Type == "shell", nil)
				if r.Type == "shell" {
					go func() {
						time.Sleep(50 * time.Millisecond)
						for _, part := range splitEvery(f.console(), 7) { // the stream arrives in pieces
							ch.Write([]byte(part))
						}
					}()
				}
			}
		}()
		go func() { // as AWS's: the client's EOF ends the session
			n, _ := io.Copy(io.Discard, ch)
			f.written.Add(n)
			ch.Close()
		}()
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for len(s) > n {
		out, s = append(out, s[:n]), s[n:]
	}
	return append(out, s)
}

// awsForSerial: an AWSAPI whose push, SSH and EC2 calls go to the fakes; ec2 nil: any EC2 call fails the test
func awsForSerial(t *testing.T, f *fakeSerial, ec2 http.Handler, hostKey string) *AWSAPI {
	a := NewAWSAPI()
	a.Configure(AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret"})
	if ec2 == nil {
		ec2 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			t.Errorf("an EC2 call: %s", b)
			w.WriteHeader(500)
		})
	}
	es := httptest.NewServer(ec2)
	t.Cleanup(es.Close)
	a.endpoint = func(string) string { return es.URL + "/" }
	a.serialEP = serialEndpoints{
		push:    func(string) string { return f.api.URL + "/" },
		ssh:     func(string) string { return f.ln.Addr().String() },
		hostKey: func(string) string { return hostKey },
		retry:   20 * time.Millisecond,
	}
	return a
}

func waitSerial(t *testing.T, a *AWSAPI) *MachineKeys {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if k, trying := a.serialKeys(serialTestID); k != nil || !trying {
			return k
		}
	}
	t.Fatal("the watcher neither read keys nor stopped")
	return nil
}

// the keys line read live, through a pushed one-off key and AWS's host key, reaches Init with no EC2 call; the console
// is only read, and the session closes once the keys are in
func TestSerialConsoleKeysReachInit(t *testing.T) {
	f := newFakeSerial(t)
	a := awsForSerial(t, f, nil, ssh.FingerprintSHA256(f.hostKey.PublicKey()))
	a.watchSerial("eu-west-2", serialTestID)
	a.watchSerial("eu-west-2", serialTestID) // a second start is the same watcher
	k := waitSerial(t, a)
	if k == nil || k.EncryptionKey != "ZW5j" || k.SigningKey != "c2ln" {
		t.Fatalf("keys %+v", k)
	}
	got, err := a.Init(serialTestID)
	if err != nil || got != *k {
		t.Fatalf("Init: %+v, %v", got, err)
	}
	select {
	case <-f.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the session stayed open after the keys line")
	}
	if n := f.sessions.Load(); n != 1 {
		t.Fatalf("%d sessions", n)
	}
	if n := f.written.Load(); n != 0 {
		t.Fatalf("the spawner wrote %d bytes to the console", n)
	}
	// the push: the JSON API's action, signed (X-Amz-Target among the signed headers), for port 0 of that instance
	f.mu.Lock()
	r, body := f.pushes[0], f.bodies[0]
	f.mu.Unlock()
	if r.Header.Get("X-Amz-Target") != "AWSEC2InstanceConnectService.SendSerialConsoleSSHPublicKey" ||
		!strings.Contains(r.Header.Get("Authorization"), "/ec2-instance-connect/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target,") ||
		!strings.Contains(body, `"InstanceId":"`+serialTestID+`"`) || !strings.Contains(body, `"SerialPort":0`) || !strings.Contains(body, `"SSHPublicKey":"ssh-ed25519 `) {
		t.Fatalf("push %v %s", r.Header, body)
	}
}

// an endpoint that doesn't show AWS's host key for the region is never read: no keys come from it
func TestSerialConsoleRefusesAnotherHostKey(t *testing.T) {
	f := newFakeSerial(t)
	a := awsForSerial(t, f, nil, "SHA256:a69rd5CE/AEG4Amm53I6lkD1ZPvS/BCV3tTPW2RnJg8")
	a.watchSerial("eu-west-2", serialTestID)
	if k := waitSerial(t, a); k != nil {
		t.Fatalf("keys from a wrong host: %+v", k)
	}
	if n := f.sessions.Load(); n != 0 {
		t.Fatalf("%d sessions opened on a wrong host", n)
	}
}

// a region without serial console access (or a key EC2 refuses) stops the watcher at once, and Init reads the keys
// from GetConsoleOutput as before
func TestSerialConsoleRefusedFallsBackToGetConsoleOutput(t *testing.T) {
	f := newFakeSerial(t)
	f.refuse = "SerialConsoleAccessDisabledException"
	var calls atomic.Int32
	ec2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		calls.Add(1)
		switch r.Form.Get("Action") {
		case "DescribeInstances":
			fmt.Fprintf(w, `<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>%s</instanceId><instanceState><name>running</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`, serialTestID)
		case "GetConsoleOutput":
			out := base64.StdEncoding.EncodeToString([]byte("boot\r\nJARVIS2-KEYS " + serialTestKeys + "\r\n"))
			fmt.Fprintf(w, `<GetConsoleOutputResponse><output>%s</output></GetConsoleOutputResponse>`, out)
		default:
			w.WriteHeader(400)
		}
	})
	a := awsForSerial(t, f, ec2, ssh.FingerprintSHA256(f.hostKey.PublicKey()))
	a.watchSerial("eu-west-2", serialTestID)
	if k := waitSerial(t, a); k != nil {
		t.Fatalf("keys %+v", k)
	}
	f.mu.Lock()
	pushes := len(f.pushes)
	f.mu.Unlock()
	if pushes != 1 {
		t.Fatalf("%d pushes after a refusal that won't change", pushes)
	}
	k, err := a.Init(serialTestID)
	if err != nil || k.EncryptionKey != "ZW5j" || calls.Load() == 0 {
		t.Fatalf("Init: %+v, %v", k, err)
	}
}

// an instance that isn't running yet refuses the push; the watcher asks again until it can read
func TestSerialConsoleWaitsForTheInstance(t *testing.T) {
	f := newFakeSerial(t)
	f.refuse = "EC2InstanceStateInvalidException"
	a := awsForSerial(t, f, nil, ssh.FingerprintSHA256(f.hostKey.PublicKey()))
	a.watchSerial("eu-west-2", serialTestID)
	time.Sleep(100 * time.Millisecond)
	if k, trying := a.serialKeys(serialTestID); k != nil || !trying {
		t.Fatalf("keys %+v, trying %v", k, trying)
	}
	f.mu.Lock()
	f.refuse = ""
	f.mu.Unlock()
	if k := waitSerial(t, a); k == nil {
		t.Fatal("no keys once the instance ran")
	}
}

// a console that hasn't written the keys yet keeps the session open; Destroy closes it and forgets the watcher
func TestSerialConsoleStopsOnDestroy(t *testing.T) {
	f := newFakeSerial(t)
	f.console = func() string { return "still booting\r\n" }
	ec2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<DescribeInstancesResponse><reservationSet></reservationSet></DescribeInstancesResponse>`)
	})
	a := awsForSerial(t, f, ec2, ssh.FingerprintSHA256(f.hostKey.PublicKey()))
	a.watchSerial("eu-west-2", serialTestID)
	for end := time.Now().Add(5 * time.Second); f.sessions.Load() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("no session")
		}
	}
	if err := a.Destroy(serialTestID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the session stayed open after Destroy")
	}
	if _, trying := a.serialKeys(serialTestID); trying {
		t.Fatal("the watcher is still known")
	}
}

// a region with no published host key has no live reader (GetConsoleOutput only)
func TestSerialConsoleOnlyWhereAWSPublishesAHostKey(t *testing.T) {
	for r := range AWSRegions {
		if !strings.HasPrefix(serialHostKeys[r], "SHA256:") || len(serialHostKeys[r]) != 50 {
			t.Fatalf("%s: host key %q", r, serialHostKeys[r])
		}
	}
	a := NewAWSAPI()
	a.watchSerial("us-east-1", serialTestID)
	if _, trying := a.serialKeys(serialTestID); trying {
		t.Fatal("a watcher with no host key to check")
	}
}

func TestKeysFromAConsoleLine(t *testing.T) {
	for line, want := range map[string]bool{
		"JARVIS2-KEYS " + serialTestKeys:                     true,
		"ip-10-40-0-9 login: JARVIS2-KEYS " + serialTestKeys: true, // the getty's prompt first
		"JARVIS2-KEYS " + serialTestKeys + "\r":              true,
		"[ 13.8] systemd[1]: Started docker.service":         false,
	} {
		k, ok, err := keysFromLine(line)
		if err != nil || ok != want || (ok && k.SigningKey != "c2ln") {
			t.Fatalf("%q: %+v %v %v", line, k, ok, err)
		}
	}
	if _, _, err := keysFromLine(`JARVIS2-KEYS {"encryptionKey":""}`); err == nil {
		t.Fatal("a keys line with no keys")
	}
	if _, err := scanKeys(strings.NewReader("boot\r\nmore\r\n")); err == nil {
		t.Fatal("keys from a console without the line")
	}
}

// Live, by hand (skipped unless set): SERIAL_LIVE_KEY=<an OpenSSH private key file> SERIAL_LIVE_INSTANCE=i-…
// SERIAL_LIVE_REGION=…: that instance's keys line through AWS's real endpoint and pinned host key, with the key pushed
// by hand (aws ec2-instance-connect send-serial-console-ssh-public-key), connecting again until it reads it
func TestSerialConsoleLive(t *testing.T) {
	path, id, region := os.Getenv("SERIAL_LIVE_KEY"), os.Getenv("SERIAL_LIVE_INSTANCE"), os.Getenv("SERIAL_LIVE_REGION")
	if path == "" {
		t.Skip("SERIAL_LIVE_KEY unset")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAWSAPI()
	for end := time.Now().Add(10 * time.Minute); time.Now().Before(end); time.Sleep(2 * time.Second) {
		k, err := a.readSerialWith(region, id, signer, make(chan struct{}))
		if k != nil {
			t.Logf("SERIAL-LIVE keys at=%.3f %s %s", float64(time.Now().UnixNano())/1e9, k.EncryptionKey[:12], k.SigningKey[:12])
			return
		}
		if errors.Is(err, errSerialHostKey) {
			t.Fatal(err)
		}
		t.Logf("SERIAL-LIVE try at=%.3f: %v", float64(time.Now().UnixNano())/1e9, err)
	}
	t.Fatal("no keys line in 10 min")
}

// Live (skipped unless SERIAL_LIVE_HOSTKEYS is set): every session region's endpoint shows the host key pinned here
func TestSerialHostKeysLive(t *testing.T) {
	if os.Getenv("SERIAL_LIVE_HOSTKEYS") == "" {
		t.Skip("SERIAL_LIVE_HOSTKEYS unset")
	}
	ep := defaultSerialEndpoints()
	for region := range AWSRegions {
		var seen string
		cfg := &ssh.ClientConfig{User: "i-0.port0", Timeout: 20 * time.Second,
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				seen = ssh.FingerprintSHA256(k)
				return errors.New("only looking")
			}}
		ssh.Dial("tcp", ep.ssh(region), cfg)
		t.Logf("SERIAL-LIVE hostkey %s %s", region, seen)
		if seen != serialHostKeys[region] {
			t.Errorf("%s shows %q, pinned %q", region, seen, serialHostKeys[region])
		}
	}
}
