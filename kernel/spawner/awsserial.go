package spawner

// An AWS machine's keys line, read live from the instance's serial console (the EC2 Serial Console, over SSH) instead
// of waiting for GetConsoleOutput, whose newest output EC2 refreshes only every 30-40 s (measured 2026-11-04:
// docs/PLAN-aws.md): the line reaches the spawner within a second of the machine writing it. GetConsoleOutput stays
// the fallback (Init), so a region without serial console access, a refused key or a dropped connection only costs
// that wait again.
//
// The link to the instance is still AWS's word: the spawner pushes a one-off key for that instance id
// (SendSerialConsoleSSHPublicKey, its own AWS key, the same tagged instances as GetConsoleOutput) and the SSH endpoint
// must show the host key AWS publishes for the region (serialHostKeys), so only AWS's serial console service can
// answer, and it answers only with that instance's ttyS0. The spawner never writes to the console: the channel is
// read until the keys line, then closed. (The console is the getty's too; Flatcar's asks for a login and the core user
// has no password.)

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// serialHostKeys: the EC2 Serial Console's SSH host key per session region, as AWS publishes them (EC2 User Guide,
// "EC2 Serial Console endpoints and fingerprints"). eu-west-2's was also seen on the endpoint on 2026-11-04.
var serialHostKeys = map[string]string{
	"eu-west-2":      "SHA256:a69rd5CE/AEG4Amm53I6lkD1ZPvS/BCV3tTPW2RnJg8",
	"ap-southeast-1": "SHA256:PLFNn7WnCQDHx3qmwLu1Gy/O8TUX7LQgZuaC6L45CoY",
	"ap-northeast-1": "SHA256:RQfsDCZTOfQawewTRDV1t9Em/HMrFQe+CRlIOT5um4k",
}

// serialWatchMax: how long a watcher keeps trying (the router's own wait for init is 10 min)
const serialWatchMax = 10 * time.Minute

// serialLine: at most this much of one console line is kept (a keys line is ~250 bytes)
const serialLineMax = 64 << 10

// serialWatch: one instance's watcher: the keys once read
type serialWatch struct {
	keys    *MachineKeys
	stopped bool // given up or done (Init falls back to GetConsoleOutput unless keys is set)
	cancel  chan struct{}
}

// serialEndpoints: where the push and the SSH go (vars on AWSAPI: tests point them at fakes)
type serialEndpoints struct {
	push    func(region string) string // the EC2 Instance Connect API
	ssh     func(region string) string // the serial console's host:port
	hostKey func(region string) string // the SSH host key's SHA256 fingerprint ("" = no serial console there)
	retry   time.Duration
}

func defaultSerialEndpoints() serialEndpoints {
	return serialEndpoints{
		push:    func(region string) string { return "https://ec2-instance-connect." + region + ".amazonaws.com/" },
		ssh:     func(region string) string { return "serial-console.ec2-instance-connect." + region + ".aws:22" },
		hostKey: func(region string) string { return serialHostKeys[region] },
		retry:   2 * time.Second,
	}
}

// watchSerial: start reading id's serial console for its keys line, unless a watcher for it exists
func (a *AWSAPI) watchSerial(region, id string) {
	if a.serialEP.hostKey(region) == "" {
		return
	}
	a.mu.Lock()
	if a.serial == nil {
		a.serial = map[string]*serialWatch{}
	}
	if _, ok := a.serial[id]; ok {
		a.mu.Unlock()
		return
	}
	w := &serialWatch{cancel: make(chan struct{})}
	a.serial[id] = w
	a.mu.Unlock()
	go a.runSerial(region, id, w)
}

// serialKeys: the keys the watcher read; whether one is still trying
func (a *AWSAPI) serialKeys(id string) (*MachineKeys, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w := a.serial[id]
	if w == nil {
		return nil, false
	}
	return w.keys, !w.stopped
}

// stopSerial: the instance is going (Destroy): its watcher stops and is forgotten
func (a *AWSAPI) stopSerial(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if w := a.serial[id]; w != nil {
		if !w.stopped {
			w.stopped = true
			close(w.cancel)
		}
		delete(a.serial, id)
	}
}

func (a *AWSAPI) runSerial(region, id string, w *serialWatch) {
	deadline := time.Now().Add(serialWatchMax)
	done := func(k *MachineKeys, why string) {
		a.mu.Lock()
		if !w.stopped {
			w.keys, w.stopped = k, true
			close(w.cancel)
		}
		a.mu.Unlock()
		if why != "" {
			log.Printf("[aws] %s serial console: %s (the keys come from GetConsoleOutput)", id, why)
		}
	}
	for time.Now().Before(deadline) {
		select {
		case <-w.cancel:
			return
		default:
		}
		k, err := a.readSerialOnce(region, id, w.cancel)
		if k != nil {
			done(k, "")
			return
		}
		var ae *AWSError
		if errors.As(err, &ae) && serialFatal(ae.Code) || errors.Is(err, errSerialHostKey) {
			done(nil, err.Error())
			return
		}
		select {
		case <-w.cancel:
			return
		case <-time.After(a.serialEP.retry):
		}
	}
	done(nil, "no keys line in "+serialWatchMax.String())
}

// errSerialHostKey: the endpoint showed a host key other than AWS's for the region; asking again won't change that
var errSerialHostKey = errors.New("not AWS's serial console host key")

// serialFatal: a refusal that won't change by asking again (the account's or the key's, not the instance's state)
func serialFatal(code string) bool {
	switch code {
	case "SerialConsoleAccessDisabledException", "AccessDeniedException", "UnrecognizedClientException",
		"InvalidSignatureException", "EC2InstanceTypeInvalidException", "EC2InstanceNotFoundException":
		return true
	}
	return false
}

// readSerialOnce: one push and one connection: the first keys line read, or why not
func (a *AWSAPI) readSerialOnce(region, id string, cancel <-chan struct{}) (*MachineKeys, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	if err := a.pushSerialKey(region, id, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))); err != nil {
		return nil, err
	}
	return a.readSerialWith(region, id, signer, cancel)
}

// readSerialWith: one connection with a key already pushed for id: the first keys line read, or why not
func (a *AWSAPI) readSerialWith(region, id string, signer ssh.Signer, cancel <-chan struct{}) (*MachineKeys, error) {
	want := a.serialEP.hostKey(region)
	cfg := &ssh.ClientConfig{
		User: id + ".port0",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if got := ssh.FingerprintSHA256(k); got != want {
				return fmt.Errorf("%w: %s, not %s for %s", errSerialHostKey, got, want, region)
			}
			return nil
		},
		Timeout: 20 * time.Second,
	}
	client, err := ssh.Dial("tcp", a.serialEP.ssh(region), cfg)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	go func() { // a cancel (Destroy) or the watcher's deadline closes the connection
		select {
		case <-cancel:
		case <-time.After(serialWatchMax):
		}
		client.Close()
	}()
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := sess.RequestPty("vt100", 40, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		return nil, err
	}
	return scanKeys(out)
}

// scanKeys: the first keys line in the console's stream (the console ends lines with \r\n, and a line may carry the
// getty's prompt before the mark)
func scanKeys(r io.Reader) (*MachineKeys, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), serialLineMax)
	for sc.Scan() {
		k, ok, err := keysFromLine(sc.Text())
		if err != nil {
			return nil, err
		}
		if ok {
			return &k, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("the serial console closed before a keys line")
}

// keysFromLine: the keys a console line carries (machine/keeper.go announceKeys writes "JARVIS2-KEYS {json}")
func keysFromLine(line string) (MachineKeys, bool, error) {
	var k MachineKeys
	i := strings.Index(line, keysMark)
	if i < 0 {
		return k, false, nil
	}
	found := strings.TrimSpace(line[i+len(keysMark):])
	if json.Unmarshal([]byte(found), &k) != nil || k.EncryptionKey == "" || k.SigningKey == "" {
		return k, false, fmt.Errorf("the console's keys line has no keys")
	}
	return k, true, nil
}

// pushSerialKey: EC2 Instance Connect's SendSerialConsoleSSHPublicKey: the key may open one serial console session on
// the instance's port 0 within 60 s
func (a *AWSAPI) pushSerialKey(region, id, pub string) error {
	c, err := a.configured()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"InstanceId": id, "SerialPort": 0, "SSHPublicKey": pub})
	req, _ := http.NewRequest("POST", a.serialEP.push(region), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AWSEC2InstanceConnectService.SendSerialConsoleSSHPublicKey")
	sign(req, body, c, region, "ec2-instance-connect", a.now())
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 == 2 {
		var ok struct{ Success bool }
		if json.Unmarshal(b, &ok) == nil && ok.Success {
			return nil
		}
		return &AWSError{HTTP: resp.StatusCode, Code: "NoSuccess", Msg: "SendSerialConsoleSSHPublicKey: " + string(b[:min(300, len(b))])}
	}
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	json.Unmarshal(b, &e)
	code := e.Type
	if i := strings.LastIndex(code, "#"); i >= 0 {
		code = code[i+1:]
	}
	msg := e.Message + e.Msg
	if code == "" {
		msg = strings.TrimSpace(string(b))
	}
	return &AWSError{HTTP: resp.StatusCode, Code: code, Msg: fmt.Sprintf("SendSerialConsoleSSHPublicKey: HTTP %d %s %s", resp.StatusCode, code, msg[:min(300, len(msg))])}
}
