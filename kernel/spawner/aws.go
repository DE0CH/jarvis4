package spawner

// The EC2 API, used only by the spawner, the only holder of its AWS key (sealed to it by the setup session: POST
// /aws-credentials). One session machine = one EC2 instance (docs/PLAN-aws.md): Flatcar Container Linux from the
// region's launch template `jarvis4-session` (infra/aws), whose Ignition user-data, written here, runs the session
// image pinned by digest as the instance's one container (privileged, the host's network, /data bound in).
// The machine's keys reach the spawner through the instance's serial console, read live over the EC2 Serial Console
// (awsserial.go) or else from GetConsoleOutput, so their link to the instance is AWS's word, not the machine's or the
// router's. The instance has one EBS volume (Flatcar's root grows to
// fill it at first boot): the image's room plus the session's diskGb, /data a directory on it, deleted with the
// instance, so there is no volume to delete afterwards. (A second volume for /data would need its device name, which
// NVMe doesn't keep: on the prototype the root disk itself was nvme1n1.)

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AWSCredentials: what POST /aws-credentials opens: the spawner's EC2 key
type AWSCredentials struct {
	AccessKeyID     string `json:"AWS_ACCESS_KEY_ID"`
	SecretAccessKey string `json:"AWS_SECRET_ACCESS_KEY"`
}

// WireGuard: how an AWS machine reaches the router (docs/PLAN-aws.md "Reaching the router"): its own key and tunnel
// address, made by the router per spawn, and the m-gateways as peers. The instance listens on UDP wgPort on its public
// IPv4; the gateways, which know that address from EC2, start the handshakes (the boxes take nothing inbound). Not a trust
// element: every /m request is signed by the machine's certified key, as on Fly's private network.
type WireGuard struct {
	PrivateKey string   `json:"privateKey"` // base64, the machine's
	Address    string   `json:"address"`    // the machine's tunnel address, e.g. 10.99.1.7
	Peers      []WGPeer `json:"peers"`      // the m-gateways
}

// WGPeer: one m-gateway: its public key and its tunnel address (the instance routes only that /32 to it)
type WGPeer struct {
	PublicKey string `json:"publicKey"`
	Address   string `json:"address"`
}

// wgPort: the UDP port an instance's WireGuard listens on (the launch template's security group lets it in)
const wgPort = 51820

var (
	wgKeyRE  = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
	wgAddrRE = regexp.MustCompile(`^10\.(9[0-9])\.[0-9]{1,3}\.[0-9]{1,3}$`)
)

// Check: keys that are WireGuard keys, addresses in 10.90.0.0–10.99.255.255, one to four gateways
func (w *WireGuard) Check() error {
	if !wgKeyRE.MatchString(w.PrivateKey) || !wgAddrRE.MatchString(w.Address) || len(w.Peers) < 1 || len(w.Peers) > 4 {
		return fmt.Errorf("wireguard: a key, an address in 10.90/15… and 1 to 4 peers")
	}
	for _, p := range w.Peers {
		if !wgKeyRE.MatchString(p.PublicKey) || !wgAddrRE.MatchString(p.Address) {
			return fmt.Errorf("wireguard: a peer's key or address")
		}
	}
	return nil
}

// AWSRegions: the regions the spawner starts instances in (the router's session regions for the aws runner); each
// has the launch template jarvis4-session (infra/aws)
var AWSRegions = map[string]bool{"eu-west-2": true, "ap-southeast-1": true, "ap-northeast-1": true}

// LaunchTemplate: every region's template for session instances (infra/aws/main.tf)
const LaunchTemplate = "jarvis4-session"

// SourceTag: the instance tag naming the source a machine is from (the router lists instances by it)
const SourceTag = "jarvis4_source"

// keysMark: the line the machine writes to the serial console with its public keys (machine/main.go)
const keysMark = "JARVIS2-KEYS "

// imageEnv: the Ignition file naming the image the session unit runs (Inspect reads it back from the user-data)
const imageEnv = "/etc/jarvis4/image.env"

// instanceType: the EC2 type for a size: at least the size's memory for the session plus room for Flatcar and
// docker, and at least as many CPUs as the Fly guest of the same size. A size past the table is refused.
func instanceType(memoryMB int) string {
	switch gb := memoryMB / 1024; {
	case gb <= 2:
		return "t3.medium" // 2 vCPU, 4 GB
	case gb <= 4:
		return "t3.large" // 2, 8
	case gb <= 8:
		return "m7i.xlarge" // 4, 16
	case gb <= 16:
		return "m7i.2xlarge" // 8, 32
	case gb <= 32:
		return "r7i.2xlarge" // 8, 64
	case gb <= 64:
		return "r7i.4xlarge" // 16, 128
	case gb <= 128:
		return "r7i.8xlarge" // 32, 256
	}
	return ""
}

// rootGB: the instance's volume besides the session's diskGb: Flatcar and the session image unpacked (about 8 GB),
// pulled (the layers stay), with room to spare
const rootGB = 30

type AWSAPI struct {
	mu     sync.Mutex
	creds  AWSCredentials
	reader bool // a read-only key (the router's): List only
	http   *http.Client
	// endpoint: the region's EC2 endpoint (a var: tests point it at a fake)
	endpoint func(region string) string
	now      func() time.Time
	serialEP serialEndpoints         // awsserial.go
	serial   map[string]*serialWatch // by instance id: the live serial console readers (awsserial.go)
}

func NewAWSAPI() *AWSAPI {
	return &AWSAPI{http: &http.Client{Timeout: 60 * time.Second},
		endpoint: func(region string) string { return "https://ec2." + region + ".amazonaws.com/" }, now: time.Now,
		serialEP: defaultSerialEndpoints()}
}

func (a *AWSAPI) Configure(c AWSCredentials) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.creds = c
}

func (a *AWSAPI) configured() (AWSCredentials, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.creds.AccessKeyID == "" || a.creds.SecretAccessKey == "" {
		return a.creds, errNoAWSCredentials
	}
	return a.creds, nil
}

// errNoAWSCredentials: the spawner restarted and the setup session (or the app's Recover) hasn't sent the key again
var errNoAWSCredentials = errors.New("the spawner has no AWS key yet (infra/setup.py aws-credentials sends it)")

// AWSError: EC2's refusal: the HTTP status and its error code (e.g. InsufficientInstanceCapacity)
type AWSError struct {
	HTTP int
	Code string
	Msg  string
}

func (e *AWSError) Error() string { return e.Msg }

// call: one EC2 Query API action in region, signed with SigV4, its XML answer into out
func (a *AWSAPI) call(region string, params url.Values, out any) error {
	c, err := a.configured()
	if err != nil {
		return err
	}
	params.Set("Version", "2016-11-15")
	body := params.Encode()
	endpoint := a.endpoint(region)
	req, _ := http.NewRequest("POST", endpoint, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sign(req, []byte(body), c, region, "ec2", a.now())
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Errors>Error"`
		}
		xml.Unmarshal(b, &e)
		code, msg := "", strings.TrimSpace(string(b))
		if len(e.Errors) > 0 {
			code, msg = e.Errors[0].Code, e.Errors[0].Message
		}
		return &AWSError{HTTP: resp.StatusCode, Code: code, Msg: fmt.Sprintf("%s: HTTP %d %s %s", params.Get("Action"), resp.StatusCode, code, msg[:min(300, len(msg))])}
	}
	if out != nil {
		return xml.Unmarshal(b, out)
	}
	return nil
}

// sign: AWS Signature Version 4 on req (its body already read into body)
func sign(req *http.Request, body []byte, c AWSCredentials, region, service string, now time.Time) {
	t := now.UTC()
	amzDate, day := t.Format("20060102T150405Z"), t.Format("20060102")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payload)
	host := req.URL.Host
	headers := map[string]string{"content-type": req.Header.Get("Content-Type"), "host": host, "x-amz-content-sha256": payload, "x-amz-date": amzDate}
	if t := req.Header.Get("X-Amz-Target"); t != "" { // a JSON API's action (EC2 Instance Connect)
		headers["x-amz-target"] = t
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canon := strings.Join([]string{req.Method, path, req.URL.RawQuery, canonHeaders.String(), signed, payload}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	ch := sha256.Sum256([]byte(canon))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	mac := func(key []byte, s string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(s))
		return h.Sum(nil)
	}
	k := mac(mac(mac(mac([]byte("AWS4"+c.SecretAccessKey), day), region), service), "aws4_request")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+signed+
		", Signature="+hex.EncodeToString(mac(k, toSign)))
}

// ---- the instance's Ignition config ----

// ignition: the user-data that makes a Flatcar instance one session machine. Units:
//   - wg0 (systemd-networkd): the machine's WireGuard to the m-gateways, listening on wgPort
//   - jarvis4-session: the session image, pinned by digest, privileged on the host's network (the container is the
//     machine, as a Fly machine's image is), /data bound in, the core's env plus the instance id; its
//     stdout goes to the journal only (the serial console carries the machine's keys line, machine/main.go). When it
//     ends the instance powers off, and the launch template terminates an instance that shuts itself down.
//
// The metadata service is closed once the instance id is read (it serves the user-data, and so the WireGuard key).
// That is tidiness, not a boundary: the container is root on the machine, as on Fly, where the machine reads its own
// config.
func ignition(image string, env map[string]string, wg WireGuard) ([]byte, error) {
	if strings.ContainsAny(image, "\n\"' ") {
		return nil, fmt.Errorf("the image has a character the unit can't carry")
	}
	if err := wg.Check(); err != nil {
		return nil, err
	}
	var netdev strings.Builder
	fmt.Fprintf(&netdev, "[NetDev]\nName=wg0\nKind=wireguard\n[WireGuard]\nPrivateKey=%s\nListenPort=%d\n", wg.PrivateKey, wgPort)
	for _, p := range wg.Peers {
		fmt.Fprintf(&netdev, "[WireGuardPeer]\nPublicKey=%s\nAllowedIPs=%s/32\nPersistentKeepalive=25\n", p.PublicKey, p.Address)
	}
	network := "[Match]\nName=wg0\n[Network]\nAddress=" + wg.Address + "/32\n"
	for _, p := range wg.Peers {
		network += "[Route]\nDestination=" + p.Address + "/32\n"
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var envFile strings.Builder
	envFile.WriteString("JARVIS2_RUNNER=aws\n")
	for _, k := range keys {
		v := env[k]
		if strings.ContainsAny(v, "\n") || strings.ContainsAny(k, "=\n") {
			return nil, fmt.Errorf("env %s doesn't fit one line", k)
		}
		envFile.WriteString(k + "=" + v + "\n")
	}
	file := func(path string, mode int, contents string) map[string]any {
		return map[string]any{"path": path, "mode": mode, "overwrite": true,
			"contents": map[string]any{"source": "data:," + url.PathEscape(contents)}}
	}
	session := `[Unit]
Description=The session machine
After=docker.service network-online.target systemd-networkd.service
Requires=docker.service
Wants=network-online.target
[Service]
Type=simple
Restart=no
TimeoutStartSec=0
EnvironmentFile=` + imageEnv + `
ExecStartPre=/bin/sh -c 'T=$(curl -sf -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token) && echo JARVIS2_MACHINE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/instance-id) > /etc/jarvis4/id.env'
ExecStartPre=/usr/sbin/iptables -I OUTPUT -d 169.254.169.254 -j DROP
ExecStartPre=/usr/bin/docker pull ${IMAGE}
ExecStart=/usr/bin/docker run --name session --network host --privileged --cgroupns host --env-file /etc/jarvis4/session.env --env-file /etc/jarvis4/id.env -v /data:/data -v /var/log/journal:/run/jarvis-host/journal:ro ${IMAGE}
ExecStopPost=/bin/sh -c 'echo "JARVIS4-SESSION-END result=$SERVICE_RESULT code=$EXIT_CODE status=$EXIT_STATUS" > /dev/ttyS0; [ "$SERVICE_RESULT" = success ] || sleep 50'
ExecStopPost=/usr/bin/systemctl poweroff
[Install]
WantedBy=multi-user.target
`
	cfg := map[string]any{
		"ignition": map[string]any{"version": "3.4.0"},
		"storage": map[string]any{
			"directories": []map[string]any{{"path": "/data", "mode": 0o755}},
			"files": []map[string]any{
				file(imageEnv, 0o644, "IMAGE="+image+"\n"),
				file("/etc/jarvis4/session.env", 0o600, envFile.String()),
				file("/etc/flatcar/update.conf", 0o644, "REBOOT_STRATEGY=off\n"),
				file("/etc/systemd/network/50-wg0.netdev", 0o644, netdev.String()), // networkd (not root) reads it
				file("/etc/systemd/network/50-wg0.network", 0o644, network),
			},
		},
		"systemd": map[string]any{"units": []map[string]any{
			{"name": "update-engine.service", "mask": true},
			{"name": "locksmithd.service", "mask": true},
			{"name": "jarvis4-session.service", "enabled": true, "contents": session},
		}},
	}
	return json.Marshal(cfg)
}

var imageLineRE = regexp.MustCompile(`(?m)^IMAGE=(\S+)$`)

// userDataImage: the image the instance's user-data runs (its image.env), "" if it names none
func userDataImage(userData string) string {
	b, err := base64.StdEncoding.DecodeString(userData)
	if err != nil {
		return ""
	}
	var cfg struct {
		Storage struct {
			Files []struct {
				Path     string `json:"path"`
				Contents struct {
					Source string `json:"source"`
				} `json:"contents"`
			} `json:"files"`
		} `json:"storage"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return ""
	}
	for _, f := range cfg.Storage.Files {
		if f.Path != imageEnv {
			continue
		}
		s, ok := strings.CutPrefix(f.Contents.Source, "data:,")
		if !ok {
			return ""
		}
		if s, err = url.PathUnescape(s); err != nil {
			return ""
		}
		if m := imageLineRE.FindStringSubmatch(s); m != nil {
			return m[1]
		}
	}
	return ""
}

// ---- the Runner calls ----

// Create: one RunInstances from the region's launch template: the size's instance type, its one volume (rootGB +
// diskGb), the source tag, the Ignition user-data → the instance id (volume "": nothing of its own to delete).
func (a *AWSAPI) Create(in CreateInput) (string, string, error) {
	if _, err := a.configured(); err != nil {
		return "", "", err
	}
	if !AWSRegions[in.Region] {
		return "", "", &AWSError{HTTP: 400, Code: "UnknownRegion", Msg: "no session launch template in region " + in.Region}
	}
	typ := instanceType(in.MemoryMB)
	if typ == "" {
		return "", "", &AWSError{HTTP: 400, Code: "UnknownSize", Msg: fmt.Sprintf("no instance type for %d MB", in.MemoryMB)}
	}
	hostname := "jarvis4-" + strings.TrimPrefix(in.Source, "source-")[:min(12, len(strings.TrimPrefix(in.Source, "source-")))]
	if in.WireGuard == nil {
		return "", "", &AWSError{HTTP: 400, Code: "NoWireGuard", Msg: "an AWS machine needs its wireguard"}
	}
	ud, err := ignition(in.Image, in.Env, *in.WireGuard)
	if err != nil {
		return "", "", err
	}
	if len(ud) > 16000 { // EC2's user-data limit is 16 KB before base64
		return "", "", fmt.Errorf("the user-data is %d bytes, over EC2's 16 KB", len(ud))
	}
	p := url.Values{}
	p.Set("Action", "RunInstances")
	p.Set("MinCount", "1")
	p.Set("MaxCount", "1")
	p.Set("LaunchTemplate.LaunchTemplateName", LaunchTemplate)
	p.Set("LaunchTemplate.Version", "$Default")
	p.Set("InstanceType", typ)
	p.Set("UserData", base64.StdEncoding.EncodeToString(ud))
	p.Set("BlockDeviceMapping.1.DeviceName", "/dev/xvda")
	p.Set("BlockDeviceMapping.1.Ebs.VolumeSize", strconv.Itoa(rootGB+in.DiskGB))
	p.Set("BlockDeviceMapping.1.Ebs.VolumeType", "gp3")
	p.Set("BlockDeviceMapping.1.Ebs.Encrypted", "true")
	p.Set("BlockDeviceMapping.1.Ebs.DeleteOnTermination", "true")
	p.Set("TagSpecification.1.ResourceType", "instance")
	p.Set("TagSpecification.1.Tag.1.Key", SourceTag)
	p.Set("TagSpecification.1.Tag.1.Value", in.Source)
	p.Set("TagSpecification.1.Tag.2.Key", "Name")
	p.Set("TagSpecification.1.Tag.2.Value", hostname)
	p.Set("TagSpecification.2.ResourceType", "volume")
	p.Set("TagSpecification.2.Tag.1.Key", SourceTag)
	p.Set("TagSpecification.2.Tag.1.Value", in.Source)
	var out struct {
		Instances []struct {
			ID string `xml:"instanceId"`
		} `xml:"instancesSet>item"`
	}
	if err := a.call(in.Region, p, &out); err != nil {
		return "", "", err
	}
	if len(out.Instances) != 1 || out.Instances[0].ID == "" {
		return "", "", fmt.Errorf("RunInstances made no instance")
	}
	a.watchSerial(in.Region, out.Instances[0].ID) // its keys line, live, as soon as it is written (awsserial.go)
	return out.Instances[0].ID, "", nil
}

// find: the region an instance is in and the instance, looked up in every session region (an id is unique across
// them); nil when no region knows it
func (a *AWSAPI) find(id string) (string, *ec2Instance, error) {
	for region := range AWSRegions {
		inst, err := a.describe(region, id)
		if err != nil {
			return "", nil, err
		}
		if inst != nil {
			return region, inst, nil
		}
	}
	return "", nil, nil
}

type ec2Instance struct {
	ID    string `xml:"instanceId"`
	State struct {
		Name string `xml:"name"`
	} `xml:"instanceState"`
	Tags []struct {
		Key   string `xml:"key"`
		Value string `xml:"value"`
	} `xml:"tagSet>item"`
}

// describe: the instance in region (nil when EC2 doesn't know it there)
func (a *AWSAPI) describe(region, id string) (*ec2Instance, error) {
	p := url.Values{}
	p.Set("Action", "DescribeInstances")
	p.Set("InstanceId.1", id)
	var out struct {
		Reservations []struct {
			Instances []ec2Instance `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
	}
	if err := a.call(region, p, &out); err != nil {
		var ae *AWSError
		if errors.As(err, &ae) && (ae.Code == "InvalidInstanceID.NotFound" || ae.Code == "InvalidInstanceID.Malformed") {
			return nil, nil
		}
		return nil, err
	}
	for _, r := range out.Reservations {
		for i := range r.Instances {
			if r.Instances[i].ID == id {
				return &r.Instances[i], nil
			}
		}
	}
	return nil, nil
}

// Inspect: the instance's state as the spawner's words (stateWord), the image its user-data runs, and its source tag. An instance EC2
// no longer knows was terminated long ago: destroyed.
func (a *AWSAPI) Inspect(id string) (FlyMachine, error) {
	region, inst, err := a.find(id)
	if err != nil {
		return FlyMachine{}, err
	}
	if inst == nil {
		return FlyMachine{State: "destroyed"}, nil
	}
	m := FlyMachine{State: stateWord(inst.State.Name)}
	for _, t := range inst.Tags {
		if t.Key == SourceTag {
			m.Source = t.Value
		}
	}
	if m.State == "started" {
		p := url.Values{}
		p.Set("Action", "DescribeInstanceAttribute")
		p.Set("InstanceId", id)
		p.Set("Attribute", "userData")
		var ud struct {
			Value string `xml:"userData>value"`
		}
		if err := a.call(region, p, &ud); err != nil {
			return FlyMachine{}, err
		}
		m.Image = userDataImage(ud.Value)
	}
	return m, nil
}

// Init: the machine's keys line from the instance's serial console: as the live reader read it (awsserial.go), else the
// newest output EC2 keeps (GetConsoleOutput Latest, refreshed every 30-40 s). The machine writes it until its cert
// arrives; until then this is a not-started (the router asks again).
func (a *AWSAPI) Init(id string) (MachineKeys, error) {
	var k MachineKeys
	if sk, _ := a.serialKeys(id); sk != nil {
		return *sk, nil
	}
	region, inst, err := a.find(id)
	if err != nil {
		return k, err
	}
	if inst == nil {
		return k, fmt.Errorf("instance %s is gone", id)
	}
	a.watchSerial(region, id) // none yet: this spawner didn't create it (a restart, a copy flip)
	p := url.Values{}
	p.Set("Action", "GetConsoleOutput")
	p.Set("InstanceId", id)
	p.Set("Latest", "true")
	var out struct {
		Output string `xml:"output"`
	}
	if err := a.call(region, p, &out); err != nil {
		return k, err
	}
	b, _ := base64.StdEncoding.DecodeString(out.Output)
	found := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, keysMark) {
			found = line
		}
	}
	if found == "" {
		return k, errNotYet
	}
	k, _, err = keysFromLine(found)
	return k, err
}

// errNotYet: the machine hasn't written its keys line yet (its image is still being pulled)
var errNotYet = errors.New("no keys on the console yet")

// Destroy: TerminateInstances (its volume goes with it)
func (a *AWSAPI) Destroy(id string) error {
	a.stopSerial(id)
	region, inst, err := a.find(id)
	if err != nil || inst == nil {
		return err
	}
	p := url.Values{}
	p.Set("Action", "TerminateInstances")
	p.Set("InstanceId.1", id)
	return a.call(region, p, nil)
}

// DeleteVolume: nothing; the instance's volume is deleted with it
func (a *AWSAPI) DeleteVolume(string) error { return nil }

// ---- the router's read-only view (its own key: DescribeInstances only) ----

// Instance: a session instance as EC2 lists it, in the spawner's state words (Inspect)
type Instance struct {
	ID, Region, State, Source, Type string
	PublicIP                        string // its public IPv4 address (the m-gateways' endpoint)
	Launched                        time.Time
}

// stateWord: EC2's instance state as the spawner's word (Inspect)
func stateWord(ec2State string) string {
	switch ec2State {
	case "pending":
		return "created"
	case "running":
		return "started"
	case "terminated":
		return "destroyed"
	case "shutting-down":
		return "destroying"
	}
	return ec2State // stopping, stopped
}

// List: every instance tagged with a source, in every session region (terminated ones while EC2 still lists them)
func (a *AWSAPI) List() ([]Instance, error) {
	var all []Instance
	for region := range AWSRegions {
		p := url.Values{}
		p.Set("Action", "DescribeInstances")
		p.Set("Filter.1.Name", "tag-key")
		p.Set("Filter.1.Value.1", SourceTag)
		p.Set("MaxResults", "1000")
		var out struct {
			Reservations []struct {
				Instances []struct {
					ec2Instance
					Type     string    `xml:"instanceType"`
					PublicIP string    `xml:"ipAddress"`
					Launched time.Time `xml:"launchTime"`
				} `xml:"instancesSet>item"`
			} `xml:"reservationSet>item"`
		}
		if err := a.call(region, p, &out); err != nil {
			return nil, fmt.Errorf("%s: %w", region, err)
		}
		for _, r := range out.Reservations {
			for _, i := range r.Instances {
				in := Instance{ID: i.ID, Region: region, State: stateWord(i.State.Name), Type: i.Type, PublicIP: i.PublicIP, Launched: i.Launched}
				for _, t := range i.Tags {
					if t.Key == SourceTag {
						in.Source = t.Value
					}
				}
				all = append(all, in)
			}
		}
	}
	return all, nil
}

// ConfigureReader: a key that only reads (the router's): List works, the rest refuse for want of a tailnet key
func (a *AWSAPI) ConfigureReader(accessKeyID, secret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.creds = AWSCredentials{AccessKeyID: accessKeyID, SecretAccessKey: secret}
	a.reader = true
}
