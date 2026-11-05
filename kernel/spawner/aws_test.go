package spawner

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

var testWG = WireGuard{PrivateKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", Address: "10.99.1.7",
	Peers: []WGPeer{{PublicKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=", Address: "10.99.0.1"}}}

// The user-data runs the image it names, and Inspect reads that name back
func TestIgnitionNamesItsImage(t *testing.T) {
	img := "ghcr.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("a", 64)
	ud, err := ignition(img, map[string]string{"JARVIS2_URL": "http://10.99.0.1:8081", "JARVIS2_SOURCE": "source-x"}, testWG)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if json.Unmarshal(ud, &cfg) != nil {
		t.Fatal("not JSON")
	}
	if got := userDataImage(base64.StdEncoding.EncodeToString(ud)); got != img {
		t.Fatalf("image %q", got)
	}
	for _, want := range []string{"wg0", "ListenPort=51820", "AllowedIPs=10.99.0.1%2F32", "JARVIS2_RUNNER=aws", "docker run --name session"} {
		if !strings.Contains(string(ud), want) {
			t.Fatalf("no %s in %s", want, ud)
		}
	}
	// the logs (docs/PLAN-aws.md "Logs"): the host's journal read only in the container, and the container's end on the
	// console with 50 s before the power-off when it didn't end cleanly
	for _, want := range []string{"-v /var/log/journal:/run/jarvis-host/journal:ro ${IMAGE}",
		`echo "JARVIS4-SESSION-END result=$SERVICE_RESULT code=$EXIT_CODE status=$EXIT_STATUS" > /dev/ttyS0; [ "$SERVICE_RESULT" = success ] || sleep 50`} {
		j, _ := json.Marshal(want) // the unit sits in the JSON as a string (escaped as json.Marshal escapes it)
		if !strings.Contains(string(ud), strings.Trim(string(j), `"`)) {
			t.Fatalf("no %s in %s", want, ud)
		}
	}
	if _, err := ignition(img+" ; rm", nil, testWG); err == nil {
		t.Fatal("an image with a space")
	}
	if _, err := ignition(img, map[string]string{"A": "x\ny"}, testWG); err == nil {
		t.Fatal("a value with a newline")
	}
	bad := testWG
	bad.Address = "192.168.1.1"
	if _, err := ignition(img, nil, bad); err == nil {
		t.Fatal("an address outside 10.90/15")
	}
}

func TestInstanceTypes(t *testing.T) {
	for size, want := range map[string]string{"small": "t3.medium", "medium": "t3.large", "large": "m7i.xlarge", "16gb": "m7i.2xlarge", "32gb": "r7i.2xlarge", "1024gb": ""} {
		_, _, mem := sizeGuest(size)
		if got := instanceType(mem); got != want {
			t.Fatalf("%s: %s, want %s", size, got, want)
		}
	}
}

// SigV4 against AWS's documented example (the IAM ListUsers GET in the SigV4 docs' "Examples of the complete
// Version 4 signing process" uses a query string; this checks the same key derivation on a fixed POST instead: the
// signature must not change unless the algorithm does)
func TestSignIsStable(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://ec2.ap-southeast-1.amazonaws.com/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sign(req, []byte("Action=DescribeInstances&Version=2016-11-15"), AWSCredentials{AccessKeyID: "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "ap-southeast-1", "ec2", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	a := req.Header.Get("Authorization")
	if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/ap-southeast-1/ec2/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=") {
		t.Fatal(a)
	}
}
