package spawner

// What the Rust spawner must make byte for byte as this one does (rust/kernel/src/spawner/tests_aws.rs): an EC2
// machine's Ignition user-data, a SigV4 Authorization, the sizes' instance types. GEN_RUST_VECTORS=1 go test -run
// TestRustSpawnerVectors writes rust/kernel/tests/vectors/spawner-aws.json again; without it the file is only checked
// to parse.

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const rustSpawnerVecPath = "../../rust/kernel/tests/vectors/spawner-aws.json"

type rustSpawnerVectors struct {
	Image         string            `json:"image"`
	Env           map[string]string `json:"env"`
	WireGuard     WireGuard         `json:"wireguard"`
	UserData      string            `json:"userData"`
	Body          string            `json:"body"`
	Authorization string            `json:"authorization"`
	Instances     map[string]string `json:"instances"`
}

func TestRustSpawnerVectors(t *testing.T) {
	if os.Getenv("GEN_RUST_VECTORS") == "" {
		b, err := os.ReadFile(rustSpawnerVecPath)
		if err != nil {
			t.Skip(err)
		}
		var v rustSpawnerVectors
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		return
	}
	v := rustSpawnerVectors{Image: "ghcr.io/de0ch/jarvis4-session@sha256:" + strings.Repeat("a", 64),
		Env:       map[string]string{"JARVIS2_URL": "http://10.99.0.1:8081", "JARVIS2_SOURCE": "source-x", "B": "a b=c%d&e"},
		WireGuard: testWG, Body: "Action=DescribeInstances&Version=2016-11-15", Instances: map[string]string{}}
	ud, err := ignition(v.Image, v.Env, v.WireGuard)
	if err != nil {
		t.Fatal(err)
	}
	v.UserData = string(ud)
	req, _ := http.NewRequest("POST", "https://ec2.ap-southeast-1.amazonaws.com/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sign(req, []byte(v.Body), AWSCredentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		"ap-southeast-1", "ec2", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	v.Authorization = req.Header.Get("Authorization")
	for _, size := range []string{"small", "medium", "large", "16gb", "32gb", "64gb", "1024gb"} {
		_, _, mem := sizeGuest(size)
		v.Instances[size] = instanceType(mem)
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(rustSpawnerVecPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
