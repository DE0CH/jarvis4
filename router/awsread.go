package main

// The router's own EC2 reads with its read-only key (AWS_READ_*: IAM user jarvis4-router-read, infra/aws/iam.tf;
// signed by awsbudget.go's awsSignV4):
// one instance as EC2 describes it now, with its state's reasons (the lifecycle log's AWS events, lifecycle.go), and
// the newest serial console output of a session instance (the AWS machines' log shipping, awslogs.go). The listing
// for lost machines and the gateways stays the spawner package's (awsrunner.go listAWSMachines); these need fields
// it doesn't read, and kernel/ stays as the kernel release left it.

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DE0CH/jarvis4/kernel/spawner"
)

// awsReadEndpoint: a region's EC2 endpoint (tests point it at a fake)
var awsReadEndpoint = func(region string) string { return "https://ec2." + region + ".amazonaws.com/" }

var awsReadHTTP = &http.Client{Timeout: 30 * time.Second}

// awsReadOn: the router has its read-only AWS key
func awsReadOn() bool {
	return os.Getenv("AWS_READ_ACCESS_KEY_ID") != "" && os.Getenv("AWS_READ_SECRET_ACCESS_KEY") != ""
}

// ec2ReadError: EC2's refusal (its error code, e.g. UnauthorizedOperation, InvalidInstanceID.NotFound)
type ec2ReadError struct {
	Status int
	Code   string
	Msg    string
}

func (e *ec2ReadError) Error() string {
	return fmt.Sprintf("EC2: HTTP %d %s %s", e.Status, e.Code, e.Msg)
}

// ec2Read: one EC2 Query API action in region with the read-only key, SigV4-signed, its XML answer into out
func ec2Read(region string, params url.Values, out any) error {
	id, secret := os.Getenv("AWS_READ_ACCESS_KEY_ID"), os.Getenv("AWS_READ_SECRET_ACCESS_KEY")
	if id == "" || secret == "" {
		return fmt.Errorf("the router has no AWS read key (AWS_READ_ACCESS_KEY_ID)")
	}
	params.Set("Version", "2016-11-15")
	body := params.Encode()
	req, err := http.NewRequest("POST", awsReadEndpoint(region), strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	awsSignV4(req, []byte(body), id, secret, region, "ec2", time.Now()) // awsbudget.go
	resp, err := awsReadHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Errors>Error"`
		}
		xml.Unmarshal(b, &e)
		re := &ec2ReadError{Status: resp.StatusCode}
		if len(e.Errors) > 0 {
			re.Code, re.Msg = e.Errors[0].Code, e.Errors[0].Message
		}
		return re
	}
	return xml.Unmarshal(b, out)
}

// awsInstanceView: one instance as DescribeInstances gives it, with the reasons for its state
type awsInstanceView struct {
	ID, Region, State string // EC2's own state words: pending, running, stopping, stopped, shutting-down, terminated
	Type, Zone        string
	PublicIP          string
	Launched          time.Time
	Transition        string // stateTransitionReason, e.g. "User initiated (2026-11-04 13:18:40 GMT)"
	ReasonCode        string // stateReason: e.g. Client.InstanceInitiatedShutdown, Server.InsufficientInstanceCapacity
	ReasonMsg         string
}

type ec2DescribeOut struct {
	Reservations []struct {
		Instances []struct {
			ID    string `xml:"instanceId"`
			State struct {
				Name string `xml:"name"`
			} `xml:"instanceState"`
			Type      string    `xml:"instanceType"`
			PublicIP  string    `xml:"ipAddress"`
			Launched  time.Time `xml:"launchTime"`
			Placement struct {
				Zone string `xml:"availabilityZone"`
			} `xml:"placement"`
			Transition  string `xml:"reason"`
			StateReason struct {
				Code    string `xml:"code"`
				Message string `xml:"message"`
			} `xml:"stateReason"`
		} `xml:"instancesSet>item"`
	} `xml:"reservationSet>item"`
}

// awsRegionOfInstance: the region the newest listing saw the instance in ("" when it didn't)
func awsRegionOfInstance(id string) string {
	awsSeenMu.Lock()
	defer awsSeenMu.Unlock()
	return awsSeen[id].Region
}

// awsDescribe: the instance as EC2 describes it now (nil when no session region knows it: terminated long ago)
func awsDescribe(id string) (*awsInstanceView, error) {
	regions := []string{}
	if r := awsRegionOfInstance(id); r != "" {
		regions = append(regions, r)
	}
	for r := range spawner.AWSRegions {
		if len(regions) == 0 || r != regions[0] {
			regions = append(regions, r)
		}
	}
	for _, region := range regions {
		p := url.Values{}
		p.Set("Action", "DescribeInstances")
		p.Set("InstanceId.1", id)
		var out ec2DescribeOut
		if err := ec2Read(region, p, &out); err != nil {
			if e, ok := err.(*ec2ReadError); ok && (e.Code == "InvalidInstanceID.NotFound" || e.Code == "InvalidInstanceID.Malformed") {
				continue
			}
			return nil, err
		}
		for _, rs := range out.Reservations {
			for _, i := range rs.Instances {
				if i.ID == id {
					return &awsInstanceView{ID: id, Region: region, State: i.State.Name, Type: i.Type, Zone: i.Placement.Zone,
						PublicIP: i.PublicIP, Launched: i.Launched, Transition: i.Transition, ReasonCode: i.StateReason.Code,
						ReasonMsg: i.StateReason.Message}, nil
				}
			}
		}
	}
	return nil, nil
}

// awsConsole: the instance's newest serial console output (GetConsoleOutput Latest: up to its last 64 KB; EC2 keeps
// none once the instance is terminated)
func awsConsole(region, id string) (string, error) {
	p := url.Values{}
	p.Set("Action", "GetConsoleOutput")
	p.Set("InstanceId", id)
	p.Set("Latest", "true")
	var out struct {
		Output string `xml:"output"`
	}
	if err := ec2Read(region, p, &out); err != nil {
		return "", err
	}
	b, err := base64.StdEncoding.DecodeString(out.Output)
	if err != nil {
		return "", fmt.Errorf("GetConsoleOutput: %w", err)
	}
	return string(b), nil
}
