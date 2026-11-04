package main

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAWSBurnRate(t *testing.T) {
	inv := awsInventory{
		Instances: []awsInstance{
			{ID: "i-1", Region: "eu-west-2", Type: "t3.medium", State: "running", PublicIP: "1.2.3.4"},
			{ID: "i-2", Region: "ap-northeast-1", Type: "r7i.2xlarge", State: "running", PublicIP: "5.6.7.8"},
			{ID: "i-3", Region: "eu-west-2", Type: "t3.large", State: "stopped"},
			{ID: "i-4", Region: "eu-west-2", Type: "t3.medium", State: "terminated"},
			{ID: "i-5", Region: "eu-west-2", Type: "x9.huge", State: "running"}, // unknown: the dearest
		},
		Volumes: []awsVolume{{Region: "eu-west-2", State: "in-use", SizeGB: 40}, {Region: "ap-southeast-1", State: "available", SizeGB: 10},
			{Region: "eu-west-2", State: "deleting", SizeGB: 999}},
		Snapshots: []awsSnapshot{{Region: "eu-west-2", State: "completed", VolumeGB: 20, Bytes: 10 << 30},
			{Region: "ap-southeast-1", State: "completed", VolumeGB: 20}}, // no full size: the volume's size
		Addresses: []awsAddress{{Region: "eu-west-2", PublicIP: "1.2.3.4"}, {Region: "eu-west-2", PublicIP: "9.9.9.9"}}, // one attached, one idle
	}
	b := awsBurnRate(inv)
	want := 0.0472 + 0.6384 + 2.5536 + // instances
		(40*0.0928+10*0.096)/730 + // gp3
		(10*0.053+20*0.05)/730 + // snapshots
		3*0.005 // 1.2.3.4, 5.6.7.8, 9.9.9.9
	if math.Abs(b.RatePerHour-want) > 1e-9 || b.Running != 3 || b.Volumes != 2 || b.VolumeGB != 50 || b.Snapshots != 2 || b.IPv4 != 3 {
		t.Fatalf("%+v, want %.6f", b, want)
	}
	if strings.Join(b.UnknownTypes, ",") != "eu-west-2/x9.huge" {
		t.Fatal(b.UnknownTypes)
	}
	// every type the spawner launches has a price in every session region
	for _, region := range awsBudgetRegions {
		for _, typ := range []string{"t3.medium", "t3.large", "m7i.xlarge", "m7i.2xlarge", "r7i.2xlarge", "r7i.4xlarge", "r7i.8xlarge"} {
			if _, ok := awsInstanceRate(region, typ); !ok {
				t.Fatalf("no price for %s in %s", typ, region)
			}
		}
		if g, s := awsStorageRate(region); g == 0 || s == 0 {
			t.Fatalf("no storage price in %s", region)
		}
	}
}

// Fly and AWS fill one pool; Cost Explorer's figure is a floor under the AWS part
func TestOnePool(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	s, _, _ := applySample(&BudgetState{Month: "2026-11", SpentUSD: 20, LastSampleAt: &t0}, t0.Add(time.Hour), spendSample{FlyRate: 1, AWSRate: 2}, 50, 45)
	if !near(s.SpentUSD, 23) || !near(s.AWSUSD, 2) || !near(s.flyPart(), 21) || !near(s.pool(), 23) {
		t.Fatalf("%+v", s)
	}
	// the bill is above the estimate (traffic, credits, the days before tracking): the pool counts the bill
	s, a, _ := applySample(&s, t0.Add(2*time.Hour), spendSample{FlyRate: 1, AWSRate: 2, Billed: &awsBilled{Month: "2026-11", USD: 26, At: t0}}, 50, 45)
	if !near(s.awsPart(), 26) || !near(s.pool(), 22+26) || !a.WarnDM {
		t.Fatalf("%+v %+v", s, a)
	}
	// it stays until the next reading; the estimate overtaking it takes over
	s, a, _ = applySample(&s, t0.Add(3*time.Hour), spendSample{FlyRate: 0, AWSRate: 30}, 50, 45)
	if !near(s.AWSUSD, 34) || !near(s.awsPart(), 34) || !near(s.pool(), 22+34) || !a.Enforce || !a.CapDM {
		t.Fatalf("%+v %+v", s, a)
	}
	// last month's bill doesn't count in a new month
	s, _, _ = applySample(&s, time.Date(2026, 12, 1, 0, 1, 0, 0, time.UTC), spendSample{Billed: &awsBilled{Month: "2026-11", USD: 99}}, 50, 45)
	if s.pool() != 0 || s.AWSBilledUSD != 0 {
		t.Fatalf("%+v", s)
	}
}

type fakeAWS struct {
	inv    awsInventory
	billed float64
	calls  int
}

func (f *fakeAWS) Inventory(time.Time) (awsInventory, error) { return f.inv, nil }
func (f *fakeAWS) Billed(string) (float64, string, error) {
	f.calls++
	return f.billed, "795109470764", nil
}

func TestBudgetTickPausesAWSSessions(t *testing.T) {
	st, _ := testState(t, t.TempDir())
	r := NewRouter(Config{}, st, nil, Policy{})
	st.Do(func(d *persisted) {
		d.Sessions["s1"] = &Session{ID: "s1", MachineID: "m1", Label: "on fly", State: "started"}
		d.Sessions["s2"] = &Session{ID: "s2", MachineID: "i-aaa", Label: "on aws", State: "started"}
		d.Machines["m1"], d.Machines["i-aaa"] = "s1", "s2"
	})
	var paused, dms []string
	budgetPause = func(r *Router, sid string) error { paused = append(paused, sid); return nil }
	budgetDM = func(r *Router, text string) { dms = append(dms, text) }
	defer func() {
		budgetPause = func(r *Router, sid string) error { return r.Pause(sid) }
		budgetDM = func(r *Router, text string) { r.DM(text) }
	}()
	fly := &fakeFly{ms: []flyMachine{machine("m1", "started")}}
	aws := &fakeAWS{inv: awsInventory{Instances: []awsInstance{
		{ID: "i-aaa", Region: "eu-west-2", Type: "t3.medium", State: "running", PublicIP: "1.1.1.1"},
		{ID: "i-bake", Region: "eu-west-2", Type: "t3.medium", State: "running", Name: "jarvis4-bake"},
	}}, billed: 1.5}
	t0 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	if _, _, err := r.budgetTick(fly, aws, t0, 50, 45); err != nil {
		t.Fatal(err)
	}
	v := budgetView.budget
	ap := v["aws"].(map[string]any)
	if aws.calls != 1 || ap["billedUsd"] != 1.5 || v["spentUsd"] != 1.5 || ap["running"] != 2 || v["running"] != 3 || ap["account"] != "795109470764" {
		t.Fatalf("%v", v)
	}
	if o := ap["other"].([]map[string]string); len(o) != 1 || o[0]["id"] != "i-bake" {
		t.Fatalf("other %v", o)
	}
	// Cost Explorer is read again only after awsBilledEvery
	r.budgetTick(fly, aws, t0.Add(time.Hour), 50, 45)
	if aws.calls != 1 {
		t.Fatal("Cost Explorer asked every tick")
	}
	r.budgetTick(fly, aws, t0.Add(awsBilledEvery+time.Minute), 50, 45)
	if aws.calls != 2 {
		t.Fatal("Cost Explorer not asked again")
	}
	// over the cap: both runners' sessions pause, the stranger is named, the DM gives the split
	st.Do(func(d *persisted) { d.Budget.SpentUSD = 49.9 })
	a, _, _ := r.budgetTick(fly, aws, t0.Add(awsBilledEvery+2*time.Minute), 50, 45)
	if !a.Enforce || strings.Join(paused, ",") != "s1,s2" {
		t.Fatalf("%+v %v", a, paused)
	}
	if len(dms) != 1 || !strings.Contains(dms[0], "i-bake") || !strings.Contains(dms[0], "(Fly USD") || !strings.Contains(dms[0], "AWS USD") {
		t.Fatalf("%q", dms)
	}
}

// the real reader against a fake AWS: every call signed, EC2's XML and Cost Explorer's JSON read, the account filter set
func TestAWSCostAPI(t *testing.T) {
	var ceBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") {
			t.Errorf("unsigned %s", req.URL)
		}
		b, _ := io.ReadAll(req.Body)
		if req.Header.Get("X-Amz-Target") == "AWSInsightsIndexService.GetCostAndUsage" {
			json.Unmarshal(b, &ceBody)
			w.Write([]byte(`{"ResultsByTime":[{"Total":{"UnblendedCost":{"Amount":"1.4201","Unit":"USD"}}}]}`))
			return
		}
		q, _ := url.ParseQuery(string(b))
		switch q.Get("Action") {
		case "GetCallerIdentity":
			w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>795109470764</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
		case "DescribeInstances":
			w.Write([]byte(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-1</instanceId><instanceType>t3.medium</instanceType><instanceState><name>running</name></instanceState><ipAddress>1.2.3.4</ipAddress><tagSet><item><key>jarvis4_source</key><value>source-x</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`))
		case "DescribeVolumes":
			if q.Get("NextToken") == "" {
				w.Write([]byte(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-1</volumeId><size>30</size><status>in-use</status></item></volumeSet><nextToken>p2</nextToken></DescribeVolumesResponse>`))
			} else {
				w.Write([]byte(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-2</volumeId><size>10</size><status>available</status></item></volumeSet></DescribeVolumesResponse>`))
			}
		case "DescribeSnapshots":
			w.Write([]byte(`<DescribeSnapshotsResponse><snapshotSet><item><snapshotId>snap-1</snapshotId><volumeSize>20</volumeSize><status>completed</status><fullSnapshotSizeInBytes>19121831936</fullSnapshotSizeInBytes></item></snapshotSet></DescribeSnapshotsResponse>`))
		case "DescribeAddresses":
			w.Write([]byte(`<DescribeAddressesResponse><addressesSet/></DescribeAddressesResponse>`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	a := newAWSCostAPI("AKID", "secret")
	a.ec2 = func(string) string { return srv.URL + "/" }
	a.sts, a.ce = srv.URL+"/", srv.URL+"/"
	inv, err := a.Inventory(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	n := len(awsBudgetRegions)
	if len(inv.Instances) != n || inv.Instances[0].Source != "source-x" || inv.Instances[0].PublicIP != "1.2.3.4" ||
		len(inv.Volumes) != 2*n || len(inv.Snapshots) != n || inv.Snapshots[0].Bytes != 19121831936 {
		t.Fatalf("%+v", inv)
	}
	usd, acct, err := a.Billed("2026-11")
	if err != nil || usd != 1.4201 || acct != "795109470764" {
		t.Fatal(usd, acct, err)
	}
	b, _ := json.Marshal(ceBody)
	if !strings.Contains(string(b), `"LINKED_ACCOUNT","Values":["795109470764"]`) || !strings.Contains(string(b), `"Start":"2026-11-01"`) ||
		!strings.Contains(string(b), `"End":"2026-12-01"`) {
		t.Fatalf("%s", b)
	}
}

// AWS_BUDGET_LIVE_TEST=1 with AWS_READ_ACCESS_KEY_ID / AWS_READ_SECRET_ACCESS_KEY: the real account, read only
func TestAWSCostAPILive(t *testing.T) {
	if os.Getenv("AWS_BUDGET_LIVE_TEST") == "" {
		t.Skip("AWS_BUDGET_LIVE_TEST unset: not against AWS")
	}
	a := awsCosterFromEnv()
	inv, err := a.Inventory(time.Now())
	b := awsBurnRate(inv)
	t.Logf("inventory err=%v: %d instances, %d volumes, %d snapshots, %d addresses; %+v; USD %.2f a month",
		err, len(inv.Instances), len(inv.Volumes), len(inv.Snapshots), len(inv.Addresses), b, b.RatePerHour*hoursPerMonth)
	usd, acct, err := a.Billed(time.Now().UTC().Format("2006-01"))
	t.Logf("billed USD %.4f in %s (err %v)", usd, acct, err)
}
