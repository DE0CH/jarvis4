package main

// AWS spend in the budget (docs/PLAN-aws.md "Budget"; Deyao, 2026-11-04: "aws spend tracking just like fly's spend
// tracking. they contribute to the same pool of 50 usd, make sure the billing is recorded separately from yyc").
//
// AWS has spend alerts but no hard stop, so the router estimates it the way it estimates Fly (budget.go): every tick it
// lists everything that accrues in jarvis4's AWS account in the session regions (running instances by type and region,
// EBS volumes, snapshots, public IPv4 addresses) with the router's read-only key, prices it at AWS's published
// on-demand rates and adds rate × elapsed to the month's total. Fly and AWS fill ONE pool, FLY_BUDGET_USD.
//
// Cross-check: every awsBilledEvery the router asks Cost Explorer for the month's billed usage of its own account (the
// key's account, from STS; LINKED_ACCOUNT filter, so no other account of the organisation, YYC's 551897326524
// among them, is counted; RECORD_TYPE Usage: no tax, no credits). Cost Explorer lags about a day and catches what the
// estimate doesn't see (data transfer, t3 surplus credits, anything outside the session regions), so the pool counts
// AWS as the larger of the two. The cap still works on the live estimate. Each Cost Explorer request costs USD 0.01
// (aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing, read 2026-11-04): 4 a day, about USD 1.20 a month.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// awsBudgetRegions: the session regions (kernel/spawner/aws.go AWSRegions; infra/aws builds nothing elsewhere)
var awsBudgetRegions = []string{"eu-west-2", "ap-southeast-1", "ap-northeast-1"}

// awsInstanceRates: USD an hour, on-demand Linux, shared tenancy, for every instance type kernel/spawner/aws.go
// instanceType uses, per region. From AWS's Price List API (pricing:GetProducts, service AmazonEC2, read 2026-11-04;
// the same figures as aws.amazon.com/ec2/pricing/on-demand). A type not listed is priced at the dearest listed (the
// cap errs high) and logged.
var awsInstanceRates = map[string]map[string]float64{
	"eu-west-2": {"t3.medium": 0.0472, "t3.large": 0.0944, "m7i.xlarge": 0.2331, "m7i.2xlarge": 0.4662,
		"r7i.2xlarge": 0.6216, "r7i.4xlarge": 1.2432, "r7i.8xlarge": 2.4864},
	"ap-southeast-1": {"t3.medium": 0.0528, "t3.large": 0.1056, "m7i.xlarge": 0.2520, "m7i.2xlarge": 0.5040,
		"r7i.2xlarge": 0.6384, "r7i.4xlarge": 1.2768, "r7i.8xlarge": 2.5536},
	"ap-northeast-1": {"t3.medium": 0.0544, "t3.large": 0.1088, "m7i.xlarge": 0.2604, "m7i.2xlarge": 0.5208,
		"r7i.2xlarge": 0.6384, "r7i.4xlarge": 1.2768, "r7i.8xlarge": 2.5536},
}

// awsStorageRates: USD per GB-month, from the Price List API (read 2026-11-04; aws.amazon.com/ebs/pricing): gp3
// provisioned storage (EBS:VolumeUsage.gp3; its 3000 IOPS and 125 MB/s are included, the launch template asks for no
// more) and snapshot data stored (EBS:SnapshotUsage). Every volume is priced as gp3 (the spawner and bake.sh make no
// other kind).
var awsStorageRates = map[string]struct{ GP3, Snapshot float64 }{
	"eu-west-2":      {0.0928, 0.053},
	"ap-southeast-1": {0.096, 0.05},
	"ap-northeast-1": {0.096, 0.05},
}

// awsIPv4PerHour: a public IPv4 address, in use or idle, every region (Price List API AmazonVPC
// PublicIPv4:InUseAddress / IdleAddress, read 2026-11-04; aws.amazon.com/vpc/pricing)
const awsIPv4PerHour = 0.005

const (
	awsBilledEvery   = 6 * time.Hour    // Cost Explorer: USD 0.01 a request
	awsSnapshotEvery = 30 * time.Minute // snapshots and Elastic IPs change rarely
)

func awsInstanceRate(region, typ string) (float64, bool) {
	if p, ok := awsInstanceRates[region][typ]; ok {
		return p, true
	}
	top := 0.0
	for _, m := range awsInstanceRates {
		for _, p := range m {
			top = max(top, p)
		}
	}
	return top, false
}

func awsStorageRate(region string) (gp3, snap float64) {
	if r, ok := awsStorageRates[region]; ok {
		return r.GP3, r.Snapshot
	}
	for _, r := range awsStorageRates {
		gp3, snap = max(gp3, r.GP3), max(snap, r.Snapshot)
	}
	return
}

// ---- what AWS lists ---------------------------------------------------------------------------------

type awsInstance struct {
	ID, Region, Type, State, PublicIP, Name, Source string
}

type awsVolume struct {
	ID, Region, State string
	SizeGB            int
}

type awsSnapshot struct {
	ID, Region, State string
	VolumeGB          int
	Bytes             int64 // fullSnapshotSizeInBytes (0 when EC2 doesn't say: VolumeGB is counted)
}

type awsAddress struct{ Region, PublicIP string }

type awsInventory struct {
	Instances []awsInstance
	Volumes   []awsVolume
	Snapshots []awsSnapshot
	Addresses []awsAddress
}

// awsCoster: AWS read only (the real one: awsCostAPI; tests: a fake)
type awsCoster interface {
	// Inventory: everything in the session regions; a part that failed is its last good listing, with the first error
	Inventory(now time.Time) (awsInventory, error)
	// Billed: Cost Explorer's usage cost so far in month ("YYYY-MM"), and the account it is for
	Billed(month string) (float64, string, error)
}

// awsBurn: the hourly rate of an inventory
type awsBurn struct {
	RatePerHour  float64
	Running      int
	Volumes      int
	VolumeGB     int
	Snapshots    int
	SnapshotGB   float64
	IPv4         int
	UnknownTypes []string
}

func awsBurnRate(inv awsInventory) awsBurn {
	var b awsBurn
	ips := map[string]bool{}
	for _, in := range inv.Instances {
		if in.State != "running" {
			continue // pending is not billed yet; stopped instances bill only their volumes
		}
		p, known := awsInstanceRate(in.Region, in.Type)
		if !known {
			b.UnknownTypes = append(b.UnknownTypes, in.Region+"/"+in.Type)
		}
		b.RatePerHour += p
		b.Running++
		if in.PublicIP != "" {
			ips[in.PublicIP] = true
		}
	}
	for _, v := range inv.Volumes {
		if v.State == "deleting" || v.State == "deleted" || v.State == "error" {
			continue
		}
		gp3, _ := awsStorageRate(v.Region)
		b.RatePerHour += float64(v.SizeGB) * gp3 / hoursPerMonth
		b.Volumes++
		b.VolumeGB += v.SizeGB
	}
	for _, s := range inv.Snapshots {
		if s.State == "error" {
			continue
		}
		gb := float64(s.Bytes) / (1 << 30)
		if s.Bytes <= 0 {
			gb = float64(s.VolumeGB)
		}
		_, snap := awsStorageRate(s.Region)
		b.RatePerHour += gb * snap / hoursPerMonth
		b.Snapshots++
		b.SnapshotGB += gb
	}
	for _, a := range inv.Addresses { // Elastic IPs: billed attached or not; an attached one is its instance's address
		if a.PublicIP != "" {
			ips[a.PublicIP] = true
		}
	}
	b.IPv4 = len(ips)
	b.RatePerHour += float64(b.IPv4) * awsIPv4PerHour
	sort.Strings(b.UnknownTypes)
	return b
}

// awsBilled: one Cost Explorer reading
type awsBilled struct {
	Month string
	USD   float64
	At    time.Time
}

// ---- the real reader: EC2's Query API, STS and Cost Explorer, signed with SigV4 ----------------------------------

type awsCostAPI struct {
	id, secret string
	http       *http.Client
	ec2        func(region string) string // endpoints (vars: tests point them at a fake)
	sts, ce    string
	now        func() time.Time

	mu      sync.Mutex
	account string
	last    map[string]awsInventory // by region: the last good listing of each part
	slowAt  map[string]time.Time    // by region: when snapshots and addresses were last listed
}

func newAWSCostAPI(id, secret string) *awsCostAPI {
	return &awsCostAPI{id: id, secret: secret, http: &http.Client{Timeout: 30 * time.Second},
		ec2: func(region string) string { return "https://ec2." + region + ".amazonaws.com/" },
		sts: "https://sts.amazonaws.com/", ce: "https://ce.us-east-1.amazonaws.com/", now: time.Now,
		last: map[string]awsInventory{}, slowAt: map[string]time.Time{}}
}

// awsSignV4: AWS Signature Version 4 on req (body already read)
func awsSignV4(req *http.Request, body []byte, id, secret, region, service string, now time.Time) {
	t := now.UTC()
	amzDate, day := t.Format("20060102T150405Z"), t.Format("20060102")
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payload)
	headers := map[string]string{"content-type": req.Header.Get("Content-Type"), "host": req.URL.Host,
		"x-amz-content-sha256": payload, "x-amz-date": amzDate}
	if v := req.Header.Get("X-Amz-Target"); v != "" {
		headers["x-amz-target"] = v
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canon := strings.Join([]string{req.Method, path, req.URL.RawQuery, ch.String(), signed, payload}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	h := sha256.Sum256([]byte(canon))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	k := []byte("AWS4" + secret)
	for _, p := range []string{day, region, service, "aws4_request"} {
		k = hmacSHA(k, p)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+id+"/"+scope+", SignedHeaders="+signed+
		", Signature="+hex.EncodeToString(hmacSHA(k, toSign)))
}

func (a *awsCostAPI) post(endpoint, region, service, contentType, target string, body []byte) ([]byte, error) {
	req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if target != "" {
		req.Header.Set("X-Amz-Target", target)
	}
	awsSignV4(req, body, a.id, a.secret, region, service, a.now())
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		var e struct {
			Code    string `xml:"Errors>Error>Code"`
			Message string `xml:"Errors>Error>Message"`
		}
		if xml.Unmarshal(b, &e) == nil && e.Code != "" {
			msg = e.Code + " " + e.Message
		}
		return nil, fmt.Errorf("%s: HTTP %d %s", service, resp.StatusCode, msg[:min(300, len(msg))])
	}
	return b, nil
}

// ec2Call: one EC2 Query action, every page (NextToken), each page's XML to page
func (a *awsCostAPI) ec2Call(region string, p url.Values, page func([]byte) (next string, err error)) error {
	p.Set("Version", "2016-11-15")
	for {
		b, err := a.post(a.ec2(region), region, "ec2", "application/x-www-form-urlencoded; charset=utf-8", "", []byte(p.Encode()))
		if err != nil {
			return fmt.Errorf("%s %s: %w", region, p.Get("Action"), err)
		}
		next, err := page(b)
		if err != nil {
			return fmt.Errorf("%s %s: %w", region, p.Get("Action"), err)
		}
		if next == "" {
			return nil
		}
		p.Set("NextToken", next)
	}
}

type ec2Tag struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

func (a *awsCostAPI) instances(region string) ([]awsInstance, error) {
	p := url.Values{"Action": {"DescribeInstances"}, "MaxResults": {"1000"}}
	var out []awsInstance
	return out, a.ec2Call(region, p, func(b []byte) (string, error) {
		var r struct {
			Next         string `xml:"nextToken"`
			Reservations []struct {
				Instances []struct {
					ID    string   `xml:"instanceId"`
					Type  string   `xml:"instanceType"`
					State string   `xml:"instanceState>name"`
					IP    string   `xml:"ipAddress"`
					Tags  []ec2Tag `xml:"tagSet>item"`
				} `xml:"instancesSet>item"`
			} `xml:"reservationSet>item"`
		}
		if err := xml.Unmarshal(b, &r); err != nil {
			return "", err
		}
		for _, res := range r.Reservations {
			for _, i := range res.Instances {
				in := awsInstance{ID: i.ID, Region: region, Type: i.Type, State: i.State, PublicIP: i.IP}
				for _, t := range i.Tags {
					switch t.Key {
					case "Name":
						in.Name = t.Value
					case "jarvis4_source":
						in.Source = t.Value
					}
				}
				out = append(out, in)
			}
		}
		return r.Next, nil
	})
}

func (a *awsCostAPI) volumes(region string) ([]awsVolume, error) {
	p := url.Values{"Action": {"DescribeVolumes"}, "MaxResults": {"500"}}
	var out []awsVolume
	return out, a.ec2Call(region, p, func(b []byte) (string, error) {
		var r struct {
			Next    string `xml:"nextToken"`
			Volumes []struct {
				ID     string `xml:"volumeId"`
				Size   int    `xml:"size"`
				Status string `xml:"status"`
			} `xml:"volumeSet>item"`
		}
		if err := xml.Unmarshal(b, &r); err != nil {
			return "", err
		}
		for _, v := range r.Volumes {
			out = append(out, awsVolume{ID: v.ID, Region: region, State: v.Status, SizeGB: v.Size})
		}
		return r.Next, nil
	})
}

func (a *awsCostAPI) snapshots(region string) ([]awsSnapshot, error) {
	p := url.Values{"Action": {"DescribeSnapshots"}, "Owner.1": {"self"}, "MaxResults": {"1000"}}
	var out []awsSnapshot
	return out, a.ec2Call(region, p, func(b []byte) (string, error) {
		var r struct {
			Next  string `xml:"nextToken"`
			Snaps []struct {
				ID     string `xml:"snapshotId"`
				Size   int    `xml:"volumeSize"`
				Full   int64  `xml:"fullSnapshotSizeInBytes"`
				Status string `xml:"status"`
			} `xml:"snapshotSet>item"`
		}
		if err := xml.Unmarshal(b, &r); err != nil {
			return "", err
		}
		for _, s := range r.Snaps {
			out = append(out, awsSnapshot{ID: s.ID, Region: region, State: s.Status, VolumeGB: s.Size, Bytes: s.Full})
		}
		return r.Next, nil
	})
}

func (a *awsCostAPI) addresses(region string) ([]awsAddress, error) {
	var out []awsAddress
	return out, a.ec2Call(region, url.Values{"Action": {"DescribeAddresses"}}, func(b []byte) (string, error) {
		var r struct {
			Addrs []struct {
				IP string `xml:"publicIp"`
			} `xml:"addressesSet>item"`
		}
		if err := xml.Unmarshal(b, &r); err != nil {
			return "", err
		}
		for _, x := range r.Addrs {
			out = append(out, awsAddress{Region: region, PublicIP: x.IP})
		}
		return "", nil
	})
}

func (a *awsCostAPI) Inventory(now time.Time) (awsInventory, error) {
	var all awsInventory
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, region := range awsBudgetRegions {
		a.mu.Lock()
		cur, slowAt := a.last[region], a.slowAt[region]
		a.mu.Unlock()
		if ins, err := a.instances(region); err == nil {
			cur.Instances = ins
		} else {
			keep(err)
		}
		if vs, err := a.volumes(region); err == nil {
			cur.Volumes = vs
		} else {
			keep(err)
		}
		if now.Sub(slowAt) >= awsSnapshotEvery {
			ok := true
			if ss, err := a.snapshots(region); err == nil {
				cur.Snapshots = ss
			} else {
				keep(err)
				ok = false
			}
			if as, err := a.addresses(region); err == nil {
				cur.Addresses = as
			} else {
				keep(err)
				ok = false
			}
			if ok {
				slowAt = now
			}
		}
		a.mu.Lock()
		a.last[region], a.slowAt[region] = cur, slowAt
		a.mu.Unlock()
		all.Instances = append(all.Instances, cur.Instances...)
		all.Volumes = append(all.Volumes, cur.Volumes...)
		all.Snapshots = append(all.Snapshots, cur.Snapshots...)
		all.Addresses = append(all.Addresses, cur.Addresses...)
	}
	return all, firstErr
}

// Account: the key's own account (STS GetCallerIdentity: needs no permission)
func (a *awsCostAPI) Account() (string, error) {
	a.mu.Lock()
	acct := a.account
	a.mu.Unlock()
	if acct != "" {
		return acct, nil
	}
	b, err := a.post(a.sts, "us-east-1", "sts", "application/x-www-form-urlencoded; charset=utf-8", "",
		[]byte("Action=GetCallerIdentity&Version=2011-06-15"))
	if err != nil {
		return "", err
	}
	var r struct {
		Account string `xml:"GetCallerIdentityResult>Account"`
	}
	if err := xml.Unmarshal(b, &r); err != nil || r.Account == "" {
		return "", fmt.Errorf("sts: no account in the answer (%v)", err)
	}
	a.mu.Lock()
	a.account = r.Account
	a.mu.Unlock()
	return r.Account, nil
}

func (a *awsCostAPI) Billed(month string) (float64, string, error) {
	acct, err := a.Account()
	if err != nil {
		return 0, "", err
	}
	start, err := time.Parse("2006-01", month)
	if err != nil {
		return 0, acct, err
	}
	q := map[string]any{
		"TimePeriod":  map[string]string{"Start": start.Format("2006-01-02"), "End": start.AddDate(0, 1, 0).Format("2006-01-02")},
		"Granularity": "MONTHLY",
		"Metrics":     []string{"UnblendedCost"},
		"Filter": map[string]any{"And": []any{
			map[string]any{"Dimensions": map[string]any{"Key": "LINKED_ACCOUNT", "Values": []string{acct}}},
			map[string]any{"Dimensions": map[string]any{"Key": "RECORD_TYPE", "Values": []string{"Usage"}}},
		}},
	}
	body, _ := json.Marshal(q)
	b, err := a.post(a.ce, "us-east-1", "ce", "application/x-amz-json-1.1", "AWSInsightsIndexService.GetCostAndUsage", body)
	if err != nil {
		return 0, acct, err
	}
	var r struct {
		ResultsByTime []struct {
			Total map[string]struct{ Amount string } `json:"Total"`
		} `json:"ResultsByTime"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return 0, acct, err
	}
	total := 0.0
	for _, p := range r.ResultsByTime {
		v, err := strconv.ParseFloat(p.Total["UnblendedCost"].Amount, 64)
		if err != nil {
			return 0, acct, fmt.Errorf("ce: amount %q", p.Total["UnblendedCost"].Amount)
		}
		total += v
	}
	return total, acct, nil
}

// awsCosterFromEnv: the router's read-only key (AWS_READ_ACCESS_KEY_ID, as awsrunner.go), else nil: no AWS in the pool
func awsCosterFromEnv() awsCoster {
	id, secret := os.Getenv("AWS_READ_ACCESS_KEY_ID"), os.Getenv("AWS_READ_SECRET_ACCESS_KEY")
	if id == "" || secret == "" {
		return nil
	}
	return newAWSCostAPI(id, secret)
}

// ---- the tick's AWS part ------------------------------------------------------------------------------

// awsBudgetPart: what one tick read from AWS
type awsBudgetPart struct {
	inv     awsInventory
	burn    awsBurn
	billed  *awsBilled // a fresh Cost Explorer reading, else nil
	acct    string
	err     string
	billErr string
}

var awsBillAccount struct {
	sync.Mutex
	acct, err string
}

// readAWS: the inventory every tick, Cost Explorer when the month's reading is older than awsBilledEvery
func readAWS(aws awsCoster, prev *BudgetState, now time.Time) *awsBudgetPart {
	if aws == nil {
		return nil
	}
	p := &awsBudgetPart{}
	inv, err := aws.Inventory(now)
	p.inv, p.burn = inv, awsBurnRate(inv)
	if err != nil {
		p.err = err.Error()
		log.Printf("[budget] AWS: %v (counted from the last list)", err)
	}
	if len(p.burn.UnknownTypes) > 0 {
		log.Printf("[budget] AWS: no price for %s: priced as the dearest type", strings.Join(p.burn.UnknownTypes, ", "))
	}
	month := now.UTC().Format("2006-01")
	if prev == nil || prev.Month != month || prev.AWSBilledAt == nil || now.Sub(*prev.AWSBilledAt) >= awsBilledEvery {
		usd, acct, err := aws.Billed(month)
		awsBillAccount.Lock()
		if acct != "" {
			awsBillAccount.acct = acct
		}
		awsBillAccount.err = ""
		if err != nil {
			awsBillAccount.err = err.Error()
		}
		awsBillAccount.Unlock()
		if err != nil {
			log.Printf("[budget] AWS Cost Explorer: %v", err)
		} else {
			p.billed = &awsBilled{Month: month, USD: usd, At: now.UTC()}
		}
	}
	awsBillAccount.Lock()
	p.acct, p.billErr = awsBillAccount.acct, awsBillAccount.err
	awsBillAccount.Unlock()
	return p
}

// view: the AWS half of the budget view
func (p *awsBudgetPart) view(r *Router, s BudgetState) map[string]any {
	other := []map[string]string{}
	r.st.Do(func(d *persisted) {
		for _, in := range p.inv.Instances {
			if in.State == "terminated" || in.State == "shutting-down" {
				continue
			}
			if ss := d.Sessions[d.Machines[in.ID]]; ss != nil && ss.MachineID == in.ID {
				continue
			}
			other = append(other, map[string]string{"id": in.ID, "region": in.Region, "type": in.Type, "state": in.State, "name": in.Name})
		}
	})
	sort.Slice(other, func(i, j int) bool { return other[i]["id"] < other[j]["id"] })
	v := map[string]any{"spentUsd": s.awsPart(), "estimateUsd": s.AWSUSD, "billedUsd": s.AWSBilledUSD, "billedAt": s.AWSBilledAt,
		"ratePerHour": p.burn.RatePerHour, "perMonth": p.burn.RatePerHour * hoursPerMonth, "running": p.burn.Running,
		"volumes": p.burn.Volumes, "volumeGb": p.burn.VolumeGB, "snapshots": p.burn.Snapshots,
		"snapshotGb": math.Round(p.burn.SnapshotGB*10) / 10, "publicIpv4": p.burn.IPv4, "account": p.acct,
		"regions": awsBudgetRegions, "other": other, "error": nil, "billedError": nil}
	if p.err != "" {
		v["error"] = p.err
	}
	if p.billErr != "" {
		v["billedError"] = p.billErr
	}
	return v
}
