# Plan: sessions on AWS EC2, Fly kept as an option

Deyao, 2026-11-03: sessions run on AWS by default, one EC2 instance per session, started when the session starts
(a few minutes' start is fine); Fly stays as a per-session option. Deyao's own AWS account, on-demand,
regions London (eu-west-2), Singapore (ap-southeast-1), Tokyo (ap-northeast-1); no Hong Kong. A container OS keeps the
change small; the kernel change is the spawner's second backend, which Deyao signs into the roster as a new signer.

## The runner

A session has a runner, `aws` (default) or `fly`, next to its region; New session and Upgrade offer both. The router
passes it to the spawner's `start` (`runner`), and the spawner keeps it per machine. Machine objects are `fly-<id>`
(as now) or `aws-<instance id>`; everything after the spawner treats both the same.

## One session = one EC2 instance (`kernel/spawner/aws.go`)

The same calls the Fly backend makes, single calls, no waiting (the router retries):

| Fly | AWS |
|---|---|
| CreateVolume + Create | `RunInstances` from the region's launch template `jarvis4-session` (Flatcar Container Linux, pinned AMI): the size's instance type, one gp3 volume of 30 GB + the session's `diskGb` (Flatcar's root grows to fill it; `/data` is a directory on it), tag `jarvis4_source`, user-data = an Ignition config that runs `ghcr.io/de0ch/jarvis4-session@sha256:…` privileged with host networking, `/data` bound in, the env the core sets, and the machine's WireGuard |
| Inspect | `DescribeInstances` (pending → created, running → started, shutting-down → destroying, terminated → destroyed), the tag; the image = the `IMAGE=` line of the user-data's `/etc/jarvis4/image.env` (`DescribeInstanceAttribute userData`), which the session unit runs |
| Init (exec jarvis2-init) | the machine's keeper writes `JARVIS2-KEYS {…}` to the serial console every 20 s until its cert is in; the spawner reads it live over the EC2 Serial Console (`kernel/spawner/awsserial.go`: from Create on, a one-off key pushed with `SendSerialConsoleSSHPublicKey`, SSH to the region's endpoint with AWS's published host key pinned, read until the line, closed), else from `GetConsoleOutput --latest`; either way AWS's word that the line came from that instance |
| Destroy | `TerminateInstances` (the volume goes with it) |
| DeleteVolume | nothing to do |

Measured 2026-11-03 (Singapore, t3.medium): running after 21 s, the session unit at 40 s, the 7.5 GB image pulled in
3 min, the keys line on the console 4.8 min after launch. A second volume for `/data` was tried and dropped: NVMe
doesn't keep device names (the root disk itself was `nvme1n1`). Each region's template now boots an AMI with the pinned image pre-pulled
(`infra/aws/bake.sh`, run by `.github/workflows/aws.yml` after every images run; 2026-11-04): the unit's
`docker pull <digest>` finds it on disk. Each bake's test boot reports, in the run's summary, Ignition running again,
`docker run`'s time and GetConsoleOutput's lag. A region whose bake failed boots plain Flatcar and pulls as before.
Measured 2026-11-04 (London, t3.medium, the baked AMI, its own image; three timed boots with the session's unit
steps on the host and the console read every 2 s): the kernel 15 s after launch; network-online at 23-32 s and
docker up at 31-53 s of uptime (the slow, varying part: first reads of a disk restored from a snapshot load lazily);
`docker pull` of the image on disk 1.3 s (9-12 s when the pin had moved past the AMI's image: the changed layers);
`docker run` 7.7 s (5.6-8.8 s in the bakes' test boots); the keys file 4.7 s later; the keys line written 61-85 s
after launch. GetConsoleOutput --latest refreshes in batches about every 30-40 s, so a line shows 7-47 s after it is
written (33 s and 43 s in these boots); the spawner sees the keys 74-119 s after launch (the router asks every 2 s).
That batching plus `docker run` and keygen is the ~65 s between the pull's end and the keys line on 2026-11-03.
Read live over the EC2 Serial Console the same line arrived 0.2 s after it was written (2026-11-04, London, a reader on
another instance), so the spawner reads it that way and keeps GetConsoleOutput as the fallback: a region without
serial console access, a refused key or a wrong host key stops the live reader and costs only that wait again. The
serial console allows one session per instance, and a pushed key opens one within 60 s; the reader never writes
(the console is also Flatcar's getty, which asks for a login; the core user has no password).

The container gets the whole VM, as a Fly machine does (privileged, host network, the host's cgroup), so the session
image runs unchanged; the machine reads `JARVIS2_RUNNER=aws` and `JARVIS2_MACHINE_ID` (the unit reads the instance id
from the metadata service, then closes it) and announces its keys on the console instead of waiting for
`jarvis2-init`. Machine objects in the kernel are `fly-<id>` or `aws-i-<id>`, both of kind "machine".

Sizes → instance types (`instanceType`): small → `t3.medium` (2 vCPU, 4 GB), medium → `t3.large` (2, 8), large →
`m7i.xlarge` (4, 16), 16gb → `m7i.2xlarge` (8, 32), 32gb → `r7i.2xlarge` (8, 64), 64gb → `r7i.4xlarge`, 128gb →
`r7i.8xlarge`; past that, refused.

The spawner's AWS key: IAM user `jarvis4-spawner` (infra/aws/iam.tf): RunInstances only from a launch template and
with the source tag, Describe, and GetConsoleOutput / DescribeInstanceAttribute / TerminateInstances /
SendSerialConsoleSSHPublicKey only on tagged instances (serial console access is on in each session region,
`aws_ec2_serial_console_access`; the kernel-spawner NetworkPolicy lets port 22 out for it). Sealed to the spawner like the Fly token (`infra/setup.py kernel-aws-credentials`), memory only, handed
over in the copy flip. The router's read-only key (`jarvis4-router-read`: DescribeInstances, costs) is Secret
router-secrets-aws.

## Reaching the router (WireGuard)

Fly machines reach the m-gateways over Fly's private network. An AWS machine reaches them over WireGuard (Deyao,
2026-11-03: "just use wireguard"): the router makes the machine's key pair and a tunnel address in 10.99.1.0/16 per
spawn (kept on the session until the machine is up, so a spawn whose answer was lost is adopted with them) and hands
them to the spawner, which writes `wg0` into the instance (systemd-networkd, listening on UDP 51820, the gateways
10.99.0.1 and 10.99.0.2 as peers). The m-gateways (router/awsgw.go) list the AWS machines from the router every 10 s
(GET /gw/aws-peers on the machines' port, which the gateways' proxy refuses to machines) and start every handshake
to the instance's public IPv4 (the pods' IPv4 goes out through WARP, as their handshakes to Fly's gateway do), so the
boxes take nothing inbound; the security group lets in UDP 51820 only. The machines know the gateways as
`KERNEL_AWS_MACHINE_URL` = `http://10.99.0.1:8081,http://10.99.0.2:8081`. Nothing about the tunnel is a trust element:
every /m request is signed by the machine's certified key. The gateways' AWS device runs at MTU 1200
(router/awsgw.go awsWGMTU): its UDP goes through WARP's 1280-byte tunnel, and at 1420 every full-size segment from an
instance was lost, so a machine's first small requests went through and nothing bigger did (2026-11-04: both AWS test
sessions failed "the harness didn't come up").

Flatcar has cgroup v2, Fly's guest cgroup v1: the session's and rescue memory cgroups are /sys/fs/cgroup/jarvis-session
and jarvis-rescue there, limited by memory.max (machine/oomguard.go cgroupDir).

## Infra (`infra/aws/`, OpenTofu, `.github/workflows/aws.yml`)

Per region (London, Singapore, Tokyo): a VPC 10.40.0.0/16 with a public subnet per zone, an internet gateway, the
security group (UDP 51820 in, anything out), the launch template (IMDSv2, terminate on shutdown, unlimited t3
credits). Account-wide: the IAM users above. State in R2 beside DE0CH/deyao-ai'. The workflow's key is IAM user
`jarvis4-infra` (EC2 and the /jarvis4/ IAM users only).

## Router

- A session's runner (`Session.Runner`, `NewSession.runner`, `GET /api/regions` lists runners and the default),
  fixed when made; `DEFAULT_RUNNER` (fly: aws from the first AWS session's end-to-end run, back to fly 2026-11-04 by Deyao). Its region stays a place
  that each runner maps (lhr/sin/nrt → eu-west-2/ap-southeast-1/ap-northeast-1).
- Lost machines and the adoption of a lost spawn answer look at AWS too (`listAWSMachines`).
- The lifecycle log's AWS events (router/lifecycle.go, awsread.go; 2026-11-04): while an operation runs and for 30 s
  after, the router describes each of its AWS machines every 2 s with its read-only key and writes an entry (source
  `aws`) for each change: launched (type, zone, at EC2's launch time), pending, running (public IPv4), stopping,
  shutting-down, terminated (with EC2's `stateReason`, e.g. `Client.InstanceInitiatedShutdown`, and
  `stateTransitionReason`), and "EC2 no longer lists" it; an instance already running when the operation began shows
  only its changes. The router's own steps say when the spawner launched the instance and when its keys arrived (and
  how long after the spawn), and the console's notable lines (an OOM kill, a panic, Ignition failing) join the running
  operation (awslogs.go). A launch EC2 refuses is the spawn's error, as before ("the spawn failed (…): try 2 of 3").
- Logs to Grafana: "Logs" below. The runner picker is in New session in the web page and the iPhone app (2469018).

## Budget (AWS spend, `router/awsbudget.go`)

AWS and Fly fill one pool, the existing cap (`FLY_BUDGET_USD`, default USD 50; DM at `FLY_BUDGET_WARN_USD`, 45; Deyao,
2026-11-04: "they contribute to the same pool of 50 usd"). Every budget tick (2 min) the router lists, with its read-only
key in the three session regions, every instance, EBS volume, snapshot (`Owner self`: the baked AMIs' snapshots) and
Elastic IP, and prices them at AWS's published on-demand rates (Price List API, read 2026-11-04, the tables in
awsbudget.go): running instances by type and region, gp3 GB-months, snapshots by their full stored size, USD 0.005 an
hour for each public IPv4. That rate is added to Fly's and summed over time like Fly's. At the cap the router pauses
every running session on either runner (an AWS session by its instance id, as a Fly one by its machine id); instances
that are no session's (a bake's builder, an experiment) are named in the DM, not stopped.

Cross-check: every 6 h Cost Explorer's month-to-date usage cost (`ce:GetCostAndUsage`, filtered to the key's own account
and record type Usage: no tax, no credits; USD 0.01 a request). It lags about a day but sees what the estimate doesn't
(data transfer, t3 surplus credits, other regions, the days before tracking), so the pool counts AWS as the larger of
the estimate and the billed figure. `GET /api/state` `budget`: the pool's totals, `budget.fly` and `budget.aws` (spent,
estimate, billed, rate, running, volumes, snapshots, public IPv4, instances that are no session's, account); the web
page's Settings and the app's Settings show the split.

## Billing: separate from YYC

Checked 2026-11-04 (`sts get-caller-identity` with every key): jarvis4's AWS (the `infra/aws` OpenTofu, the
`jarvis4-infra`, `jarvis4-spawner` and `jarvis4-router-read` keys, every session instance, the baked AMIs) is in
account 795109470764 (`deyaochen`, Deyao's own), the organisation's management account. YYC's AWS is the member
account 551897326524 (`yyc`). Consolidated billing puts both on one invoice, but every charge is under its account
(Cost Explorer / the bill by linked account), so jarvis4's spend never lands in YYC's figures, and the router's Cost
Explorer query filters on its own account. To tell jarvis4 apart from anything else Deyao runs in 795109470764, every
jarvis4 resource carries `app=jarvis4` (tofu's `default_tags`; the launch templates tag each instance, volume and
network interface; bake.sh its builders, AMIs and snapshots), and `app` is an active cost allocation tag in Billing
(activated 2026-11-04; it applies from then on).

## Logs (2026-11-04)

Fly's platform reads a Fly machine's output and the Fly app `jarvis2-log-shipper` takes it to Grafana (`box="fly"`).
Nothing reads an EC2 instance's: the unit's `docker run` writes the container's output to the instance's journal
(and docker's json-file log), and both go with the instance. So the AWS machines' logs reach the same Grafana stack
(the same 14 days, the same read token) through the router, `box="aws"`:

| source | what | how |
|---|---|---|
| `machine` | the container's stdout and stderr (the keeper's, the boot steps', both supervisors', the harness's console lines: what Fly ships as the app's lines) | the keeper (PID 1) makes fd 1 and 2 a pipe and tees each line on to the journal and into `/run/jarvis/output.log`; supervisor-core pushes it every 2 s to `POST /m/machine-output` (machine/output.go) |
| `journal` | the instance's systemd units: the session unit's image pull and start, docker, networkd's WireGuard, journald (not the kernel's: the console has those; not the unit's docker client after the keeper started: that is `machine`) | the keeper mounts the host's ROOT partition read only (privileged, as the container is; under a 0700 directory) and follows `journalctl -D … -b -f -o json` from the boot's start; pushed as above |
| `console` | the serial console: the kernel from its first second, the initrd's systemd, Ignition, getty, an OOM kill, a panic; also for a machine whose container never started | the leader reads `GetConsoleOutput --latest` of each live session instance every 15 s with the router's read key (`ec2:GetConsoleOutput` on tagged instances, infra/aws/iam.tf) and ships what follows the last line it shipped (router/awslogs.go) |

The machine's pushes are signed with its certified key like every `/m` request, so the router, not the machine, puts
the instance id, region and session on the lines. The machine holds no Grafana credential: the router pushes to the
Deployment `jarvis2-obs/aws-log-shipper` (Alloy, `loki.source.api`, only the router may reach it), which sets
`box="aws"`, replaces the same secret shapes as the boxes and the Fly shipper, and writes with the existing Secret
`jarvis2-obs/alloy`. The machine replaces every value the supervisor holds first (as for the supervisor log).
Labels: `instance`, `aws_region`, `session`, `source`. RUNBOOK "Logs and metrics".

Checked on instances from the session template (London, the baked AMI, 2026-11-04): docker's log driver on Flatcar is
json-file (the container's output reaches the journal only through the unit's `docker run`); the session image has
journalctl; a read-only mount of the ROOT partition is refused (EBUSY, the host has it read-write), a mount as the host
has it then `remount,bind,ro` works and refuses writes; `journalctl -D <mount>/var/log/journal -b` read the boot's
1894 entries with the unit's image pull, and `-f` followed new ones. The console holds no file contents (Ignition logs
paths only; the machine writes only its public keys there). EC2 keeps no console output of a terminated instance
(GetConsoleOutput, latest or not, came back empty within seconds of `terminated`), and its newest output lags by
7-47 s, so a line written in the last seconds before the power-off is not read.

What none of this sends: what the instance writes after the container has ended (the unit's exit status, the
power-off), since no machine is left to sign it, and the keeper's own crash trace (it reaches the journal, through
`debug.SetCrashOutput`, but the container ends with it). The lifecycle log has EC2's word instead
(`shutting-down: Client.InstanceInitiatedShutdown`: the instance powered itself off, i.e. the container ended).

**In the kernel (Deyao, 2026-11-05: "release the logs change"; a spawner release after the serial console's):** two
lines of the session unit in `kernel/spawner/aws.go` (`ignition`):

```diff
-ExecStart=/usr/bin/docker run --name session --network host --privileged --cgroupns host --env-file /etc/jarvis4/session.env --env-file /etc/jarvis4/id.env -v /data:/data ${IMAGE}
-ExecStopPost=/usr/bin/systemctl poweroff
+ExecStart=/usr/bin/docker run --name session --network host --privileged --cgroupns host --env-file /etc/jarvis4/session.env --env-file /etc/jarvis4/id.env -v /data:/data -v /var/log/journal:/run/jarvis-host/journal:ro ${IMAGE}
+ExecStopPost=/bin/sh -c 'echo "JARVIS4-SESSION-END result=$SERVICE_RESULT code=$EXIT_CODE status=$EXIT_STATUS" > /dev/ttyS0; [ "$SERVICE_RESULT" = success ] || sleep 50'
+ExecStopPost=/usr/bin/systemctl poweroff
```

1. The journal bound read only into the container: the keeper reads it there (machine/output.go already looks for
   `/run/jarvis-host/journal` first) and no longer mounts the host's disk. Same lines, a tidier way in.
2. The container's end on the console: the unit's result and exit status (what Fly's "Main child exited with code"
   gives), and, when the container didn't end cleanly, 50 s before the power-off so the router's console read sees
   it (the console's newest output lags 7-47 s); the router already ships that line and puts it into the running
   operation's lifecycle log (`JARVIS4-SESSION-END`, router/awslogs.go). Tried on a test instance from the session
   template (2026-11-04: a container exiting 3): `JARVIS4-SESSION-END result=exit-code code=exited status=3` was in
   GetConsoleOutput 28 s after it was written, before the power-off. The cost: an instance whose container failed runs
   50 s longer (USD 0.0006 on a t3.medium); a clean end (status 0, the teardown's) powers off at once.

Neither changes what the spawner checks, signs or reads (the keys line, Inspect's image), and the user-data grows by
about 200 bytes. A machine started by an older spawner has neither and works as described above.

## Order

1. Prototype by hand (done 2026-11-03).
2. `infra/aws` and its workflow.
3. Spawner AWS backend, machine side, router and m-gateways: one push, a kernel release (Deyao's OK 2026-11-03: a new
   spawner signer in the roster), then `kernel-aws-credentials`.
4. An AWS session end to end (runner aws named explicitly), then `DEFAULT_RUNNER=aws` (done 2026-11-04: the one-shot
   "AWS runner test 2" booted, ran its prompt and was archived and destroyed by itself, after the MTU fix; back to
   `fly` the same day, Deyao's call).
