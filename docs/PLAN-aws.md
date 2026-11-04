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
credits). Account-wide: the IAM users above. State in R2 beside DE0CH/services'. The workflow's key is IAM user
`jarvis4-infra` (EC2 and the /jarvis4/ IAM users only).

## Router

- A session's runner (`Session.Runner`, `NewSession.runner`, `GET /api/regions` lists runners and the default),
  fixed when made; `DEFAULT_RUNNER` (fly: aws from the first AWS session's end-to-end run, back to fly 2026-11-04 by Deyao). Its region stays a place
  that each runner maps (lhr/sin/nrt → eu-west-2/ap-southeast-1/ap-northeast-1).
- Lost machines and the adoption of a lost spawn answer look at AWS too (`listAWSMachines`).
- To do: the budget (AWS spend), the lifecycle log's AWS events, the app's runner picker, shipping instance logs.

## Order

1. Prototype by hand (done 2026-11-03).
2. `infra/aws` and its workflow.
3. Spawner AWS backend, machine side, router and m-gateways: one push, a kernel release (Deyao's OK 2026-11-03: a new
   spawner signer in the roster), then `kernel-aws-credentials`.
4. An AWS session end to end (runner aws named explicitly), then `DEFAULT_RUNNER=aws` (done 2026-11-04: the one-shot
   "AWS runner test 2" booted, ran its prompt and was archived and destroyed by itself, after the MTU fix; back to
   `fly` the same day, Deyao's call).
