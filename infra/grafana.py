#!/usr/bin/env python3
"""grafana.py — Jarvis 4's alerting in Grafana Cloud, as code (docs/RUNBOOK.md "Logs, metrics and alerts").

    GRAFANA_ADMIN_TOKEN=… GRAFANA_DISCORD_WEBHOOK=… infra/grafana.py apply
    GRAFANA_ADMIN_TOKEN=… infra/grafana.py show
    GRAFANA_SM_TOKEN=… HEALTH_PROBE_ID=… HEALTH_PROBE_SECRET=… infra/grafana.py probe [--disabled]

Stack jumboshortbread1389 (EU Germany, prod-eu-west-2), which Jarvis 2 shares: Jarvis 2's rules (folder "jarvis2",
group "boxes"), its template `jarvis2`, its contact point `jarvis2-discord` and the stack's notification policy are
Jarvis 2's and this script never writes them. GRAFANA_ADMIN_TOKEN is the stack's service account token
`jarvis2-admin`; GRAFANA_DISCORD_WEBHOOK is the webhook "Grafana" of the Discord channel #jarvis2-alerts (both in the
`jarvis2-ops` store). `apply` makes or updates, idempotently: the message template `jarvis4` (what is wrong, what it
means, what to do), the contact point `jarvis4-discord`, the folder "Jarvis 4" (uid jarvis4) and its rule group
"cluster" below; each rule names its contact point itself (notification_settings), so the shared policy stays as it
is. The rules read what Alloy ships from each node of the cluster (infra/alloy/box.alloy, label box="cluster" and
node) and what the external probe reports (Synthetic Monitoring, `probe` below). Per node, nothing to list: a node
that has sent metrics in the last 24 h and none for 5 min is "gone quiet", so a node infra/cluster-node.sh adds is
covered once it has shipped once (a removed node's "gone quiet" resolves 24 h later). Prints names, never a token.

`probe` makes or updates the Synthetic Monitoring HTTP check `jarvis4-healthz`: GET https://jarvis4.deyaochen.com/healthz
once a minute from London and Frankfurt (2 × 43,200 = 86,400 runs a month, inside the free 100k), with the Access
service token jarvis2-health-probe (infra/cloudflare.py --health), 200 required. GRAFANA_SM_TOKEN is the Synthetic
Monitoring access token of the stack (`jarvis2-ops` store).
"""
SM = "https://synthetic-monitoring-api-eu-west-2.grafana.net/api/v1"
import json, os, sys, urllib.request, urllib.error

STACK = "https://jumboshortbread1389.grafana.net"
PROM, LOKI = "grafanacloud-prom", "grafanacloud-logs"
FOLDER, GROUP, TPL, CP = "jarvis4", "cluster", "jarvis4", "jarvis4-discord"


def call(method, path, body=None):
    req = urllib.request.Request(STACK + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + os.environ["GRAFANA_ADMIN_TOKEN"],
                                          "Content-Type": "application/json", "X-Disable-Provenance": "true",
                                          "User-Agent": "jarvis2-infra"})
    try:
        with urllib.request.urlopen(req) as r:
            t = r.read()
            return r.status, json.loads(t) if t else {}
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]


def rule(uid, title, summary, ds, expr, threshold, for_="2m", kind="prom", severity="warning", meaning="", action="",
         exec_err="KeepLast"):
    """one alert rule: query A, reduce B (last), threshold C (> threshold).

    summary / meaning / action are the three lines of the Discord message (what is wrong, what it means, what to do;
    template `jarvis4` below). execErrState KeepLast: when Grafana Cloud can't run the query (its own Prometheus or
    Loki times out, 2026-10-21) the rule keeps its last state instead of paging a "DatasourceError" with this rule's
    severity; the `j4-grafana-*` canaries below report a query error that lasts. noDataState OK: every query here is
    written so that the bad case PRODUCES a series (absent_over_time, rate > x, count > x), so no data = healthy."""
    model = {"refId": "A", "expr": expr, "instant": True} if kind == "prom" else {"refId": "A", "expr": expr, "queryType": "instant"}
    ann = {"summary": summary}
    if meaning:
        ann["meaning"] = meaning
    if action:
        ann["action"] = action
    return {
        "uid": uid, "title": title, "condition": "C", "for": for_, "noDataState": "OK", "execErrState": exec_err,
        "annotations": ann, "labels": {"severity": severity, "system": "jarvis4"},
        "notification_settings": {"receiver": CP, "group_by": ["alertname", "node"],
                                  "group_wait": "30s", "group_interval": "5m", "repeat_interval": "4h"},
        "data": [
            {"refId": "A", "datasourceUid": ds, "relativeTimeRange": {"from": 600, "to": 0}, "model": model},
            {"refId": "B", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
             "model": {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last"}},
            {"refId": "C", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
             "model": {"refId": "C", "type": "threshold", "expression": "B",
                       "conditions": [{"evaluator": {"type": "gt", "params": [threshold]}}]}},
        ],
    }


C = 'box="cluster"'          # every series from the cluster
N = 'box="cluster",node!=""'  # those with a node (all of them since 2026-10-23)


def rules():
    return [
        # memory pressure: the share of time every task stalled on memory (PSI "full"), the warning before a thrash
        rule("j4-mem-pressure", "Memory pressure",
             "{{ $labels.node }} is short of memory: its tasks stalled on memory over 2 % of the time for 2 min.",
             PROM, f'sum by (node) (rate(node_pressure_memory_stalled_seconds_total{{{N}}}[2m]))', 0.02,
             meaning="Something on it is using too much memory; left alone it can slow to a crawl.",
             action="Look at container_memory_working_set_bytes for that node in Grafana to see which pod grew."),
        rule("j4-oom", "OOM kill",
             "The kernel killed a process for memory on {{ $labels.node }} in the last 5 min.",
             PROM, f'sum by (node) (increase(node_vmstat_oom_kill{{{N}}}[5m]))', 0, for_="0s",
             meaning="A program on it ran out of memory and was stopped; k3s usually restarts it.",
             action="Check that node's journal (unit kernel) for which process, and whether it keeps happening."),
        rule("j4-disk", "Disk above 80 %",
             "The root filesystem of {{ $labels.node }} is over 80 % full.",
             PROM, f'max by (node) (1 - node_filesystem_avail_bytes{{{N},mountpoint="/"}} / node_filesystem_size_bytes{{{N},mountpoint="/"}})', 0.8, for_="10m",
             meaning="Nothing breaks yet; at 100 % pods fail to write and images can't be pulled.",
             action="Find what grew (images, logs, volumes) and prune it through git."),
        # gone quiet, per node: seen in the last 24 h, nothing for 5 min (an instant query looks back 5 min)
        rule("j4-silent-node", "Gone quiet",
             "No metrics have arrived from {{ $labels.node }} for 5 min.",
             PROM, f'count by (node) (last_over_time(node_time_seconds{{{N}}}[24h])) unless count by (node) (node_time_seconds{{{N}}})', 0,
             for_="0s", severity="critical",
             meaning="That node, its Alloy (the shipper) or its WARP link is down: what runs on it (on the server: Jarvis 4 "
                     "itself; on the others: watches, a router replica) may be down.",
             action="Check whether Jarvis 4 answers in the app; a node that is gone is rebuilt from git (RUNBOOK)."),
        # and the whole cluster, which the per-node rule can't see once every node has been silent for 24 h
        rule("j4-silent-cluster", "Gone quiet",
             "No metrics have arrived from any node of the cluster for 5 min.",
             PROM, f'absent_over_time(node_time_seconds{{{C}}}[5m])', 0, for_="0s", severity="critical",
             meaning="The cluster, or every node's link out, is down: Jarvis 4 itself may be down.",
             action="Check whether Jarvis 4 answers in the app; if the server is gone, it is rebuilt from git (RUNBOOK)."),
        rule("j4-flux", "Flux failing",
             "Flux on the cluster has failed to reconcile for 10 min.",
             LOKI, f'sum(count_over_time({{{C}, namespace="flux-system"}} |~ "(?i)reconciliation failed" [10m]))', 5, for_="10m", kind="loki",
             meaning="New commits to main aren't reaching the cluster; what runs keeps running.",
             action="Read Flux's logs (namespace flux-system) in Grafana and fix the commit it rejects."),
        rule("j4-restarts", "Control plane restarting",
             "The kubelet restarted a router, cloudflared or kernel container on {{ $labels.node }} 3 times in 10 min.",
             LOKI, f'sum by (node) (count_over_time({{{C}, source="journal", unit=~"k3s.service|k3s-agent.service"}} |~ "(?i)(back-off restarting|liveness probe failed|readiness probe failed).*(router|cloudflared|jarvis4-kernel)" [10m]))', 3, for_="0s", kind="loki",
             meaning="Jarvis 4 may have dropped out briefly; if it keeps restarting, it is down.",
             action="Read that container's logs in Grafana for why it failed its probe."),
        rule("j4-probe", "jarvis4.deyaochen.com /healthz failing",
             "The external probe gets no 200 from https://jarvis4.deyaochen.com/healthz for 3 min.",
             PROM, '1 - min(probe_success{job="jarvis4-healthz"})', 0, for_="3m", severity="critical",
             meaning="Jarvis 4 isn't serving: the router, the tunnel or the kernel is down, so the app and sessions can't reach it.",
             action="Open the app to confirm, then check the router's and the kernel's logs in Grafana."),
        # canaries: the only rules that page on a query error, after it has lasted 15 min, as a notice. A real
        # series keeps them Normal (gt a value never reached); an empty result is No data = OK.
        rule("j4-grafana-metrics", "Grafana can't query its own metrics",
             "Grafana Cloud couldn't query its own metrics store for 15 min.",
             PROM, f'count(node_time_seconds{{{C}}})', 1e9, for_="15m", severity="notice", exec_err="Error",
             meaning="This is Grafana's problem, not Jarvis's: the nodes are fine as far as anyone knows, but the metric alerts (gone quiet, memory, disk, the probe) can't fire meanwhile.",
             action="Nothing to fix on our side; it clears by itself. https://status.grafana.com says whether Grafana knows."),
        rule("j4-grafana-logs", "Grafana can't query its own logs",
             "Grafana Cloud couldn't query its own logs store for 15 min.",
             LOKI, f'sum(count_over_time({{{C}}} [5m]))', 1e12, for_="15m", kind="loki", severity="notice", exec_err="Error",
             meaning="This is Grafana's problem, not Jarvis's: the log alerts (Flux, restarts) can't fire meanwhile.",
             action="Nothing to fix on our side; it clears by itself. https://status.grafana.com says whether Grafana knows."),
    ]


# the rule's name, then "on <node>" from the label (Grafana doesn't fill in a template inside a rule's title, so the
# titles stay plain: "OOM kill on {{ $labels.box }}" reached Discord as written, 2026-10-21)
TEMPLATE = """{{ define "jarvis4.name" }}{{ if .Labels.rulename }}{{ .Labels.rulename }}{{ else }}{{ .Labels.alertname }}{{ end }}{{ with .Labels.node }} on {{ . }}{{ end }}{{ end }}
{{ define "jarvis4.title" }}{{ if eq .Status "firing" }}{{ if eq .CommonLabels.severity "critical" }}Critical{{ else }}Alert{{ end }}{{ else }}Resolved{{ end }}: {{ with index .Alerts 0 }}{{ template "jarvis4.name" . }}{{ end }}{{ if gt (len .Alerts) 1 }} ({{ len .Alerts }} alerts){{ end }}{{ end }}
{{ define "jarvis4.message" }}{{ range .Alerts.Firing }}**{{ template "jarvis4.name" . }}**
{{ .Annotations.summary }}
{{ with .Annotations.meaning }}What it means: {{ . }}
{{ end }}{{ with .Annotations.action }}What to do: {{ . }}
{{ end }}{{ if eq .Labels.alertname "DatasourceError" }}(Grafana's query error: {{ .Annotations.Error }})
{{ end }}Since {{ .StartsAt.UTC.Format "15:04 UTC, 2 Jan" }} · {{ .Labels.severity }}

{{ end }}{{ range .Alerts.Resolved }}Resolved: **{{ template "jarvis4.name" . }}** ({{ .StartsAt.UTC.Format "15:04" }} to {{ .EndsAt.UTC.Format "15:04 UTC" }})
{{ end }}{{ end }}"""


def apply():
    hook = os.environ["GRAFANA_DISCORD_WEBHOOK"]
    st, tpl = call("GET", f"/api/v1/provisioning/templates/{TPL}")
    print("template", TPL, call("PUT", f"/api/v1/provisioning/templates/{TPL}",
                                {"template": TEMPLATE, "version": tpl.get("version", "") if isinstance(tpl, dict) else ""})[0])
    st, cps = call("GET", f"/api/v1/provisioning/contact-points?name={CP}")
    cp = {"name": CP, "type": "discord",
          "settings": {"url": hook, "use_discord_username": False,
                       "title": '{{ template "jarvis4.title" . }}', "message": '{{ template "jarvis4.message" . }}'},
          "disableResolveMessage": False}
    if isinstance(cps, list) and cps:
        cp["uid"] = cps[0]["uid"]
        print("contact point", CP, call("PUT", f"/api/v1/provisioning/contact-points/{cp['uid']}", cp)[0])
    else:
        print("contact point", CP, call("POST", "/api/v1/provisioning/contact-points", cp)[0])
    st, _ = call("GET", f"/api/folders/{FOLDER}")
    if st != 200:
        print("folder", call("POST", "/api/folders", {"uid": FOLDER, "title": "Jarvis 4"})[0])
    st, body = call("PUT", f"/api/v1/provisioning/folder/{FOLDER}/rule-groups/{GROUP}",
                    {"title": GROUP, "interval": 60, "rules": rules()})
    print("rule group", GROUP, st, "" if st < 300 else body)
    if st >= 300:
        sys.exit(1)


def sm(method, path, body=None):
    req = urllib.request.Request(SM + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + os.environ["GRAFANA_SM_TOKEN"],
                                          "Content-Type": "application/json", "User-Agent": "jarvis2-infra"})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:400]


def probe(enabled=True):
    check = {"job": "jarvis4-healthz", "target": "https://jarvis4.deyaochen.com/healthz", "frequency": 60000,
             "timeout": 10000, "enabled": enabled, "probes": [1, 14], "alertSensitivity": "none", "basicMetricsOnly": True,
             "labels": [{"name": "system", "value": "jarvis4"}],
             "settings": {"http": {"method": "GET", "ipVersion": "Any", "noFollowRedirects": True, "failIfNotSSL": True,
                                   "validStatusCodes": [200],
                                   "headers": ["CF-Access-Client-Id: " + os.environ["HEALTH_PROBE_ID"],
                                               "CF-Access-Client-Secret: " + os.environ["HEALTH_PROBE_SECRET"]]}}}
    st, checks = sm("GET", "/check/list")
    old = next((c for c in checks if c.get("job") == check["job"]), None) if isinstance(checks, list) else None
    if old:
        check |= {"id": old["id"], "tenantId": old["tenantId"]}
        st, _ = sm("POST", "/check/update", check)
    else:
        st, _ = sm("POST", "/check/add", check)
    print("check jarvis4-healthz", st)


def show():
    st, g = call("GET", f"/api/v1/provisioning/folder/{FOLDER}/rule-groups/{GROUP}")
    for r in (g.get("rules", []) if isinstance(g, dict) else []):
        print(r["uid"], "|", r["title"], "| for", r["for"], "| noData", r["noDataState"], "| execErr", r["execErrState"],
              "|", r["labels"].get("severity"))
    st, cps = call("GET", f"/api/v1/provisioning/contact-points?name={CP}")
    for c in cps if isinstance(cps, list) else []:
        print("contact point", c["name"], "| title", c["settings"].get("title"), "| message", c["settings"].get("message"))
    st, t = call("GET", f"/api/v1/provisioning/templates/{TPL}")
    print("template", TPL, st, "matches" if isinstance(t, dict) and t.get("template") == TEMPLATE else "DIFFERS")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["apply"]:
        apply()
    elif a[:1] == ["probe"]:
        probe(enabled="--disabled" not in a)
    elif a[:1] == ["show"]:
        show()
    else:
        sys.exit(__doc__)
