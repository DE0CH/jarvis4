#!/usr/bin/env python3
"""grafana.py — Jarvis 4's alerting in Grafana Cloud, as code (docs/RUNBOOK.md "Logs, metrics and alerts").

    GRAFANA_ADMIN_TOKEN=… GRAFANA_DISCORD_WEBHOOK=… infra/grafana.py apply [--boxes control,services]
    GRAFANA_ADMIN_TOKEN=… infra/grafana.py show
    GRAFANA_SM_TOKEN=… HEALTH_PROBE_ID=… HEALTH_PROBE_SECRET=… infra/grafana.py probe [--disabled]

Stack jumboshortbread1389 (EU Germany, prod-eu-west-2). GRAFANA_ADMIN_TOKEN is the stack's service account token
`jarvis2-admin`; GRAFANA_DISCORD_WEBHOOK is the webhook "Grafana" of the Discord channel #jarvis2-alerts (both in the
`jarvis2-ops` store). `apply` makes or updates, idempotently: the message template `jarvis2` (what is wrong, what it
means, what to do), the contact point (Discord), the notification policy (every alert to it), the folder "Jarvis 4"
and the rule group "boxes" below, for the boxes named (a box that doesn't exist yet would fire "silent"). The rules read what Alloy ships from each box (infra/alloy/box.alloy) and what the external
probe reports (Synthetic Monitoring, `probe` below). Prints names, never a token.

`probe` makes or updates the Synthetic Monitoring HTTP check `jarvis2-healthz`: GET https://jarvis4.deyaochen.com/healthz
once a minute from London and Frankfurt (2 × 43,200 = 86,400 runs a month, inside the free 100k), with the Access
service token jarvis2-health-probe (infra/cloudflare.py --health), 200 required. GRAFANA_SM_TOKEN is the Synthetic
Monitoring access token of the stack (`jarvis2-ops` store).
"""
SM = "https://synthetic-monitoring-api-eu-west-2.grafana.net/api/v1"
import json, os, sys, urllib.request, urllib.error

STACK = "https://jumboshortbread1389.grafana.net"
PROM, LOKI = "grafanacloud-prom", "grafanacloud-logs"
FOLDER = "jarvis2"


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
    template `jarvis2` below). execErrState KeepLast: when Grafana Cloud can't run the query (its own Prometheus or
    Loki times out, 2026-10-21) the rule keeps its last state instead of paging a "DatasourceError" with this rule's
    severity; the `j2-grafana-*` canaries below report a query error that lasts. noDataState OK: every query here is
    written so that the bad case PRODUCES a series (absent_over_time, rate > x, count > x), so no data = healthy."""
    model = {"refId": "A", "expr": expr, "instant": True} if kind == "prom" else {"refId": "A", "expr": expr, "queryType": "instant"}
    ann = {"summary": summary}
    if meaning:
        ann["meaning"] = meaning
    if action:
        ann["action"] = action
    return {
        "uid": uid, "title": title, "condition": "C", "for": for_, "noDataState": "OK", "execErrState": exec_err,
        "annotations": ann, "labels": {"severity": severity, "system": "jarvis2"},
        "data": [
            {"refId": "A", "datasourceUid": ds, "relativeTimeRange": {"from": 600, "to": 0}, "model": model},
            {"refId": "B", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
             "model": {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last"}},
            {"refId": "C", "datasourceUid": "__expr__", "relativeTimeRange": {"from": 0, "to": 0},
             "model": {"refId": "C", "type": "threshold", "expression": "B",
                       "conditions": [{"evaluator": {"type": "gt", "params": [threshold]}}]}},
        ],
    }


def rules(boxes):
    r = [
        # memory pressure: the share of time every task stalled on memory (PSI "full"), the warning before a thrash
        rule("j2-mem-pressure", "Memory pressure",
             "The {{ $labels.box }} box is short of memory: its tasks stalled on memory over 2 % of the time for 2 min.",
             PROM, 'sum by (box) (rate(node_pressure_memory_stalled_seconds_total{box=~"control|services"}[2m]))', 0.02,
             meaning="Something on it is using too much memory; left alone it can slow to a crawl (2026-10-15 started like this).",
             action="Look at container_memory_working_set_bytes for that box in Grafana to see which pod grew."),
        rule("j2-oom", "OOM kill",
             "The kernel killed a process for memory on the {{ $labels.box }} box in the last 5 min.",
             PROM, 'sum by (box) (increase(node_vmstat_oom_kill{box=~"control|services"}[5m]))', 0, for_="0s",
             meaning="A program on it ran out of memory and was stopped; k3s usually restarts it.",
             action="Check the journal (unit kernel) for which process, and whether it keeps happening."),
        rule("j2-disk", "Disk above 80 %",
             "The root filesystem of the {{ $labels.box }} box is over 80 % full.",
             PROM, 'max by (box) (1 - node_filesystem_avail_bytes{box=~"control|services",mountpoint="/"} / node_filesystem_size_bytes{box=~"control|services",mountpoint="/"})', 0.8, for_="10m",
             meaning="Nothing breaks yet; at 100 % pods fail to write and images can't be pulled.",
             action="Find what grew (images, logs, volumes) and prune it through git."),
        rule("j2-flux", "Flux failing",
             "Flux on the {{ $labels.box }} box has failed to reconcile for 10 min.",
             LOKI, 'sum by (box) (count_over_time({box=~"control|services", container="manager"} |~ "(?i)reconciliation failed" [10m]))', 5, for_="10m", kind="loki",
             meaning="New commits to main aren't reaching that box; what runs keeps running.",
             action="Read Flux's logs (container manager) in Grafana and fix the commit it rejects."),
        rule("j2-restarts", "Control plane restarting",
             "A control-plane container (core, router, cloudflared) was restarted by the kubelet in the last 10 min.",
             LOKI, 'sum by (box) (count_over_time({box="control", source="journal", unit="k3s.service"} |~ "(?i)(back-off restarting|liveness probe failed|readiness probe failed).*(core|router|cloudflared)" [10m]))', 3, for_="0s", kind="loki",
             meaning="Jarvis 4 may have dropped out briefly; if it keeps restarting, it is down.",
             action="Read that container's logs in Grafana for why it failed its probe."),
        rule("j2-core-change", "A new core on the control box",
             "The router saw a new core (a restart, a release or a reboot).",
             LOKI, 'sum(count_over_time({box="control", container="router"} |= "a new core (" [10m]))', 0, for_="0s", kind="loki", severity="critical",
             meaning="If the new core is empty, sessions can't get their secrets until it is Recovered.",
             action="Open the Jarvis 4 app: if it asks for Recover, do it."),
        rule("j2-probe", "jarvis4.deyaochen.com /healthz failing",
             "The external probe gets no 200 from https://jarvis4.deyaochen.com/healthz for 3 min.",
             PROM, '1 - min(probe_success{job="jarvis2-healthz"})', 0, for_="3m", severity="critical",
             meaning="Jarvis 4 isn't serving: the router, the tunnel or the kernel (the core, on a box with one) is down, so the app and sessions can't reach it.",
             action="Open the app to confirm, then check the control box's logs in Grafana."),
        # canaries: the only rules that page on a query error, after it has lasted 15 min, as a notice. A real
        # series keeps them Normal (gt a value never reached); an empty result is No data = OK.
        rule("j2-grafana-metrics", "Grafana can't query its own metrics",
             "Grafana Cloud couldn't query its own metrics store for 15 min.",
             PROM, 'count(node_time_seconds)', 1e9, for_="15m", severity="notice", exec_err="Error",
             meaning="This is Grafana's problem, not Jarvis's: the boxes are fine as far as anyone knows, but the metric alerts (gone quiet, memory, disk, the probe) can't fire meanwhile.",
             action="Nothing to fix on our side; it clears by itself. https://status.grafana.com says whether Grafana knows."),
        rule("j2-grafana-logs", "Grafana can't query its own logs",
             "Grafana Cloud couldn't query its own logs store for 15 min.",
             LOKI, 'sum(count_over_time({box="control"} [5m]))', 1e12, for_="15m", kind="loki", severity="notice", exec_err="Error",
             meaning="This is Grafana's problem, not Jarvis's: the log alerts (Flux, restarts, a new core) can't fire meanwhile.",
             action="Nothing to fix on our side; it clears by itself. https://status.grafana.com says whether Grafana knows."),
    ]
    for b in boxes:
        # absent_over_time gives a series only when the box has sent nothing for 5 min: no data = the box is sending
        r.append(rule(f"j2-silent-{b}", "Gone quiet",
                      f"No metrics have arrived from the {b} box for 5 min.",
                      PROM, f'absent_over_time(node_time_seconds{{box="{b}"}}[5m])', 0, for_="0s", severity="critical",
                      meaning=f"The {b} box, its Alloy (the shipper) or its WARP link is down"
                              + (": Jarvis 4 itself may be down." if b == "control" else ": transcript search, the iCloud index and watches may be down."),
                      action="Check whether Jarvis 4 answers in the app; if the box is gone, it is rebuilt from git (RUNBOOK)."))
    return r


# the rule's name, then "on <box>" from the label (Grafana doesn't fill in a template inside a rule's title, so the
# titles stay plain: "OOM kill on {{ $labels.box }}" reached Discord as written, 2026-10-21)
TEMPLATE = """{{ define "jarvis2.name" }}{{ if .Labels.rulename }}{{ .Labels.rulename }}{{ else }}{{ .Labels.alertname }}{{ end }}{{ with .Labels.box }} on the {{ . }} box{{ end }}{{ end }}
{{ define "jarvis2.title" }}{{ if eq .Status "firing" }}{{ if eq .CommonLabels.severity "critical" }}Critical{{ else }}Alert{{ end }}{{ else }}Resolved{{ end }}: {{ with index .Alerts 0 }}{{ template "jarvis2.name" . }}{{ end }}{{ if gt (len .Alerts) 1 }} ({{ len .Alerts }} alerts){{ end }}{{ end }}
{{ define "jarvis2.message" }}{{ range .Alerts.Firing }}**{{ template "jarvis2.name" . }}**
{{ .Annotations.summary }}
{{ with .Annotations.meaning }}What it means: {{ . }}
{{ end }}{{ with .Annotations.action }}What to do: {{ . }}
{{ end }}{{ if eq .Labels.alertname "DatasourceError" }}(Grafana's query error: {{ .Annotations.Error }})
{{ end }}Since {{ .StartsAt.UTC.Format "15:04 UTC, 2 Jan" }} · {{ .Labels.severity }}

{{ end }}{{ range .Alerts.Resolved }}Resolved: **{{ template "jarvis2.name" . }}** ({{ .StartsAt.UTC.Format "15:04" }} to {{ .EndsAt.UTC.Format "15:04 UTC" }})
{{ end }}{{ end }}"""


def apply(boxes):
    hook = os.environ["GRAFANA_DISCORD_WEBHOOK"]
    st, cps = call("GET", "/api/v1/provisioning/contact-points?name=jarvis2-discord")
    st, tpl = call("GET", "/api/v1/provisioning/templates/jarvis2")
    print("template", call("PUT", "/api/v1/provisioning/templates/jarvis2",
                           {"template": TEMPLATE, "version": tpl.get("version", "") if isinstance(tpl, dict) else ""})[0])
    cp = {"name": "jarvis2-discord", "type": "discord",
          "settings": {"url": hook, "use_discord_username": False,
                       "title": '{{ template "jarvis2.title" . }}', "message": '{{ template "jarvis2.message" . }}'},
          "disableResolveMessage": False}
    if isinstance(cps, list) and cps:
        cp["uid"] = cps[0]["uid"]
        print("contact point", call("PUT", f"/api/v1/provisioning/contact-points/{cp['uid']}", cp)[0])
    else:
        print("contact point", call("POST", "/api/v1/provisioning/contact-points", cp)[0])
    print("policy", call("PUT", "/api/v1/provisioning/policies",
                         {"receiver": "jarvis2-discord", "group_by": ["alertname", "box"],
                          "group_wait": "30s", "group_interval": "5m", "repeat_interval": "4h"})[0])
    st, _ = call("GET", f"/api/folders/{FOLDER}")
    if st != 200:
        print("folder", call("POST", "/api/folders", {"uid": FOLDER, "title": "Jarvis 4"})[0])
    st, body = call("PUT", f"/api/v1/provisioning/folder/{FOLDER}/rule-groups/boxes",
                    {"title": "boxes", "interval": 60, "rules": rules(boxes)})
    print("rule group boxes", st, "" if st < 300 else body)
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
    check = {"job": "jarvis2-healthz", "target": "https://jarvis4.deyaochen.com/healthz", "frequency": 60000,
             "timeout": 10000, "enabled": enabled, "probes": [1, 14], "alertSensitivity": "none", "basicMetricsOnly": True,
             "labels": [{"name": "system", "value": "jarvis2"}],
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
    print("check jarvis2-healthz", st)


def show():
    st, g = call("GET", f"/api/v1/provisioning/folder/{FOLDER}/rule-groups/boxes")
    for r in (g.get("rules", []) if isinstance(g, dict) else []):
        print(r["uid"], "|", r["title"], "| for", r["for"], "| noData", r["noDataState"], "| execErr", r["execErrState"],
              "|", r["labels"].get("severity"))
    st, cps = call("GET", "/api/v1/provisioning/contact-points")
    for c in cps if isinstance(cps, list) else []:
        print("contact point", c["name"], "| title", c["settings"].get("title"), "| message", c["settings"].get("message"))
    st, t = call("GET", "/api/v1/provisioning/templates/jarvis2")
    print("template jarvis2", st, "matches" if isinstance(t, dict) and t.get("template") == TEMPLATE else "DIFFERS")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["apply"]:
        boxes = ["control", "services"]
        if "--boxes" in a:
            boxes = [b for b in a[a.index("--boxes") + 1].split(",") if b]
        apply(boxes)
    elif a[:1] == ["probe"]:
        probe(enabled="--disabled" not in a)
    elif a[:1] == ["show"]:
        show()
    else:
        sys.exit(__doc__)
