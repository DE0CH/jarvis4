# The session machines' log shipper (docs/RUNBOOK.md "Logs and metrics"): Fly's own log shipper (Vector reading
# org jarvis2-370's log stream over NATS) sending to Grafana Cloud Logs, as the Fly app jarvis2-log-shipper in that org.
# Changed from the upstream image: only the Loki sink, secret shapes replaced before anything leaves, and NO listening
# ports (upstream serves Vector's API, whose `tap` would stream every session's log to any machine on the org's private
# network, and a metrics port): the app sits in the same org as the sessions.
FROM flyio/log-shipper:v0.0.8@sha256:72c7ff62b6871b86968650a67cec99d2b438b157b1da8f5bb365a8184dcaeeec
RUN find /etc/vector/sinks -type f ! -name loki.toml -delete \
 && sed -i -e '/^\[api\]/,/^$/d' -e '/^\[sources.fly_log_metrics\]/,/^$/d' -e '/^\[sinks.fly_log_metrics_prometheus\]/,/^$/d' /etc/vector/vector.toml \
 && ! grep -q 'address' /etc/vector/vector.toml
COPY loki.toml /etc/vector/sinks/loki.toml
