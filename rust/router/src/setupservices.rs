//! GET /setup/services (the setup session; infra/setup.py services): the watch runner as the router reaches it, for an
//! operator with no way into the cluster: a check script that only prints, through the same call a watch's check
//! makes. Nothing is written. Transcript search is not Jarvis's (DE0CH/deyao-ai, search.deyaochen.com).

use crate::nethttp::{Req, W, write_json};
use crate::router::Router;
use serde_json::{Map, json};
use std::sync::Arc;
use std::time::Instant;

impl Router {
    pub fn setup_services(self: &Arc<Self>, w: &mut W, req: &mut Req) {
        let uri = if req.raw_query.is_empty() {
            req.path.clone()
        } else {
            format!("{}?{}", req.path, req.raw_query)
        };
        if let Err(e) = self.check_setup_sig(
            &req.method,
            &uri,
            &req.header("X-Setup-Time"),
            &req.header("X-Setup-Sig"),
            b"",
        ) {
            return write_json(w, 401, &json!({"error": format!("{e:#}")}));
        }
        let t0 = Instant::now();
        let mut watch = Map::new();
        let res = crate::watches::run_check_hook(&crate::watches::Watch {
            name: "setup-services-check".into(),
            script: "echo watch runner ok; exit 0".into(),
            ..Default::default()
        });
        watch.insert("ms".into(), json!(t0.elapsed().as_millis() as i64));
        match res {
            Err(e) => {
                watch.insert("error".into(), json!(format!("{e:#}")));
            }
            Ok(res) => {
                watch.insert("exit".into(), json!(res.exit));
                watch.insert(
                    "stdout".into(),
                    json!(crate::util::trim_to(&res.stdout, 200)),
                );
                watch.insert("timedOut".into(), json!(res.timed_out));
            }
        }
        write_json(
            w,
            200,
            &json!({"replica": crate::router::router_id(), "watch": {"url": crate::watches::watch_runner_url(), "run": watch}}),
        );
    }
}
