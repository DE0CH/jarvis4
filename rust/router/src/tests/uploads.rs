use crate::testutil::{Rig, add_session, new_test_machine, new_test_router, wait_for};
use crate::uploads::MAX_SESSION_UPLOADS;
use crate::vouch::{AttachmentRef, SessionConfig};
use jarvis_go::GoTime;
use sha2::Digest;

fn app(
    h: &crate::nethttp::Handler,
    method: &str,
    target: &str,
    body: &str,
    hdr: &[(&str, &str)],
) -> (u16, String) {
    let mut req = crate::nethttp::Req::new(method, target, body.as_bytes());
    for (k, v) in hdr {
        req = req.with_header(k, v);
    }
    let mut w = crate::nethttp::W::recorder();
    h(&mut w, &mut req);
    (w.status(), w.body_text())
}

/// A session proposing a new session attaches files it staged itself: they go into the new line's signed config by
/// hash exactly as the app's do, the app reads them back for the approval page, and the new session's first machine
/// lists them with the core's attestation. An upload is its owner's only.
#[test]
fn a_sessions_proposal_carries_its_own_uploads() {
    let (rg, vc) = Rig::v2_with(|c| c.no_access = true);
    add_session(&rg, "sA", "started", "mA", false);
    add_session(&rg, "sB", "started", "mB", false);
    let (ma, mb) = (new_test_machine(&rg, "mA"), new_test_machine(&rg, "mB"));
    let mh = rg.machine_handler();
    let h = rg.handler();
    let (photo, notes) = ("\u{89}PNG a screenshot", "some notes");
    let (code, out) = ma.do_(
        &mh,
        "PUT",
        "/m/api/sessions/sA/uploads/u1/screen%20shot.png",
        photo,
    );
    assert!(
        code == 200
            && out["name"] == "screen_shot.png"
            && out["isImage"] == true
            && out["size"] == photo.len(),
        "{code} {out}"
    );
    let (code, out) = ma.do_(&mh, "PUT", "/m/api/sessions/sA/uploads/u1/notes.txt", notes);
    assert!(code == 200 && out["isImage"] == false, "{code} {out}");
    // another session's path, another session's upload, the app on a session's upload
    assert_eq!(
        ma.do_(&mh, "PUT", "/m/api/sessions/sB/uploads/u2/x.txt", "x")
            .0,
        403,
        "another session's path"
    );
    assert_eq!(
        mb.do_(&mh, "PUT", "/m/api/sessions/sB/uploads/u1/x.txt", "x")
            .0,
        400,
        "another session's upload"
    );
    assert_eq!(
        app(
            &h,
            "POST",
            "/api/uploads",
            "x",
            &[("x-upload-id", "u1"), ("x-upload-name", "x.txt")]
        )
        .0,
        400,
        "the app on a session's upload"
    );
    let bind = r#"{"prompt":"p","explanation":"e","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}}"#;
    assert_eq!(
        mb.do_(&mh, "POST", "/m/api/sessions", bind).0,
        400,
        "another session bound it"
    );
    assert_eq!(
        app(
            &h,
            "POST",
            "/api/sessions",
            r#"{"prompt":"p","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}}"#,
            &[]
        )
        .0,
        400,
        "the app bound it"
    );
    let other = r#"{"prompt":"p","explanation":"e","attachments":{"uploadId":"u1","files":[{"name":"other.png"}]}}"#;
    assert_eq!(
        ma.do_(&mh, "POST", "/m/api/sessions", other).0,
        400,
        "a file never uploaded"
    );
    // a batch binding one upload twice: nothing filed
    let two = r#"{"summary":"s","items":[{"intent":"new-session","requestId":"a","prompt":"p","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}},{"intent":"new-session","requestId":"b","prompt":"p","attachments":{"uploadId":"u1","files":[{"name":"notes.txt"}]}}]}"#;
    let (code, out) = ma.do_(&mh, "POST", "/m/api/requests/batch", two);
    assert!(
        code == 400 && rg.inbox().is_empty(),
        "one upload twice: {code} {out}"
    );
    let body = r#"{"requestId":"r1","label":"look","prompt":"what is on the screen?","harness":"claude","explanation":"Deyao asked",
		"attachments":{"uploadId":"u1","files":[{"name":"screen shot.png"},{"name":"notes.txt"}]}}"#;
    let (code, out) = ma.do_(&mh, "POST", "/m/api/sessions", body);
    assert_eq!(code, 200, "{out}");
    let sid = out["id"].as_str().unwrap_or("").to_string();
    let (code, again) = ma.do_(&mh, "POST", "/m/api/sessions", body);
    assert!(
        code == 200 && again["id"] == sid.as_str(),
        "a repeat: {code} {again}"
    );
    wait_for("succession", || vc.last("/succession").is_some());
    let cfg = vc
        .last("/succession")
        .map(|b| b["options"]["config"].as_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let c: SessionConfig = serde_json::from_str(&cfg).unwrap_or_default();
    let hash = |s: &str| hex::encode(sha2::Sha256::digest(s.as_bytes()));
    assert_eq!(
        c.attachments,
        [
            AttachmentRef {
                name: "screen_shot.png".into(),
                sha256: hash(photo),
                size: photo.len() as i64
            },
            AttachmentRef {
                name: "notes.txt".into(),
                sha256: hash(notes),
                size: notes.len() as i64
            },
        ],
        "signed config"
    );
    wait_for("approval", || {
        rg.st.do_(|d| {
            d.approvals.values().any(|a| {
                a.session == sid
                    && a.options.get("attachments").map(String::as_str) == Some("2 file(s)")
                    && a.origin.as_ref().is_some_and(|o| {
                        o.caller.kind == "session"
                            && o.caller.session == "sA"
                            && o.call.args["attachments"].as_array().map_or(0, Vec::len) == 2
                    })
            })
        })
    });
    // once bound, the upload takes no more files
    assert_eq!(
        ma.do_(&mh, "PUT", "/m/api/sessions/sA/uploads/u1/late.txt", "late")
            .0,
        400,
        "a file added after the proposal"
    );
    // the app reads it back for the approval page
    let (code, b) = app(
        &h,
        "GET",
        &format!("/api/sessions/{sid}/attachments/screen_shot.png"),
        "",
        &[],
    );
    assert!(code == 200 && b == photo, "app read: {code} {b:?}");
    // the new session's first machine lists both, attested
    rg.st.do_(|d| {
        if let Some(s) = d.sessions.get_mut(&sid) {
            s.machine_id = "mN".into();
            s.state = "initialising".into();
        }
        d.machines.insert("mN".into(), sid.clone());
    });
    let mn = new_test_machine(&rg, "mN");
    let (code, out) = mn.do_(&mh, "GET", "/m/attachments", "");
    assert!(
        code == 200
            && out["files"].as_array().map_or(0, Vec::len) == 2
            && out["attest"].as_object().map_or(0, |m| m.len()) == 2,
        "{code} {out}"
    );
}

/// a session holds at most MAX_SESSION_UPLOADS unbound uploads; unbound ones go with their owner
#[test]
fn a_sessions_unbound_uploads_are_capped() {
    let t = new_test_router();
    add_session(&t, "sA", "started", "mA", false);
    let m = new_test_machine(&t, "mA");
    let h = t.machine_handler();
    for i in 0..MAX_SESSION_UPLOADS {
        let (code, out) = m.do_(
            &h,
            "PUT",
            &format!(
                "/m/api/sessions/sA/uploads/u{}/f.txt",
                (b'a' + i as u8) as char
            ),
            "x",
        );
        assert_eq!(code, 200, "{out}");
    }
    assert_eq!(
        m.do_(&h, "PUT", "/m/api/sessions/sA/uploads/uz/f.txt", "x")
            .0,
        400,
        "one upload too many"
    );
    assert_eq!(
        m.do_(&h, "PUT", "/m/api/sessions/sA/uploads/ua/g.txt", "y")
            .0,
        200,
        "another file in an upload it holds"
    );
    t.st.do_(|d| {
        d.sessions.remove("sA");
    });
    t.sweep_uploads(GoTime::now());
    assert_eq!(
        t.st.do_(|d| d.uploads.len()),
        0,
        "uploads left after their owner went"
    );
}
