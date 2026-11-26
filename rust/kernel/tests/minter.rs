//! kernel/minter/minter_test.go

use jarvis_kernel::kt::{TestServer, World};
use jarvis_kernel::minter::{
    Client, DeployKey, GitHub, GitHubError, MintError, Minted, Minter, Request, TOKEN_INFO,
    register,
};
use jarvis_kernel::serve::Server;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Calls {
    adds: Vec<String>,
    deletes: Vec<i64>,
    token: String,
}

#[derive(Default, Clone)]
struct FakeGitHub(Arc<Mutex<Calls>>);

impl GitHub for FakeGitHub {
    fn add_deploy_key(
        &self,
        token: &str,
        repo: &str,
        title: &str,
        public_key: &str,
    ) -> anyhow::Result<DeployKey> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.token = token.into();
        g.adds.push(format!("{repo} {title} {public_key}"));
        Ok(DeployKey {
            id: 41,
            title: title.into(),
            key: public_key.into(),
        })
    }
    fn delete_deploy_key(&self, token: &str, repo: &str, id: i64) -> anyhow::Result<()> {
        if repo == "DE0CH/refused" {
            return Err(GitHubError {
                status: 403,
                msg: "GitHub DELETE: HTTP 403 Resource not accessible".into(),
            }
            .into());
        }
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.token = token.into();
        g.deletes.push(id);
        Ok(())
    }
}

/// the minter over HTTP, as secrets reaches it: one add, one delete by id, each phone-approved; GitHub's refusal comes
/// back as a 502 naming GitHub's status; the answer is signed by the roster's minter
#[test]
fn mint_over_http() {
    let w = World::new();
    let g = FakeGitHub::default();
    let s = Server::new(w.component("minter"), w.trust.clone());
    register(&s, Arc::new(Minter::new(Box::new(g.clone()))));
    let h = s.handler();
    let srv = TestServer::handler(move |wr, r| h(wr, r));
    let cl = Client::new(&srv.url);
    let req = |begin: Value| {
        let b = w.c["secrets"]
            .signer
            .sign_json(&begin)
            .unwrap_or_else(|e| panic!("{e}"));
        let info = format!(
            "{TOKEN_INFO}{}",
            begin["pending"].as_str().unwrap_or_default()
        );
        let token = jarvis_sig::seal_to(&w.c["minter"].identity.agreement_key, b"gh-token", &info)
            .unwrap_or_else(|e| panic!("{e}"));
        Request {
            phone_sig: w.phone.sign(b.payload.as_bytes()),
            begin: b,
            keys: w.keys_doc.clone(),
            token,
        }
    };
    let d = cl
        .mint(&req(json!({"kind": "deploy-key-begin", "pending": "p1", "action": "add", "repo": "DE0CH/x", "title": "jarvis4 github-x", "publicKey": "ssh-ed25519 AAAA"})))
        .unwrap_or_else(|e| panic!("{e:#}"));
    let m: Minted = d
        .open(&w.c["minter"].identity.signing_key)
        .unwrap_or_else(|e| panic!("{e}"));
    {
        let c = g.0.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            m.key_id == 41 && m.pending == "p1" && c.token == "gh-token" && c.adds.len() == 1,
            "{m:?}"
        );
    }
    cl.mint(&req(json!({"kind": "deploy-key-begin", "pending": "p2", "action": "remove", "repo": "DE0CH/x", "keyId": 41})))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        g.0.lock().unwrap_or_else(|e| e.into_inner()).deletes,
        vec![41]
    );
    for (name, b) in [
        (
            "a remove without an id",
            json!({"kind": "deploy-key-begin", "pending": "p3", "action": "remove", "repo": "DE0CH/x"}),
        ),
        (
            "a path in the repo",
            json!({"kind": "deploy-key-begin", "pending": "p4", "action": "add", "repo": "DE0CH/../x", "title": "t", "publicKey": "k"}),
        ),
        (
            "another kind",
            json!({"kind": "unlock-begin", "pending": "p5", "action": "add", "repo": "DE0CH/x", "title": "t", "publicKey": "k"}),
        ),
    ] {
        assert!(cl.mint(&req(b)).is_err(), "{name}: minted");
    }
    let e = cl
        .mint(&req(json!({"kind": "deploy-key-begin", "pending": "p6", "action": "remove", "repo": "DE0CH/refused", "keyId": 9})))
        .err()
        .unwrap_or_else(|| panic!("GitHub's refusal minted"));
    let me = e
        .downcast_ref::<MintError>()
        .unwrap_or_else(|| panic!("{e:#}"));
    assert!(
        me.status == 502 && me.msg.contains("github: HTTP 403"),
        "GitHub's refusal: {me}"
    );
}
