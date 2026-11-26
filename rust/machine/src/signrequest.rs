//! `jarvis-machine sign-request METHOD PATH < body`: this machine's signature over a request for a service outside
//! Jarvis 4, printed as the router's three headers (JSON: X-Machine, X-Time, X-Sig), the same signature every /m call
//! carries. The service asks the router whose it is (rust/router/src/machinesig.rs), which never checks one over a path under
//! /m: a signature made here can't stand in for a router call. Today's user: aviary-gateway's boot.

use crate::client::Client;
use crate::crypto::sha256_hex;
use crate::{gojson, re};
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::io::Read;

re!(SIGN_METHOD_RE = r"^[A-Z]{3,7}$");

pub fn sign_request_cmd(args: &[String]) -> Result<()> {
    if args.len() != 2
        || !SIGN_METHOD_RE.is_match(&args[0])
        || !args[1].starts_with('/')
        || args[1] == "/m"
        || args[1].starts_with("/m/")
    {
        bail!("usage: jarvis-machine sign-request METHOD PATH < body (a path outside /m)");
    }
    let mut body = vec![];
    std::io::stdin().take(64 << 20).read_to_end(&mut body)?;
    let c = Client::new()?;
    let h: BTreeMap<String, String> = c
        .signed(&args[0], &args[1], &sha256_hex(&body))?
        .into_iter()
        .collect();
    println!("{}", gojson::marshal(&h));
    Ok(())
}
