//! The AWS runner's parts, and what the Go spawner made byte for byte (tests/vectors/spawner-aws.json, which it wrote
//! before the kernel's cut, 2026-11-26): an EC2 machine's Ignition, a SigV4 signature, the sizes' instance types

use super::super::aws::{
    AwsCredentials, WireGuard, ignition, instance_type, sign_v4, user_data_image,
};
use super::super::fly::size_guest;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    image: String,
    env: BTreeMap<String, String>,
    wireguard: WireGuard,
    user_data: String,
    body: String,
    authorization: String,
    instances: BTreeMap<String, String>,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../../tests/vectors/spawner-aws.json"))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// the user-data Go made for the same machine, byte for byte, and Inspect reads its image back
#[test]
fn ignition_as_go_made_it() {
    let v = vectors();
    let ud = ignition(&v.image, &v.env, &v.wireguard).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(String::from_utf8_lossy(&ud), v.user_data);
    use base64::Engine as _;
    assert_eq!(
        user_data_image(&base64::engine::general_purpose::STANDARD.encode(&ud)),
        v.image
    );
}

/// The user-data runs the image it names; the logs (docs/PLAN-aws.md "Logs"): the host's journal read only in the
/// container, and the container's end on the console with 50 s before the power-off when it didn't end cleanly
#[test]
fn ignition_names_its_image() {
    let v = vectors();
    let env = BTreeMap::from([
        (
            "JARVIS2_URL".to_string(),
            "http://10.99.0.1:8081".to_string(),
        ),
        ("JARVIS2_SOURCE".to_string(), "source-x".to_string()),
    ]);
    let ud = ignition(&v.image, &env, &v.wireguard).unwrap_or_else(|e| panic!("{e:#}"));
    let s = String::from_utf8_lossy(&ud).into_owned();
    assert!(
        serde_json::from_str::<serde_json::Value>(&s).is_ok(),
        "not JSON"
    );
    for want in [
        "wg0",
        "ListenPort=51820",
        "AllowedIPs=10.99.0.1%2F32",
        "JARVIS2_RUNNER=aws",
        "docker run --name session",
    ] {
        assert!(s.contains(want), "no {want} in {s}");
    }
    for want in [
        "-v /var/log/journal:/run/jarvis-host/journal:ro ${IMAGE}",
        r#"echo "JARVIS4-SESSION-END result=$SERVICE_RESULT code=$EXIT_CODE status=$EXIT_STATUS" > /dev/ttyS0; [ "$SERVICE_RESULT" = success ] || sleep 50"#,
    ] {
        let j = jarvis_sig::go_json(&want).unwrap_or_default();
        assert!(s.contains(j.trim_matches('"')), "no {want} in {s}");
    }
    assert!(
        ignition(&format!("{} ; rm", v.image), &BTreeMap::new(), &v.wireguard).is_err(),
        "an image with a space"
    );
    let nl = BTreeMap::from([("A".to_string(), "x\ny".to_string())]);
    assert!(
        ignition(&v.image, &nl, &v.wireguard).is_err(),
        "a value with a newline"
    );
    let mut bad = v.wireguard.clone();
    bad.address = "192.168.1.1".into();
    assert!(
        ignition(&v.image, &BTreeMap::new(), &bad).is_err(),
        "an address outside 10.90/15"
    );
}

#[test]
fn instance_types() {
    for (size, want) in vectors().instances {
        let (_, _, mem) = size_guest(&size);
        assert_eq!(instance_type(mem), want, "{size}");
    }
}

/// the signature Go's sign made for the same request
#[test]
fn sign_as_go_signed() {
    let v = vectors();
    let h = sign_v4(
        "POST",
        "https://ec2.ap-southeast-1.amazonaws.com/",
        "application/x-www-form-urlencoded; charset=utf-8",
        "",
        v.body.as_bytes(),
        &AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        },
        "ap-southeast-1",
        "ec2",
        time::OffsetDateTime::from_unix_timestamp(1440938160).unwrap_or_else(|e| panic!("{e}")), // 2015-08-30 12:36:00 UTC
    );
    let a = h
        .iter()
        .find(|(k, _)| k == "Authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    assert_eq!(a, v.authorization);
}
