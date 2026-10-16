//! Key rotation (docs/dev/spec/protocol.md §4.10) on a real node daemon
//! against the conformance fake center, in process: the owner rotates the
//! node's key with `center rotate-key`, the center takes it, refuses it or
//! does not answer; the owner ends the grace of the old key; and the center
//! tells the node of its own new key.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use clap::Parser;
use nerve_conformance::fake_center::{self, FakeCenter, Paired};
use nerve_conformance::wire::{Conn, Recv};
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_proto::Message;
use nerve_proto::msg::method;
use nerve_transport::keys::{NodeKey, verify_node_signature};
use nerve_transport::tls::{ServerIdentity, b64url, decode_pin};
use serde_json::{Map, Value, json};
use tokio::net::TcpStream;

const WAIT: Duration = Duration::from_secs(15);
const ROTATE: &[&str] = &["rotate"];

fn options(root: &Path) -> NodeOptions {
    let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
    o.home = root.join("home");
    std::fs::create_dir_all(&o.home).unwrap();
    o.full_rights = Some(false);
    o
}

/// Pairs with `center` as `lab`, with `pin` stored as the center's pin
/// (the fake center speaks plain HTTP, so the link does not check it), and
/// starts the daemon.
async fn node(root: &Path, center: &FakeCenter, pin: Option<String>) -> Daemon {
    node_with(root, center, |e| e.pin = pin.clone()).await
}

/// [`node`], with the pairing's entry changed by `f` before the start.
async fn node_with(
    root: &Path,
    center: &FakeCenter,
    f: impl Fn(&mut nerve_policy::CenterEntry),
) -> Daemon {
    let o = options(root);
    nerve_node::pair::pair(&o.paths, &center.link(), Some("lab"))
        .await
        .expect("pair");
    nerve_node::cli::edit(&o.paths, |c| {
        f(&mut c.centers[0]);
        Ok(())
    })
    .await
    .expect("the owner's edit");
    Daemon::start(o).await.expect("start")
}

/// Accepts the node's next link and runs the handshake against `public_key`,
/// with `features` in the welcome.
async fn link(
    center: &mut FakeCenter,
    public_key: &str,
    features: Option<&[&str]>,
) -> Conn<TcpStream> {
    let paired = center.paired().expect("paired");
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    // The node id stays the one of the pairing, whatever key signs.
    assert_eq!(inc.node_header, paired.node_id);
    let hello = fake_center::handshake_with(
        &mut inc.conn,
        &center.center_id,
        &paired.node_id,
        public_key,
        features,
    )
    .await
    .expect("handshake");
    assert_eq!(hello.features, ["rotate"]);
    inc.conn
}

/// The next notification `want` from the node; anything else is passed over.
async fn next(conn: &mut Conn<TcpStream>, want: &str) -> Option<Map<String, Value>> {
    let until = tokio::time::Instant::now() + WAIT;
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            Recv::Msg(Message::Notification { method: m, params }) if m == want => {
                return Some(params);
            }
            Recv::Msg(_) => continue,
            _ => return None,
        }
    }
}

/// Runs one `nerve-node` command line as the owner would.
async fn cli(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
    let mut argv: Vec<String> = vec![
        "nerve-node".into(),
        "--config-dir".into(),
        paths.config_dir.display().to_string(),
        "--state-dir".into(),
        paths.state_dir.display().to_string(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    let cli = nerve_node::cli::Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    nerve_node::cli::execute(cli, &mut out).await?;
    Ok(String::from_utf8(out).unwrap())
}

/// `center rotate-key` in the background, so the test can play the center.
fn rotate(paths: &NodePaths, args: &[&str]) -> tokio::task::JoinHandle<Result<String, String>> {
    let paths = paths.clone();
    let mut all = vec!["center", "rotate-key"];
    all.extend_from_slice(args);
    let all: Vec<String> = all.iter().map(|s| s.to_string()).collect();
    // The CLI's future is not Send: it runs on a thread of its own, as the
    // owner's command runs in a process of its own.
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = all.iter().map(String::as_str).collect();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(cli(&paths, &args))
    })
}

fn key(paths: &NodePaths) -> NodeKey {
    NodeKey::from_text(&std::fs::read_to_string(paths.key_file("lab")).unwrap()).unwrap()
}

fn audit(paths: &NodePaths) -> String {
    std::fs::read_to_string(paths.audit_log()).unwrap_or_default()
}

fn paired(center: &FakeCenter) -> Paired {
    center.paired().expect("paired")
}

/// Checks a `key.rotate` as a center does: signed by `old` and by the new
/// key itself. Returns the new key.
fn check_rotate(p: &Map<String, Value>, center_id: &str, old: &str) -> String {
    let new = p["public_key"].as_str().unwrap().to_string();
    let raw = nerve_proto::msg::unhex(&new).unwrap();
    let message = nerve_proto::rotate_node_message(center_id, &raw);
    assert!(verify_node_signature(
        old,
        &message,
        p["sig"].as_str().unwrap()
    ));
    assert!(verify_node_signature(
        &new,
        &message,
        p["proof"].as_str().unwrap()
    ));
    new
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_takes_its_new_key_once_the_center_took_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    assert_ne!(new, old);
    // The new key is kept aside until the center answers.
    assert!(paths.next_key_file("lab").exists());
    assert_eq!(key(&paths).public_hex(), old);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    let out = run.await.unwrap().expect("the rotation");
    assert!(out.contains(&new), "{out}");
    assert!(out.contains("7 more days"), "{out}");
    assert_eq!(key(&paths).public_hex(), new);
    assert!(!paths.next_key_file("lab").exists());
    // The config names the new key, which a backup checks the key by; the
    // node id stays.
    let (cfg, _) = nerve_node::cli::read_config(&paths).await.unwrap();
    assert_eq!(cfg.centers[0].public_key.as_deref(), Some(new.as_str()));
    assert_eq!(cfg.centers[0].node_id, paired(&center).node_id);
    let log = audit(&paths);
    assert!(log.contains("\"event\":\"node-key\""), "{log}");
    // No private key in the audit log, nor in the answer.
    assert!(!log.contains(key(&paths).to_text().trim()));
    assert!(!out.contains(key(&paths).to_text().trim()));

    // The next link is signed with the new key, under the same node id.
    conn.bye("shutdown").await;
    let mut conn = link(&mut center, &new, Some(ROTATE)).await;

    // The owner ends the grace of the old key; the current key signs that.
    let run = rotate(&paths, &["--end-grace"]);
    let p = next(&mut conn, method::KEY_RETIRE)
        .await
        .expect("key.retire");
    assert_eq!(p["public_key"], new.as_str());
    let message = nerve_proto::retire_node_message(
        &center.center_id,
        &nerve_proto::msg::unhex(&new).unwrap(),
    );
    assert!(verify_node_signature(
        &new,
        &message,
        p["sig"].as_str().unwrap()
    ));
    conn.notify(method::KEY_RETIRED, json!({})).await.unwrap();
    let out = run.await.unwrap().expect("the end of the grace");
    assert!(out.contains("no longer takes"), "{out}");
    assert!(audit(&paths).contains("node-key-grace-ended"));
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_rotation_keeps_the_old_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    conn.notify(
        method::KEY_ROTATED,
        json!({"public_key": new, "error": "another node holds this key"}),
    )
    .await
    .unwrap();
    let e = run.await.unwrap().expect_err("refused");
    assert!(e.contains("another node holds this key"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    assert!(!paths.next_key_file("lab").exists());
    assert!(audit(&paths).contains("node-key-refused"));
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_center_older_than_rotation_keeps_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    // A welcome without features: a center older than rotation.
    let _conn = link(&mut center, &old, None).await;
    let e = rotate(&paths, &[])
        .await
        .unwrap()
        .expect_err("not without the feature");
    assert!(e.contains("does not speak key rotation"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    assert!(!paths.next_key_file("lab").exists());
    drop(daemon);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_rotation_is_sent_again_on_the_next_link() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    // The link drops before the answer: the center may have taken the key.
    drop(conn);
    let e = run.await.unwrap().expect_err("no answer");
    assert!(e.contains("did not answer"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    assert!(paths.next_key_file("lab").exists());
    assert!(audit(&paths).contains("node-key-unanswered"));

    // The next link is still signed with the old key, and sends the same new
    // key again by itself.
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("sent again");
    assert_eq!(check_rotate(&p, &center.center_id, &old), new);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    for _ in 0..200 {
        if key(&paths).public_hex() == new {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(key(&paths).public_hex(), new);
    assert!(!paths.next_key_file("lab").exists());
    drop(daemon);
}

/// A `key.rotated` that comes after the owner's command stopped waiting
/// still settles the rotation, on the link it came over.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_answer_settles_the_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    let e = run.await.unwrap().expect_err("no answer in time");
    assert!(e.contains("did not answer"), "{e}");
    assert_eq!(key(&paths).public_hex(), old);
    conn.notify(method::KEY_ROTATED, json!({"public_key": new}))
        .await
        .unwrap();
    for _ in 0..200 {
        if key(&paths).public_hex() == new {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(key(&paths).public_hex(), new);
    assert!(!paths.next_key_file("lab").exists());
    assert!(audit(&paths).contains("\"event\":\"node-key\""));
    drop(daemon);
}

/// A center that took the new key but whose answer never came, and whose
/// grace for the old key has ended, refuses the old key's hello: the node
/// tries the new key next, and once that links the rotation is settled.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_hello_is_tried_with_the_new_key_kept_aside() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let daemon = node(dir.path(), &center, None).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;

    let run = rotate(&paths, &[]);
    let p = next(&mut conn, method::KEY_ROTATE)
        .await
        .expect("key.rotate");
    let new = check_rotate(&p, &center.center_id, &old);
    drop(conn);
    run.await.unwrap().expect_err("no answer");

    // The center holds only the new key now: the old key's hello is refused.
    let paired = paired(&center);
    let mut inc = center.next_link(WAIT).await.expect("the node dials");
    let refused = fake_center::handshake_with(
        &mut inc.conn,
        &center.center_id,
        &paired.node_id,
        &new,
        Some(ROTATE),
    )
    .await;
    assert!(refused.is_err(), "signed with the old key");
    drop(inc);
    // The next hello is signed with the new key, under the same node id.
    let _conn = link(&mut center, &new, Some(ROTATE)).await;
    for _ in 0..200 {
        if key(&paths).public_hex() == new {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(key(&paths).public_hex(), new);
    assert!(!paths.next_key_file("lab").exists());
    drop(daemon);
}

/// An old pin whose time is over goes from node.toml.
#[tokio::test(flavor = "multi_thread")]
async fn an_old_pin_whose_time_is_over_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (a, b) = (
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
    );
    let daemon = node_with(dir.path(), &center, |e| {
        e.pin = Some(b.pin());
        e.old_pin = Some(nerve_policy::OldPin {
            pin: a.pin(),
            until_ms: 1,
        });
    })
    .await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let _conn = link(&mut center, &old, Some(ROTATE)).await;
    let (cfg, _) = nerve_node::cli::read_config(&paths).await.unwrap();
    assert_eq!(cfg.centers[0].old_pin, None);
    assert_eq!(cfg.centers[0].pin, Some(b.pin()));
    drop(daemon);
}

/// A `center.rotate` from `old` to `new`, signed by `signer`.
fn center_rotate(
    center_id: &str,
    old: &ServerIdentity,
    new: &ServerIdentity,
    signer: &ServerIdentity,
    grace_ms: u64,
) -> Value {
    let new_pin = decode_pin(&new.pin()).unwrap();
    let sig = signer
        .sign(&nerve_proto::rotate_center_message(center_id, &new_pin))
        .unwrap();
    json!({
        "old_spki": b64url(&old.spki()),
        "new_spki": b64url(&new.spki()),
        "sig": b64url(&sig),
        "grace_ms": grace_ms,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_follows_a_center_key_its_old_key_signed() {
    let dir = tempfile::tempdir().unwrap();
    let mut center = FakeCenter::start(false).await.unwrap();
    let (a, b, other) = (
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
        ServerIdentity::generate(&[]).unwrap(),
    );
    let daemon = node(dir.path(), &center, Some(a.pin())).await;
    let paths = daemon.paths().clone();
    let old = paired(&center).request.public_key;
    let mut conn = link(&mut center, &old, Some(ROTATE)).await;
    let pins = || {
        let (cfg, _) = futures_block(nerve_node::cli::read_config(&paths)).unwrap();
        let c = cfg.centers[0].clone();
        (c.pin, c.old_pin)
    };

    // Signed by another key than the pinned one: the pin stays.
    let id = center.center_id.clone();
    conn.notify(
        method::CENTER_ROTATE,
        center_rotate(&id, &a, &b, &other, 1000),
    )
    .await
    .unwrap();
    for _ in 0..40 {
        if audit(&paths).contains("center-key-refused") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(audit(&paths).contains("center-key-refused"));
    assert_eq!(pins(), (Some(a.pin()), None));

    // Signed by the pinned key: the new pin is taken, the old one for the
    // grace the center names, at most 7 days.
    let week = nerve_proto::ROTATE_GRACE_MS;
    let before = nerve_proto::msg::now_ms();
    conn.notify(
        method::CENTER_ROTATE,
        center_rotate(&id, &a, &b, &a, 10 * week),
    )
    .await
    .unwrap();
    let mut got = pins();
    for _ in 0..200 {
        if got.0 == Some(b.pin()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        got = pins();
    }
    let (pin, old_pin) = got;
    assert_eq!(pin, Some(b.pin()));
    let old_pin = old_pin.expect("the old pin is kept");
    assert_eq!(old_pin.pin, a.pin());
    assert!(
        old_pin.until_ms >= before + week && old_pin.until_ms <= nerve_proto::msg::now_ms() + week
    );
    assert!(audit(&paths).contains("\"event\":\"center-key\""));

    // Told again with no grace left (the center serves the new key): the
    // old pin goes.
    conn.notify(method::CENTER_ROTATE, center_rotate(&id, &a, &b, &a, 0))
        .await
        .unwrap();
    for _ in 0..200 {
        if pins().1.is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(pins(), (Some(b.pin()), None));
    assert!(audit(&paths).contains("center-key-grace-ended"));
    drop(daemon);
}

/// Runs `f` to its end from inside the test's runtime.
fn futures_block<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}
