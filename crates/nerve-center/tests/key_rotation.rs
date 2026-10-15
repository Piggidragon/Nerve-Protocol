//! Key rotation (docs/dev/spec/protocol.md §4.9) at the center, against a
//! fake node in the same process: a node's key, taken only when the key it
//! replaces signed it, the old key's grace and its end; and the center's own
//! key, told to the nodes signed by the old one and served at the end of the
//! grace.

use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use nerve_center::config::Args;
use nerve_center::server::{self, Running};
use nerve_proto::link::{CenterUrl, PairLink};
use nerve_proto::msg::{self, method};
use nerve_proto::rpc::Message;
use nerve_transport::keys::NodeKey;
use nerve_transport::net::BoxIo;
use nerve_transport::tls::{decode_pin, unb64url, verify_spki_signature};
use nerve_transport::ws::{self, WsMessage};
use serde_json::{Value, json};
use tokio_tungstenite::WebSocketStream;

const MAX: usize = 4 * 1024 * 1024;
const WEEK: u64 = nerve_proto::ROTATE_GRACE_MS;

/// A center in `dir`: plain HTTP for nodes on loopback, or TLS with its key.
async fn center(dir: &std::path::Path, tls: bool) -> Running {
    nerve_transport::init_crypto();
    let mut argv = vec![
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--name",
        "test-center",
        "--listen",
        "127.0.0.1:0",
        "--ui",
        "off",
        "--mcp",
        "none",
    ];
    if !tls {
        argv.push("--plain-loopback");
    }
    let args = Args::try_parse_from(argv).unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await.unwrap()
}

fn url(r: &Running, tls: bool) -> CenterUrl {
    let scheme = if tls { "https" } else { "http" };
    CenterUrl::parse(&format!("{scheme}://127.0.0.1:{}", r.nodes.port())).unwrap()
}

/// Pairs `key` as `name` over plain HTTP; the node id.
async fn pair(r: &Running, key: &NodeKey, name: &str) -> String {
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    let mut io = tokio::net::TcpStream::connect(r.nodes).await.unwrap();
    let body = json!({
        "code": link.code, "name": name, "platform": "linux", "arch": "x86_64",
        "public_key": key.public_hex(),
    });
    let resp = nerve_transport::http::post_json(
        &mut io,
        "127.0.0.1",
        nerve_proto::PAIR_PATH,
        &body,
        64 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    v["node_id"].as_str().unwrap().to_string()
}

/// Pairs `key` with a TLS center, as a node does over the pinned link.
async fn pair_tls(r: &Running, key: &NodeKey, name: &str) -> String {
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    let mut io = nerve_transport::net::open(&url(r, true), link.pin.as_deref(), None)
        .await
        .unwrap();
    let body = json!({
        "code": link.code, "name": name, "platform": "linux", "arch": "x86_64",
        "public_key": key.public_hex(),
    });
    let resp = nerve_transport::http::post_json(
        &mut io,
        "127.0.0.1",
        nerve_proto::PAIR_PATH,
        &body,
        64 * 1024,
    )
    .await
    .unwrap();
    assert_eq!(resp.status, 200);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    v["node_id"].as_str().unwrap().to_string()
}

async fn text(ws: &mut WebSocketStream<BoxIo>) -> Option<Message> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .ok()??
        {
            Ok(WsMessage::Text(t)) => return Message::decode(&t).ok(),
            Ok(WsMessage::Close(_)) | Err(_) => return None,
            Ok(_) => continue,
        }
    }
}

async fn send(ws: &mut WebSocketStream<BoxIo>, m: Message) {
    ws.send(WsMessage::text(m.encode())).await.unwrap();
}

/// Connects as `node_id`, signing with `key`, with `features` in the hello,
/// and runs the handshake up to `welcome` (or what came instead).
async fn handshake(
    url: &CenterUrl,
    pins: &[&str],
    node_id: &str,
    key: &NodeKey,
    features: &[&str],
) -> Result<(WebSocketStream<BoxIo>, Message), String> {
    let mut ws = ws::connect_pins(url, pins, None, node_id, MAX)
        .await
        .map_err(|e| e.to_string())?;
    let Some(Message::Notification { method: m, params }) = text(&mut ws).await else {
        panic!("no challenge")
    };
    assert_eq!(m, method::CHALLENGE);
    let nonce = msg::unhex(params["nonce"].as_str().unwrap()).unwrap();
    let center_id = params["center_id"].as_str().unwrap().to_string();
    let mut hello = json!({
        "node_id": node_id,
        "auth": {"sig": key.sign_connect(&center_id, &nonce)},
        "versions": ["0"],
        "software": {"name": "fake-node", "version": "x.y.z"},
        "rev": 1,
    });
    if !features.is_empty() {
        hello["features"] = json!(features);
    }
    send(&mut ws, Message::notification(method::HELLO, hello)).await;
    let next = text(&mut ws).await.expect("a reply to hello");
    Ok((ws, next))
}

fn method_of(m: &Message) -> &str {
    match m {
        Message::Notification { method, .. } | Message::Request { method, .. } => method,
        _ => "",
    }
}

fn params_of(m: Message) -> Value {
    match m {
        Message::Notification { params, .. } | Message::Request { params, .. } => {
            Value::Object(params)
        }
        _ => Value::Null,
    }
}

/// The next notification `want`, answering the center's requests on the way
/// (an empty descriptor); `None` when the link ends or nothing comes.
async fn next(ws: &mut WebSocketStream<BoxIo>, want: &str) -> Option<Value> {
    loop {
        let m = text(ws).await?;
        match m {
            Message::Notification { method: m, params } if m == want => {
                return Some(Value::Object(params));
            }
            Message::Notification { method: m, params } if m == method::BYE => {
                if want == method::BYE {
                    return Some(Value::Object(params));
                }
                return None;
            }
            Message::Request { id, .. } => {
                send(
                    ws,
                    Message::error(Some(id), nerve_proto::RpcError::internal("no")),
                )
                .await;
            }
            _ => {}
        }
    }
}

fn rotate_params(center_id: &str, old: &NodeKey, new: &NodeKey) -> Value {
    json!({
        "public_key": new.public_hex(),
        "sig": old.sign_rotate(center_id, &new.public_key()),
        "proof": new.sign_rotate(center_id, &new.public_key()),
    })
}

async fn welcomed(r: &Running, node_id: &str, key: &NodeKey) -> WebSocketStream<BoxIo> {
    let (ws, w) = handshake(&url(r, false), &[], node_id, key, &["rotate"])
        .await
        .unwrap();
    assert_eq!(method_of(&w), method::WELCOME, "{w:?}");
    ws
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..400 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out")
}

#[tokio::test]
async fn features_go_only_to_a_node_that_names_them() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let key = NodeKey::generate().unwrap();
    let id = pair(&r, &key, "box-1").await;
    let (ws, w) = handshake(&url(&r, false), &[], &id, &key, &["rotate", "x-later"])
        .await
        .unwrap();
    assert_eq!(params_of(w)["features"], json!(["rotate"]));
    drop(ws);
    // An older node names none and gets none: it refuses a field it does not
    // know in the welcome.
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_none()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut ws, w) = handshake(&url(&r, false), &[], &id, &key, &[])
        .await
        .unwrap();
    let w = params_of(w);
    assert_eq!(w["version"], "0");
    assert!(w.get("features").is_none(), "{w}");
    // Nor is its key rotated by a message it never sends.
    let new = NodeKey::generate().unwrap();
    send(
        &mut ws,
        Message::notification(
            method::KEY_ROTATE,
            rotate_params(&r.center.id(), &key, &new),
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(r.center.public_key(&id), Some(key.public_hex()));
    r.stop().await;
}

#[tokio::test]
async fn a_node_key_signed_by_the_key_it_replaces_is_taken_and_the_old_one_has_a_grace() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;

    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert_eq!(a, json!({"public_key": new.public_hex()}));
    assert_eq!(r.center.public_key(&id), Some(new.public_hex()));
    let until = r
        .center
        .read(|s| s.nodes[&id].old_key.clone())
        .expect("the old key")
        .until_ms;
    let now = msg::now_ms();
    assert!(
        until > now + WEEK - 60_000 && until <= now + WEEK,
        "{until}"
    );
    // Sent again (no answer reached the node): the same answer, nothing more.
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");
    assert!(a.get("error").is_none(), "{a}");
    assert_eq!(
        r.center
            .read(|s| s.nodes[&id].old_key.clone())
            .unwrap()
            .public_key,
        old.public_hex()
    );
    // The node id stays; the state file keeps both keys.
    let state: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("state.json")).unwrap()).unwrap();
    assert_eq!(state["nodes"][&id]["public_key"], new.public_hex());
    assert_eq!(
        state["nodes"][&id]["old_key"]["public_key"],
        old.public_hex()
    );
    drop(ws);

    // Both keys open a link during the grace, under the same node id.
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_none()).await;
    drop(welcomed(&r, &id, &new).await);
    wait_for(|| c.link(&id).is_none()).await;
    let ws = welcomed(&r, &id, &old).await;
    drop(ws);
    wait_for(|| c.link(&id).is_none()).await;

    // Once the grace has ended, the old key is refused.
    r.center.update(|s| {
        s.nodes
            .get_mut(&id)
            .unwrap()
            .old_key
            .as_mut()
            .unwrap()
            .until_ms = 1;
    });
    let (_ws, reply) = handshake(&url(&r, false), &[], &id, &old, &["rotate"])
        .await
        .unwrap();
    assert_eq!(method_of(&reply), method::BYE);
    assert_eq!(params_of(reply)["reason"], "protocol_error");
    // The sweep drops it from the state.
    r.center.sweep().await;
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    r.stop().await;
}

#[tokio::test]
async fn a_rotation_the_current_key_did_not_sign_is_refused_and_the_key_stays() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let key = NodeKey::generate().unwrap();
    let other = NodeKey::generate().unwrap();
    let id = pair(&r, &key, "box-1").await;
    let _other_id = pair(&r, &other, "box-2").await;
    let mut ws = welcomed(&r, &id, &key).await;
    let new = NodeKey::generate().unwrap();
    let stranger = NodeKey::generate().unwrap();

    let bad = [
        // Signed by a key that is not the node's.
        (rotate_params(&cid, &stranger, &new), "current key"),
        // The new key did not sign it.
        (
            json!({"public_key": new.public_hex(),
                   "sig": key.sign_rotate(&cid, &new.public_key()),
                   "proof": stranger.sign_rotate(&cid, &new.public_key())}),
            "new key did not sign",
        ),
        // Signed for another center.
        (
            rotate_params("another-center", &key, &new),
            "new key did not sign",
        ),
        // Another node's key.
        (rotate_params(&cid, &key, &other), "another node"),
        (
            json!({"public_key": "zz", "sig": "", "proof": ""}),
            "64 lowercase hex",
        ),
    ];
    for (p, why) in bad {
        send(&mut ws, Message::notification(method::KEY_ROTATE, p)).await;
        let a = next(&mut ws, method::KEY_ROTATED)
            .await
            .expect("key.rotated");
        let e = a["error"].as_str().unwrap_or_default();
        assert!(e.contains(why), "{why}: {a}");
        assert_eq!(r.center.public_key(&id), Some(key.public_hex()));
        assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    }
    // A key in the grace of another node cannot be paired either.
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &key, &new)),
    )
    .await;
    assert!(
        next(&mut ws, method::KEY_ROTATED)
            .await
            .unwrap()
            .get("error")
            .is_none()
    );
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    let mut io = tokio::net::TcpStream::connect(r.nodes).await.unwrap();
    let body = json!({"code": link.code, "name": "box-3", "platform": "linux", "arch": "x86_64",
                      "public_key": key.public_hex()});
    let resp =
        nerve_transport::http::post_json(&mut io, "127.0.0.1", nerve_proto::PAIR_PATH, &body, 4096)
            .await
            .unwrap();
    assert_eq!(resp.status, 409);
    r.stop().await;
}

#[tokio::test]
async fn the_node_ends_the_grace_and_a_link_of_the_old_key_ends_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), false).await;
    let cid = r.center.id();
    let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
    let id = pair(&r, &old, "box-1").await;
    let mut ws = welcomed(&r, &id, &old).await;
    send(
        &mut ws,
        Message::notification(method::KEY_ROTATE, rotate_params(&cid, &old, &new)),
    )
    .await;
    next(&mut ws, method::KEY_ROTATED)
        .await
        .expect("key.rotated");

    // Only the current key may end the grace.
    let retire = |k: &NodeKey| json!({"public_key": k.public_hex(), "sig": k.sign_retire(&cid)});
    send(
        &mut ws,
        Message::notification(method::KEY_RETIRE, retire(&old)),
    )
    .await;
    let a = next(&mut ws, method::KEY_RETIRED)
        .await
        .expect("key.retired");
    assert!(a["error"].as_str().is_some(), "{a}");
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_some()));

    send(
        &mut ws,
        Message::notification(method::KEY_RETIRE, retire(&new)),
    )
    .await;
    let a = next(&mut ws, method::KEY_RETIRED)
        .await
        .expect("key.retired");
    assert_eq!(a, json!({}));
    assert!(r.center.read(|s| s.nodes[&id].old_key.is_none()));
    // This link was opened with the old key, which is refused now.
    let bye = next(&mut ws, method::BYE).await.expect("bye");
    assert_eq!(bye["reason"], "replaced");
    // The node closes on the bye, and dials again with its key.
    drop(ws);
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_none()).await;
    let (_ws, reply) = handshake(&url(&r, false), &[], &id, &old, &["rotate"])
        .await
        .unwrap();
    assert_eq!(method_of(&reply), method::BYE);
    drop(welcomed(&r, &id, &new).await);
    r.stop().await;
}

/// Checks a `center.rotate` as a node does: the old key signed the new pin.
fn check_center_rotate(n: &Value, center_id: &str, old_pin: &str) -> String {
    let old = unb64url(n["old_spki"].as_str().unwrap()).unwrap();
    let new = unb64url(n["new_spki"].as_str().unwrap()).unwrap();
    let sig = unb64url(n["sig"].as_str().unwrap()).unwrap();
    assert_eq!(nerve_transport::tls::pin_of_spki(&old), old_pin);
    let new_pin = nerve_transport::tls::pin_of_spki(&new);
    let message = nerve_proto::rotate_center_message(center_id, &decode_pin(&new_pin).unwrap());
    assert!(verify_spki_signature(&old, &message, &sig));
    new_pin
}

#[tokio::test]
async fn the_center_rotates_its_key_tells_the_nodes_and_serves_it_after_the_grace() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), true).await;
    let cid = r.center.id();
    let old_pin = r.center.pin().expect("a TLS center has a pin");
    let key = NodeKey::generate().unwrap();
    let id = pair_tls(&r, &key, "box-1").await;
    let tls = url(&r, true);
    let (mut ws, w) = handshake(&tls, &[&old_pin], &id, &key, &["rotate"])
        .await
        .unwrap();
    assert_eq!(method_of(&w), method::WELCOME);
    let c = r.center.clone();
    wait_for(|| c.link(&id).is_some()).await;

    // The owner rotates: the new pin is in the answer; the linked node is
    // told, signed by the old key; the old key is still served.
    let out = r.center.rotate_key().await.unwrap();
    let new_pin = out["pin"].as_str().unwrap().to_string();
    assert_ne!(new_pin, old_pin);
    assert_eq!(out["old_pin"], old_pin.as_str());
    assert_eq!(out["told"], 1);
    let n = next(&mut ws, method::CENTER_ROTATE)
        .await
        .expect("center.rotate");
    assert_eq!(check_center_rotate(&n, &cid, &old_pin), new_pin);
    let grace = n["grace_ms"].as_u64().unwrap();
    assert!(grace > WEEK - 60_000 && grace <= WEEK, "{grace}");
    assert_eq!(r.center.pin().as_deref(), Some(old_pin.as_str()));
    assert!(dir.path().join("tls.next.pem").exists());
    // The new pin is not shown again.
    assert!(r.center.key_json().to_string().find(&new_pin).is_none());
    assert!(
        r.center
            .rotate_key()
            .await
            .unwrap_err()
            .contains("in its grace")
    );
    drop(ws);
    wait_for(|| c.link(&id).is_none()).await;

    // A node that links during the grace, with the old pin only, is told.
    let (mut ws, _) = handshake(&tls, &[&old_pin], &id, &key, &["rotate"])
        .await
        .unwrap();
    let n = next(&mut ws, method::CENTER_ROTATE)
        .await
        .expect("told on link");
    assert_eq!(check_center_rotate(&n, &cid, &old_pin), new_pin);
    // So is a node that only learns of it now; a node that does not speak
    // rotation is not.
    drop(ws);
    wait_for(|| c.link(&id).is_none()).await;

    // The grace ends: the new key is served, for every new connection.
    r.center
        .update(|s| s.key_rotation.as_mut().unwrap().until_ms = 1);
    r.center.sweep().await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    assert!(!dir.path().join("tls.next.pem").exists());
    assert!(
        handshake(&tls, &[&old_pin], &id, &key, &["rotate"])
            .await
            .is_err()
    );
    let (mut ws, w) = handshake(&tls, &[&new_pin], &id, &key, &["rotate"])
        .await
        .unwrap();
    assert_eq!(method_of(&w), method::WELCOME);
    // Nodes are still told, with no grace left, so they drop the old pin.
    let n = next(&mut ws, method::CENTER_ROTATE)
        .await
        .expect("told after");
    assert_eq!(n["grace_ms"], 0);
    // New pairing links carry the new pin.
    let link = PairLink::parse(r.center.new_pairing()["link"].as_str().unwrap()).unwrap();
    assert_eq!(link.pin.as_deref(), Some(new_pin.as_str()));
    drop(ws);
    r.stop().await;

    // A restart serves the new key from tls.pem.
    let r = center(dir.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(new_pin.as_str()));
    r.stop().await;
}

#[tokio::test]
async fn the_owner_ends_the_grace_of_the_center_key_early() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), true).await;
    let old_pin = r.center.pin().unwrap();
    assert!(
        r.center
            .finish_key_rotation("test")
            .await
            .unwrap_err()
            .contains("no rotation")
    );
    let key = NodeKey::generate().unwrap();
    let id = pair_tls(&r, &key, "box-1").await;
    let tls = url(&r, true);
    let (mut ws, _) = handshake(&tls, &[&old_pin], &id, &key, &["rotate"])
        .await
        .unwrap();
    let new_pin = r.center.rotate_key().await.unwrap()["pin"]
        .as_str()
        .unwrap()
        .to_string();
    let n = next(&mut ws, method::CENTER_ROTATE).await.unwrap();
    assert!(n["grace_ms"].as_u64().unwrap() > 0);
    let out = r
        .center
        .finish_key_rotation("the owner ended its grace")
        .await
        .unwrap();
    assert_eq!(out["pin"], new_pin.as_str());
    // The link up now goes on, and hears that the grace is over.
    let n = next(&mut ws, method::CENTER_ROTATE).await.unwrap();
    assert_eq!(n["grace_ms"], 0);
    assert!(
        handshake(&tls, &[&old_pin], &id, &key, &["rotate"])
            .await
            .is_err()
    );
    r.stop().await;
}

#[tokio::test]
async fn a_start_drops_a_new_key_the_state_does_not_know() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path(), true).await;
    let pin = r.center.pin().unwrap();
    r.stop().await;
    // A rotation cut short before the state file held it.
    let stray = nerve_transport::tls::ServerIdentity::generate(&[]).unwrap();
    std::fs::write(dir.path().join("tls.next.pem"), stray.to_pem()).unwrap();
    let r = center(dir.path(), true).await;
    assert_eq!(r.center.pin().as_deref(), Some(pin.as_str()));
    assert!(!dir.path().join("tls.next.pem").exists());
    assert!(r.center.read(|s| s.key_rotation.is_none()));
    r.stop().await;
}
