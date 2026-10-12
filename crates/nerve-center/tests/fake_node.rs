//! The center against a fake node in the same process: pairing, the link
//! handshake, describe, MCP tools/call through to `invoke`, an unknown node
//! (401) and the one-link rule.

use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use nerve_center::config::Args;
use nerve_center::mcp::Engine;
use nerve_center::server::{self, Running};
use nerve_proto::link::{CenterUrl, PairLink};
use nerve_proto::msg::{self, method};
use nerve_proto::rpc::Message;
use nerve_transport::keys::NodeKey;
use nerve_transport::net::BoxIo;
use nerve_transport::ws::{self, ConnectError, WsMessage};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;

const MAX: usize = 4 * 1024 * 1024;

async fn center(dir: &std::path::Path) -> Running {
    nerve_transport::init_crypto();
    let args = Args::try_parse_from([
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--name",
        "test-center",
        "--listen",
        "127.0.0.1:0",
        "--plain-loopback",
        "--ui",
        "127.0.0.1:0",
        "--mcp",
        "none",
    ])
    .unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await.unwrap()
}

fn url(r: &Running) -> CenterUrl {
    CenterUrl::parse(&format!("http://127.0.0.1:{}", r.nodes.port())).unwrap()
}

async fn pair(r: &Running, key: &NodeKey, name: &str) -> (u16, Value) {
    let p = r.center.new_pairing();
    let link = PairLink::parse(p["link"].as_str().unwrap()).unwrap();
    assert!(link.pin.is_none(), "plain loopback has no pin");
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
    (
        resp.status,
        serde_json::from_slice(&resp.body).unwrap_or(Value::Null),
    )
}

fn descriptor(key: &NodeKey, name: &str) -> Value {
    json!({
        "nerve": "0",
        "node": {"id": key.node_id(), "name": name, "platform": "linux", "arch": "x86_64",
                 "software": {"name": "fake-node", "version": "0.0.1"}},
        "rev": 1,
        "summary": "A fake node.",
        "capabilities": [
            {"id": "fs", "profile": "fs", "exposure": "on", "summary": "Files.",
             "actions": {"read": {"effect": "read", "summary": "Read a file.",
                                  "params": {"type": "object", "properties": {"path": {"type": "string"}},
                                             "required": ["path"]}}}},
            {"id": "exec", "profile": "exec", "exposure": "on", "summary": "Commands.",
             "actions": {"run": {"effect": "execute", "summary": "Run a command.",
                                 "params": {"type": "object", "properties": {"command": {"type": "string"}},
                                            "required": ["command"]}}}},
            {"id": "settings", "profile": "settings", "exposure": "on", "summary": "Settings.",
             "actions": {"set": {"effect": "write"}}}
        ]
    })
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

/// Connects and runs the handshake up to `welcome` (or what came instead).
async fn handshake(r: &Running, key: &NodeKey) -> (WebSocketStream<BoxIo>, Message) {
    let mut ws = ws::connect(&url(r), None, None, &key.node_id(), MAX)
        .await
        .unwrap();
    let Some(Message::Notification { method: m, params }) = text(&mut ws).await else {
        panic!("no challenge")
    };
    assert_eq!(m, method::CHALLENGE);
    let nonce = msg::unhex(params["nonce"].as_str().unwrap()).unwrap();
    let center_id = params["center_id"].as_str().unwrap().to_string();
    assert_eq!(center_id, r.center.id());
    let hello = json!({
        "node_id": key.node_id(),
        "auth": {"sig": key.sign_connect(&center_id, &nonce)},
        "versions": ["0"],
        "software": {"name": "fake-node", "version": "0.0.1"},
        "rev": 1,
    });
    send(&mut ws, Message::notification(method::HELLO, hello)).await;
    let next = text(&mut ws).await.expect("a reply to hello");
    (ws, next)
}

enum Seen {
    Invoke(Value),
    SessionEnd(String),
}

/// Answers the center like a node: describe, sub, invoke (echoing the
/// arguments), and reports what it saw.
fn serve(mut ws: WebSocketStream<BoxIo>, desc: Value) -> mpsc::UnboundedReceiver<Seen> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(m) = text(&mut ws).await {
            match m {
                Message::Request {
                    id,
                    method: m,
                    params,
                } => {
                    let result = match m.as_str() {
                        method::DESCRIBE => desc.clone(),
                        method::INVOKE => {
                            let _ = tx.send(Seen::Invoke(Value::Object(params.clone())));
                            json!({"content": format!("echo {}", params["args"]), "encoding": "utf-8"})
                        }
                        _ => json!({}),
                    };
                    send(&mut ws, Message::result(id, result)).await;
                }
                Message::Notification { method: m, params } if m == method::SESSION_END => {
                    let _ = tx.send(Seen::SessionEnd(
                        params["session"].as_str().unwrap_or("").into(),
                    ));
                }
                _ => {}
            }
        }
    });
    rx
}

async fn wait_for<T>(mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out")
}

async fn rpc(e: &Engine, id: u64, method: &str, params: Value) -> Value {
    e.handle(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .await
        .expect("a reply")
}

#[tokio::test]
async fn pair_connect_describe_and_call() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();

    let (status, body) = pair(&r, &key, "box-1").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["node_id"], key.node_id());
    assert_eq!(body["center_name"], "test-center");
    // The same name or key again is a conflict.
    let other = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &other, "box-1").await.0, 409);
    assert_eq!(pair(&r, &key, "box-2").await.0, 409);

    let (ws, welcome) = handshake(&r, &key).await;
    let Message::Notification { method: m, params } = welcome else {
        panic!("no welcome")
    };
    assert_eq!(m, method::WELCOME);
    assert_eq!(params["version"], "0");
    let mut seen = serve(ws, descriptor(&key, "box-1"));

    // The descriptor arrives and becomes tools; settings stays out of them.
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = Engine::new(&r.center, "test");
    let init = rpc(
        &e,
        1,
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}),
    )
    .await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(
        e.handle(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
            .is_none()
    );
    let list = rpc(&e, 2, "tools/list", json!({})).await;
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["nodes", "exec_run", "fs_read"]);

    // A read goes straight through and is marked as device content.
    let call = rpc(
        &e,
        3,
        "tools/call",
        json!({"name": "fs_read", "arguments": {"node": "box-1", "path": "/etc/hostname"}}),
    )
    .await;
    let out = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        out.starts_with("[device content from node \"box-1\""),
        "{out}"
    );
    assert!(out.contains("/etc/hostname"));
    assert_ne!(call["result"]["isError"], true);
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["cap"], "fs");
    assert_eq!(inv["action"], "read");
    assert_eq!(inv["args"], json!({"path": "/etc/hostname"}));
    let session = inv["ctx"]["session"].as_str().unwrap().to_string();

    // An unknown node name is refused with the names that exist.
    let bad = rpc(
        &e,
        4,
        "tools/call",
        json!({"name": "fs_read", "arguments": {"node": "nope", "path": "/"}}),
    )
    .await;
    assert_eq!(bad["result"]["isError"], true);
    assert!(
        bad["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("box-1")
    );

    // The center holds no call back: execute goes straight to the node,
    // which decides.
    let done = rpc(
        &e,
        5,
        "tools/call",
        json!({"name": "exec_run", "arguments": {"node": "box-1", "command": "uname"}}),
    )
    .await;
    assert_ne!(done["result"]["isError"], true, "{done}");
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["cap"], "exec");
    assert_eq!(inv["ctx"]["session"], session.as_str());

    // Ending the session tells the node.
    e.close().await;
    let Some(Seen::SessionEnd(s)) = seen.recv().await else {
        panic!("no session.end")
    };
    assert_eq!(s, session);
    r.stop().await;
}

#[tokio::test]
async fn unknown_node_and_wrong_codes() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    match ws::connect(&url(&r), None, None, &key.node_id(), MAX).await {
        Err(ConnectError::Unknown) => {}
        Err(e) => panic!("expected 401, got {e:?}"),
        Ok(_) => panic!("an unknown node got a link"),
    }
    // A made-up code is refused.
    let mut io = tokio::net::TcpStream::connect(r.nodes).await.unwrap();
    let body = json!({"code": "aaaaaaaaaaaa", "name": "x", "platform": "linux", "arch": "x86_64",
                      "public_key": key.public_hex()});
    let resp =
        nerve_transport::http::post_json(&mut io, "127.0.0.1", nerve_proto::PAIR_PATH, &body, 4096)
            .await
            .unwrap();
    assert_eq!(resp.status, 403);
    r.stop().await;
}

#[tokio::test]
async fn a_second_link_while_the_first_answers_is_a_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (first, _) = handshake(&r, &key).await;
    // The first link keeps reading, so it answers the center's ping.
    let _seen = serve(first, descriptor(&key, "box-1"));
    let c = r.center.clone();
    let id = key.node_id();
    wait_for(|| c.link(&id).map(|_| ())).await;

    let (_second, reply) = handshake(&r, &key).await;
    let Message::Notification { method: m, params } = reply else {
        panic!("expected bye")
    };
    assert_eq!(m, method::BYE);
    assert_eq!(params["reason"], "duplicate");
    assert!(!r.center.alerts().is_empty(), "a duplicate raises an alert");
    r.stop().await;
}

#[tokio::test]
async fn a_descriptor_with_an_underscore_in_a_name_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut d = descriptor(&key, "box-1");
    d["capabilities"][0]["id"] = json!("my_fs");
    let _seen = serve(ws, d);
    let c = r.center.clone();
    let id = key.node_id();
    wait_for(|| c.link(&id).map(|_| ())).await;
    // The describe call has long been answered when this passes.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(r.center.tools().is_empty(), "{:?}", r.center.tools().len());
    r.stop().await;
}

fn http(method: &str, headers: &[(&str, &str)], body: Value) -> nerve_transport::http::Request {
    nerve_transport::http::Request {
        method: method.into(),
        path: "/mcp".into(),
        query: String::new(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        },
    }
}

#[tokio::test]
async fn http_mcp_needs_a_token_and_a_session() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let h = nerve_center::mcp::HttpMcp::new(&r.center, Some("secret-token".into()));
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}});
    assert_eq!(h.request(http("POST", &[], init.clone())).await.status, 401);
    assert_eq!(
        h.request(http(
            "POST",
            &[("authorization", "Bearer wrong")],
            init.clone()
        ))
        .await
        .status,
        401
    );
    let auth = ("authorization", "Bearer secret-token");
    let evil = ("origin", "http://evil.example");
    assert_eq!(
        h.request(http(
            "POST",
            &[auth, evil, ("host", "127.0.0.1:7481")],
            init.clone()
        ))
        .await
        .status,
        403
    );

    let resp = h.request(http("POST", &[auth], init)).await;
    assert_eq!(resp.status, 200);
    let sid = resp
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
        .map(|(_, v)| v.clone())
        .expect("a session id");
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    assert_eq!(
        h.request(http("POST", &[auth], list.clone())).await.status,
        400,
        "no session id"
    );
    let resp = h
        .request(http(
            "POST",
            &[auth, ("mcp-session-id", &sid)],
            list.clone(),
        ))
        .await;
    assert_eq!(resp.status, 200);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(v["result"]["tools"][0]["name"], "nodes");
    assert_eq!(
        h.request(http(
            "DELETE",
            &[auth, ("mcp-session-id", &sid)],
            Value::Null
        ))
        .await
        .status,
        204
    );
    assert_eq!(
        h.request(http("POST", &[auth, ("mcp-session-id", &sid)], list))
            .await
            .status,
        404
    );
    assert_eq!(
        h.request(http("GET", &[auth], Value::Null)).await.status,
        405
    );
    r.stop().await;
}

#[tokio::test]
async fn a_disabled_node_offers_no_tools_and_gets_no_calls() {
    let dir = tempfile::tempdir().unwrap();
    let r = center(dir.path()).await;
    let key = NodeKey::generate().unwrap();
    assert_eq!(pair(&r, &key, "box-1").await.0, 200);
    let (ws, _) = handshake(&r, &key).await;
    let mut seen = serve(ws, descriptor(&key, "box-1"));
    let c = r.center.clone();
    wait_for(|| (!c.tools().is_empty()).then_some(())).await;
    let e = Engine::new(&r.center, "test");
    let names = |list: &Value| -> Vec<String> {
        list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let read = json!({"name": "fs_read", "arguments": {"node": "box-1", "path": "/x"}});
    let id = key.node_id();

    // Switched off: the tools are gone, `nodes` still lists the node and
    // says why, and the link stays up.
    c.set_disabled(&id, true).unwrap();
    assert!(c.tools().is_empty());
    assert_eq!(names(&rpc(&e, 1, "tools/list", json!({})).await), ["nodes"]);
    let listed = rpc(
        &e,
        2,
        "tools/call",
        json!({"name": "nodes", "arguments": {}}),
    )
    .await;
    let listed = listed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        listed.contains("box-1") && listed.contains("online"),
        "{listed}"
    );
    assert!(listed.contains("disabled in the center"), "{listed}");
    assert!(!listed.contains("offers fs"), "{listed}");
    assert!(c.link(&id).is_some());

    // A call on a tool list read before the switch is refused by the center
    // itself, before anything goes to the node.
    let route = {
        c.set_disabled(&id, false).unwrap();
        let tools = c.tools();
        c.set_disabled(&id, true).unwrap();
        tools.iter().find(|t| t.name == "fs_read").unwrap().routes["box-1"].clone()
    };
    let sess = c.new_session("test");
    let err = c
        .call(&sess, &route, serde_json::Map::new())
        .await
        .unwrap_err();
    let nerve_center::center::CallError::Rpc(err) = err;
    assert_eq!(err.message, "the node box-1 is disabled in the center");
    // By name through MCP it is an unknown tool.
    let by_name = rpc(&e, 3, "tools/call", read.clone()).await;
    assert!(by_name.get("error").is_some(), "{by_name}");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), seen.recv())
            .await
            .is_err(),
        "the node received something"
    );

    // Switched on again: the tools are back and a call reaches the node.
    c.set_disabled(&id, false).unwrap();
    assert_eq!(
        names(&rpc(&e, 4, "tools/list", json!({})).await),
        ["nodes", "exec_run", "fs_read"]
    );
    let done = rpc(&e, 5, "tools/call", read).await;
    assert_ne!(done["result"]["isError"], true, "{done}");
    let Some(Seen::Invoke(inv)) = seen.recv().await else {
        panic!("no invoke")
    };
    assert_eq!(inv["args"], json!({"path": "/x"}));
    r.stop().await;
}
