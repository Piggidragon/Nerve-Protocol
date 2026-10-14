//! The provider part: checks a node's provider attach
//! (docs/dev/spec/node-local.md §7), acting as a center ([`FakeCenter`])
//! and as a capability provider on the node's control socket at once.
//!
//! The caller gets a pairing link and must pair the node under test with
//! it, give the fake center the settings grant `write`, allow the program
//! that runs this part (`std::env::current_exe()`) as a provider under
//! [`Setup::provider`], and start the node. The part writes its own policy
//! (an allow rule for `echo.say` and `echo.fail`, none for `echo.shout`),
//! attaches an echo provider, and calls it through the center's link.
//!
//! Unix only: the provider attaches on the control socket.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

use nerve_proto::link::PairLink;
use nerve_proto::msg::method;
use nerve_proto::{ErrorCode, Message};

use crate::fake_center::{self, FakeCenter};
use crate::node_part::expect_code;
use crate::wire::{Recv, code_of};
use crate::{Report, ensure};

const WAIT: Duration = Duration::from_secs(15);

/// The section of the node-local spec every check of this part tests.
const SECTION: &str = "node-local 7";

/// The capability the part's provider adds.
pub const CAP: &str = "echo";

/// What the caller says about the node it started.
#[derive(Debug, Clone)]
pub struct Setup {
    /// The node's control socket. Its token is in `ctl.token` beside it.
    pub socket: PathBuf,
    /// The name `providers.allowed` gives the program that runs this part.
    pub provider: String,
}

/// Every check, in order; each needs the ones before it.
pub const CHECKS: &[&str] = &[
    "a program providers.allowed does not name is refused",
    "an allowed provider attaches",
    "a second provider of the same name is refused",
    "the node tells the center that its descriptor changed",
    "the descriptor lists the capability with its provider, cut by the policy",
    "a call the policy allows reaches the provider and its answer comes back",
    "a provider's error comes back with its code",
    "a call the policy refuses never reaches the provider",
    "when the provider exits its capability leaves the descriptor",
    "a call to a provider that left is unknown_capability",
];

type Conn = crate::wire::Conn<tokio::net::TcpStream>;

/// Runs every provider check. `start` pairs the node under test with the
/// link it is given, allows this program as a provider and starts the node.
pub async fn run<F, Fut>(start: F) -> Report
where
    F: FnOnce(PairLink) -> Fut,
    Fut: Future<Output = Result<Setup, String>>,
{
    let mut r = Report::new("provider");
    let mut center = match FakeCenter::start(false).await {
        Ok(c) => c,
        Err(e) => {
            r.check("4.1", "the fake center starts", Err(e.to_string()));
            return r;
        }
    };
    let setup = match start(center.link()).await {
        Ok(s) => s,
        Err(e) => {
            r.check("3.2", "the node pairs", Err(e));
            return r;
        }
    };
    let Some(paired) = center.paired() else {
        r.check(
            "3.2",
            "the node pairs",
            Err("no pair request arrived".into()),
        );
        return r;
    };
    let Some(mut link) = center.next_link(Duration::from_secs(30)).await else {
        r.check(
            "4.1",
            "the node dials the center",
            Err("no link within 30 s".into()),
        );
        return r;
    };
    let conn = &mut link.conn;
    if let Err(e) = fake_center::handshake(conn, &center.center_id, &paired).await {
        r.check("4.2", "the handshake", Err(e));
        return r;
    }
    let mut done = 0;
    let out = steps(conn, &setup, &mut |res| {
        r.check(SECTION, CHECKS[done], res);
        done += 1;
    })
    .await;
    if let Err(why) = out {
        for name in &CHECKS[done..] {
            r.skip(SECTION, name, &why);
        }
    }
    conn.bye("shutdown").await;
    r
}

/// The provider's side of the control socket.
struct Provider {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    w: tokio::net::unix::OwnedWriteHalf,
}

/// Sends `hello` as the provider `name` with the echo fragment: the
/// connection, and the node's answer (`ok` or the error text).
async fn hello(socket: &Path, name: &str) -> Result<(Provider, Result<Value, String>), String> {
    let token = std::fs::read_to_string(socket.with_file_name("ctl.token"))
        .map_err(|e| format!("cannot read the control socket's token: {e}"))?;
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("cannot connect to {}: {e}", socket.display()))?;
    let (r, mut w) = stream.into_split();
    let read = |text: &str| {
        json!({"effect": "read", "summary": text,
                                   "params": {"type": "object"}})
    };
    let fragment = json!([{"id": CAP, "summary": "Says back what it is sent.",
        "actions": {"say": read("Return the arguments."),
                    "shout": read("Never called: no rule allows it."),
                    "fail": read("Fails with io.")}}]);
    let line = json!({"method": "hello", "token": token.trim(),
                      "params": {"role": "provider", "name": name, "capabilities": fragment}});
    w.write_all(format!("{line}\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut lines = BufReader::new(r).lines();
    let first = tokio::time::timeout(WAIT, lines.next_line())
        .await
        .map_err(|_| "no answer to hello".to_string())?
        .map_err(|e| e.to_string())?
        .ok_or("the node closed without answering hello")?;
    let v: Value = serde_json::from_str(&first).map_err(|e| e.to_string())?;
    let answer = match (v.get("ok"), v.get("error").and_then(Value::as_str)) {
        (Some(ok), None) => Ok(ok.clone()),
        (_, Some(e)) => Err(e.to_string()),
        _ => Err(format!("neither ok nor error: {v}")),
    };
    Ok((Provider { lines, w }, answer))
}

/// Serves the provider's calls until `stop` fires, then closes: `say`
/// returns its arguments, `fail` fails with `io`. Every action it is called
/// for lands in `seen`.
async fn serve(mut p: Provider, seen: Arc<Mutex<Vec<String>>>, mut stop: oneshot::Receiver<()>) {
    loop {
        let line = tokio::select! {
            l = p.lines.next_line() => match l {
                Ok(Some(l)) => l,
                _ => return,
            },
            _ = &mut stop => return,
        };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if v["method"] != "invoke" {
            continue;
        }
        let action = v["params"]["action"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        seen.lock().unwrap().push(action.clone());
        let reply = if action == "fail" {
            json!({"id": v["id"], "error": "it failed on purpose", "code": "io"})
        } else {
            json!({"id": v["id"], "ok": v["params"]["args"]})
        };
        if p.w
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn invoke(
    conn: &mut Conn,
    action: &str,
    args: Value,
) -> Result<Result<Value, nerve_proto::RpcError>, String> {
    conn.call(
        method::INVOKE,
        json!({"cap": CAP, "action": action, "args": args, "ctx": {}}),
        WAIT,
    )
    .await
}

fn ok(got: Result<Result<Value, nerve_proto::RpcError>, String>) -> Result<Value, String> {
    match got {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("error {} ({})", code_of(&e), e.message)),
        Err(e) => Err(e),
    }
}

/// Waits for `node/descriptor_changed`, skipping everything else.
async fn descriptor_changed(conn: &mut Conn) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match conn.recv(left).await {
            Recv::Msg(Message::Notification { method: m, params })
                if m == method::EVENT
                    && params["cap"] == "node"
                    && params["name"] == "descriptor_changed" =>
            {
                return Ok(());
            }
            Recv::Msg(_) => {}
            Recv::Timeout => return Err("no node/descriptor_changed within 15 s".into()),
            other => return Err(format!("the link ended: {other:?}")),
        }
    }
}

/// The capability `CAP` of the descriptor now, if listed.
async fn listed(conn: &mut Conn) -> Result<Option<Value>, String> {
    let d = ok(conn
        .call(method::DESCRIBE, json!({"detail": "full"}), WAIT)
        .await)?;
    Ok(d["capabilities"]
        .as_array()
        .and_then(|caps| caps.iter().find(|c| c["id"] == CAP))
        .cloned())
}

/// Runs the checks in [`CHECKS`] order, giving each result to `check`;
/// stops at the first failure.
async fn steps(
    conn: &mut Conn,
    setup: &Setup,
    check: &mut dyn FnMut(Result<(), String>),
) -> Result<(), String> {
    let mut step = |res: Result<(), String>| {
        let failed = res
            .as_ref()
            .err()
            .map(|e| format!("an earlier check failed: {e}"));
        check(res);
        failed.map_or(Ok(()), Err)
    };

    // Default deny: an allow rule for two of its actions, before it comes.
    let got = ok(conn
        .call(
            method::GET,
            json!({"cap": "settings", "keys": ["document", "version"]}),
            WAIT,
        )
        .await)
    .map_err(|e| format!("settings get (the fake center needs the settings grant write): {e}"))?;
    let mut doc = got["document"].clone();
    doc["policy"]["mode"] = json!("allowlist");
    doc["policy"]["allow"] = json!([format!("{CAP}.say"), format!("{CAP}.fail")]);
    if let Some(p) = doc["policy"].as_object_mut() {
        p.remove("until");
    }
    ok(conn
        .call(
            method::INVOKE,
            json!({"cap": "settings", "action": "set", "ctx": {},
                   "args": {"document": doc, "if_version": got["version"]}}),
            WAIT,
        )
        .await)
    .map_err(|e| format!("settings set: {e}"))?;

    let stranger = format!("{}-stranger", setup.provider);
    step(match hello(&setup.socket, &stranger).await {
        Ok((_, Err(_))) => Ok(()),
        Ok((_, Ok(v))) => Err(format!("it attached: {v}")),
        Err(e) => Err(e),
    })?;

    let (provider, answer) = hello(&setup.socket, &setup.provider).await?;
    step(answer.and_then(|v| {
        ensure(
            v["capabilities"] == json!([CAP]),
            format!("the answer names {v}"),
        )
    }))?;

    step(match hello(&setup.socket, &setup.provider).await {
        Ok((_, Err(_))) => Ok(()),
        Ok((_, Ok(v))) => Err(format!("a second one attached: {v}")),
        Err(e) => Err(e),
    })?;

    step(descriptor_changed(conn).await)?;

    step(listed(conn).await.and_then(|cap| {
        let cap = cap.ok_or("the descriptor does not list it")?;
        ensure(
            cap["provider"] == json!(setup.provider),
            format!("its provider is {}", cap["provider"]),
        )?;
        let mut actions: Vec<&String> = cap["actions"]
            .as_object()
            .map(|a| a.keys().collect())
            .unwrap_or_default();
        actions.sort();
        // No rule allows shout, so the center is not shown it.
        ensure(
            actions == ["fail", "say"],
            format!("its actions are {actions:?}"),
        )
    }))?;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let (stop, stopped) = oneshot::channel();
    let served = tokio::spawn(serve(provider, seen.clone(), stopped));

    step(
        ok(invoke(conn, "say", json!({"text": "hello provider"})).await)
            .and_then(|v| ensure(v["text"] == "hello provider", format!("got {v}"))),
    )?;

    step(match invoke(conn, "fail", json!({})).await {
        Ok(Err(e)) => ensure(
            code_of(&e) == "io" && e.message.contains("it failed on purpose"),
            format!("got {} ({})", code_of(&e), e.message),
        ),
        Ok(Ok(v)) => Err(format!("succeeded with {v}")),
        Err(e) => Err(e),
    })?;

    // Lines to the provider keep their order: had the refused call been
    // forwarded, the provider would see it before the next say.
    step(
        async {
            expect_code(invoke(conn, "shout", json!({})).await, ErrorCode::Forbidden)?;
            ok(invoke(conn, "say", json!({"text": "again"})).await)?;
            let seen = seen.lock().unwrap().clone();
            ensure(
                !seen.iter().any(|a| a == "shout"),
                format!("the provider was called for {seen:?}"),
            )
        }
        .await,
    )?;

    let _ = stop.send(());
    let _ = served.await;
    step(
        async {
            descriptor_changed(conn).await?;
            match listed(conn).await? {
                None => Ok(()),
                Some(c) => Err(format!("still listed: {c}")),
            }
        }
        .await,
    )?;

    step(expect_code(
        invoke(conn, "say", json!({"text": "gone"})).await,
        ErrorCode::UnknownCapability,
    ))?;
    Ok(())
}
