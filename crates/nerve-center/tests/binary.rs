//! The `nerve-center` binary as a harness starts it: MCP over stdio, and a
//! second instance on the same state folder that attaches to the first.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn spawn(state: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_STATE_DIR", state)
        .env("NERVE_LISTEN", "127.0.0.1:0")
        .env("NERVE_PLAIN_LOOPBACK", "true")
        .env("NERVE_UI", "off")
        .env("NERVE_LOG", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn ask(child: &mut Child, out: &mut BufReader<std::process::ChildStdout>, msg: Value) -> Value {
    let stdin = child.stdin.as_mut().unwrap();
    writeln!(stdin, "{msg}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
}

fn init(child: &mut Child, out: &mut BufReader<std::process::ChildStdout>) {
    let r = ask(
        child,
        out,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}),
    );
    assert_eq!(r["result"]["serverInfo"]["name"], "nerve-center", "{r}");
    let stdin = child.stdin.as_mut().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    .unwrap();
}

fn wait(child: &mut Child, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn stdio_and_a_second_instance_that_attaches() {
    let dir = tempfile::tempdir().unwrap();
    let mut owner = spawn(dir.path());
    let mut owner_out = BufReader::new(owner.stdout.take().unwrap());
    init(&mut owner, &mut owner_out);
    let tools = ask(
        &mut owner,
        &mut owner_out,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(tools["result"]["tools"][0]["name"], "nodes", "{tools}");

    // The second instance finds the lock held and relays to the owner.
    let mut second = spawn(dir.path());
    let mut second_out = BufReader::new(second.stdout.take().unwrap());
    init(&mut second, &mut second_out);
    let nodes = ask(
        &mut second,
        &mut second_out,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nodes", "arguments": {}}}),
    );
    assert_ne!(nodes["result"]["isError"], true, "{nodes}");

    // The owner's harness goes; the owner stays while the attached one runs.
    drop(owner.stdin.take());
    assert!(
        !wait(&mut owner, Duration::from_millis(1500)),
        "the owner left an attached harness behind"
    );
    let again = ask(
        &mut second,
        &mut second_out,
        json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}),
    );
    assert_eq!(again["result"], json!({}));
    drop(second.stdin.take());
    assert!(
        wait(&mut second, Duration::from_secs(10)),
        "the attached instance did not exit"
    );
    assert!(
        wait(&mut owner, Duration::from_secs(10)),
        "the owner did not exit"
    );
    assert!(owner.wait().unwrap().success());
}

#[test]
fn a_ui_beyond_loopback_without_a_harness_token_does_not_start() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_nerve-center"))
        .env_clear()
        .env("NERVE_STATE_DIR", dir.path())
        .env("NERVE_LISTEN", "127.0.0.1:0")
        .env("NERVE_PLAIN_LOOPBACK", "true")
        .env("NERVE_UI", "0.0.0.0:0")
        .env("NERVE_LOG", "warn")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("NERVE_HARNESS_TOKEN"), "{err}");
}
