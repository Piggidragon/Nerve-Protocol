//! How the center decides on the web UI's login at start: it logs in with the
//! harness token (from a flag or made in the UI), may be switched off on
//! loopback, and beyond loopback it needs a token and cannot be switched off.

use clap::Parser;
use nerve_center::config::Args;
use nerve_center::server::{self, Running};
use nerve_center::store::{Store, TokenRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start(dir: &std::path::Path, extra: &[&str]) -> Result<Running, String> {
    nerve_transport::init_crypto();
    let mut argv = vec![
        "nerve-center",
        "--state-dir",
        dir.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
        "--plain-loopback",
        "--mcp",
        "none",
    ];
    argv.extend_from_slice(extra);
    let args = Args::try_parse_from(argv).unwrap();
    let lock = nerve_center::attach::try_lock(dir)
        .unwrap()
        .expect("the lock is free");
    server::start(&args, lock).await
}

/// `GET /` on the UI as a browser on this machine without a cookie: the
/// status line and the `Location` header, if any.
async fn get_root(r: &Running) -> (u16, Option<String>) {
    let mut io = tokio::net::TcpStream::connect(r.ui.expect("a UI"))
        .await
        .unwrap();
    io.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    io.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text.split(' ').nth(1).unwrap().parse().unwrap();
    let location = text
        .lines()
        .find_map(|l| {
            l.strip_prefix("Location: ")
                .or(l.strip_prefix("location: "))
        })
        .map(str::to_string);
    (status, location)
}

fn store_with_a_token(dir: &std::path::Path) {
    let mut s = Store::new("c".into(), "home".into());
    s.harness_tokens.push(TokenRecord {
        id: "t1".into(),
        label: "harness".into(),
        hash: "0".repeat(64),
        created_ms: 1,
    });
    nerve_transport::files::create_private_dir(dir).unwrap();
    s.save(dir).unwrap();
}

#[tokio::test]
async fn a_fresh_center_is_open_on_loopback_so_the_first_token_can_be_made() {
    let d = tempfile::tempdir().unwrap();
    let r = start(d.path(), &["--ui", "127.0.0.1:0"]).await.unwrap();
    assert_eq!(get_root(&r).await, (200, None));
}

#[tokio::test]
async fn a_token_from_a_flag_turns_the_login_on() {
    let d = tempfile::tempdir().unwrap();
    let r = start(
        d.path(),
        &["--ui", "127.0.0.1:0", "--harness-token", "nrv_secret"],
    )
    .await
    .unwrap();
    assert_eq!(get_root(&r).await, (303, Some("/login".into())));
}

#[tokio::test]
async fn a_token_made_in_an_earlier_run_turns_the_login_on() {
    let d = tempfile::tempdir().unwrap();
    store_with_a_token(d.path());
    let r = start(d.path(), &["--ui", "127.0.0.1:0"]).await.unwrap();
    assert_eq!(get_root(&r).await, (303, Some("/login".into())));
}

#[tokio::test]
async fn the_login_can_be_switched_off_on_loopback() {
    let d = tempfile::tempdir().unwrap();
    let r = start(
        d.path(),
        &[
            "--ui",
            "127.0.0.1:0",
            "--harness-token",
            "nrv_secret",
            "--ui-no-login",
        ],
    )
    .await
    .unwrap();
    assert_eq!(get_root(&r).await, (200, None));
}

#[tokio::test]
async fn beyond_loopback_a_token_is_required() {
    let d = tempfile::tempdir().unwrap();
    for ui in ["0.0.0.0:0", "[::]:0"] {
        let e = start(d.path(), &["--ui", ui])
            .await
            .err()
            .expect("a refusal");
        assert!(e.contains("harness token"), "{ui}: {e}");
        assert!(e.contains("beyond loopback"), "{ui}: {e}");
    }
    // Nothing was written for a start that was refused.
    assert!(!d.path().join(nerve_center::store::FILE).exists());
}

#[tokio::test]
async fn beyond_loopback_the_login_cannot_be_switched_off() {
    let d = tempfile::tempdir().unwrap();
    let e = start(
        d.path(),
        &[
            "--ui",
            "0.0.0.0:0",
            "--harness-token",
            "nrv_secret",
            "--ui-no-login",
        ],
    )
    .await
    .err()
    .expect("a refusal");
    assert!(e.contains("--ui-no-login"), "{e}");
}

#[tokio::test]
async fn beyond_loopback_a_token_from_a_flag_or_the_state_is_enough() {
    let d = tempfile::tempdir().unwrap();
    let r = start(
        d.path(),
        &["--ui", "0.0.0.0:0", "--harness-token", "nrv_secret"],
    )
    .await
    .unwrap();
    assert!(r.ui.is_some());
    r.stop().await;

    let d = tempfile::tempdir().unwrap();
    store_with_a_token(d.path());
    let r = start(d.path(), &["--ui", "0.0.0.0:0"]).await.unwrap();
    assert!(r.ui.is_some());
}

#[tokio::test]
async fn without_a_web_ui_nothing_is_asked() {
    let d = tempfile::tempdir().unwrap();
    let r = start(d.path(), &["--ui", "off", "--ui-no-login"])
        .await
        .unwrap();
    assert!(r.ui.is_none());
}
