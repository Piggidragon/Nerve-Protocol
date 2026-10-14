//! Local control sockets: how `nerve-node`'s CLI talks to the running node
//! (docs/dev/spec/node-local.md).
//!
//! One JSON object per line. The client sends `{"method", "params"}`; the
//! server answers with one line `{"ok": value}` or `{"error": "text"}`, or, for
//! a following call, with several `{"item": value}` lines until it closes.
//!
//! On Unix the socket is created 0600 in a 0700 folder, and every peer's
//! credentials are read: only the socket's own user or root may talk to it.
//! That does not tell the owner's programs from a sandboxed process of the
//! same user: Landlock keeps a process from connecting to a socket file only
//! from ABI 9 on, and a process that left the tree below its command (with
//! `setsid`) is no longer known as one. So a server may also hand out a token
//! ([`write_token`]): a file beside the socket that the client reads and sends
//! with each request, which a process kept from the folder cannot read.
//! Windows has no control channel; there the CLI works on the config files
//! directly (see `nerve-node`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtlRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    /// What the client read from [`token_file`], when it could.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Who is on the other end of a control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: Option<u32>,
}

/// The file that holds the token of the server on the socket `socket`.
pub fn token_file(socket: &std::path::Path) -> std::path::PathBuf {
    socket.with_file_name("ctl.token")
}

/// The parent process of `pid`, from `/proc/<pid>/stat` (Linux only).
#[cfg(target_os = "linux")]
pub fn parent_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces and parentheses: the fields after it
    // start after the last ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Whether `pid` is `ancestor` or one of its descendants (Linux only; elsewhere
/// always false). Used to refuse settings changes from commands a center ran.
pub fn descends_from(pid: u32, ancestor: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let mut p = pid;
        for _ in 0..256 {
            if p == ancestor {
                return true;
            }
            match parent_of(p) {
                Some(pp) if pp != p && pp != 0 => p = pp,
                _ => return false,
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, ancestor);
        false
    }
}

#[cfg(unix)]
mod unix {
    use std::path::Path;
    use std::sync::Arc;

    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::mpsc;

    use super::{CtlRequest, Peer, token_file};

    /// The longest request line read.
    const LINE_BYTES: usize = 1024 * 1024;

    /// What a handler sends back: one answer, or items of a following call.
    pub enum Reply {
        Ok(Value),
        Err(String),
        /// Items until the sender is dropped.
        Follow(mpsc::Receiver<Value>),
    }

    /// Binds `path` and serves every connection with `handler`. A stale socket
    /// file is replaced; a live one (another node running) is an error.
    pub async fn serve<F, Fut>(path: &Path, handler: F) -> std::io::Result<()>
    where
        F: Fn(CtlRequest, Peer) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Reply> + Send + 'static,
    {
        serve_on(bind(path).await?, handler).await
    }

    /// Like [`serve`], on a socket [`bind`] made already. Binding once
    /// matters: a socket dropped and bound again can look in use while a
    /// child forked meanwhile still holds the old one.
    ///
    /// A connection that cannot be taken does not end the serving, whatever the
    /// reason: for want of descriptors or memory (EMFILE once a process of the
    /// user holds the node's open files), of epoll watches (ENOSPC, which a
    /// process of the user can use up for every process of the user), or
    /// because it went before it was taken. The socket stays, and the next
    /// connection is taken once the cause is gone. Ending would leave the node
    /// without its socket until it restarts, and the CLI would take a running
    /// node for none. Only an error that says the listener itself is broken
    /// ends it.
    pub async fn serve_on<F, Fut>(listener: UnixListener, handler: F) -> std::io::Result<()>
    where
        F: Fn(CtlRequest, Peer) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Reply> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let me = crate::net::euid();
        let mut failing = false;
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) if passing(&e) => {
                    // Once per run of failures: they come as fast as the
                    // pause allows.
                    if !std::mem::replace(&mut failing, true) {
                        tracing::warn!("the control socket cannot take a connection now: {e}");
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            failing = false;
            let handler = handler.clone();
            tokio::spawn(async move {
                let peer = match stream.peer_cred() {
                    Ok(c) => Peer {
                        uid: c.uid(),
                        pid: c.pid().and_then(|p| u32::try_from(p).ok()),
                    },
                    Err(_) => return,
                };
                if peer.uid != me && peer.uid != 0 {
                    return;
                }
                let _ = connection(stream, peer, handler).await;
            });
        }
    }

    /// Whether `accept` failed for this connection only and the listener
    /// can take the next one. The list is of the errors that mean the
    /// listener itself is broken, not of the passing ones: a limit of the
    /// user's that runs out (descriptors, memory, epoll watches) shows up as
    /// one of many errors, and missing one would end the socket for good.
    /// An error without an OS code comes from tokio itself (the runtime
    /// shutting down) and ends it too.
    fn passing(e: &std::io::Error) -> bool {
        match e.raw_os_error() {
            Some(libc::EBADF | libc::EINVAL | libc::ENOTSOCK | libc::EOPNOTSUPP | libc::EFAULT) => {
                false
            }
            Some(_) => true,
            None => false,
        }
    }

    pub async fn bind(path: &Path) -> std::io::Result<UnixListener> {
        if let Some(dir) = path.parent() {
            crate::files::create_private_dir(dir)?;
        }
        if path.exists() {
            if UnixStream::connect(path).await.is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("{} is in use: is the node running already?", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    async fn connection<F, Fut>(
        stream: UnixStream,
        peer: Peer,
        handler: Arc<F>,
    ) -> std::io::Result<()>
    where
        F: Fn(CtlRequest, Peer) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Reply> + Send + 'static,
    {
        let (r, mut w) = stream.into_split();
        let mut lines = BufReader::new(r.take(LINE_BYTES as u64 * 64));
        loop {
            let mut line = String::new();
            if lines.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line.len() > LINE_BYTES {
                return Ok(());
            }
            let reply = match serde_json::from_str::<CtlRequest>(&line) {
                Ok(req) => handler(req, peer).await,
                Err(e) => Reply::Err(format!("bad request: {e}")),
            };
            match reply {
                Reply::Ok(v) => write_line(&mut w, &json!({"ok": v})).await?,
                Reply::Err(e) => write_line(&mut w, &json!({"error": e})).await?,
                Reply::Follow(mut rx) => {
                    while let Some(item) = rx.recv().await {
                        write_line(&mut w, &json!({"item": item})).await?;
                    }
                    return Ok(());
                }
            }
        }
    }

    async fn write_line<W: AsyncWriteExt + Unpin>(w: &mut W, v: &Value) -> std::io::Result<()> {
        let mut s = v.to_string();
        s.push('\n');
        w.write_all(s.as_bytes()).await?;
        w.flush().await
    }

    /// Error when nothing listens on `path`.
    pub const NOT_RUNNING: &str = "not running";

    /// Makes a token for the server on `socket` that [`bind`] just made: a
    /// new one per start, in [`token_file`], readable by its user only. The
    /// server compares what requests carry with it ([`token_ok`]).
    pub fn write_token(socket: &Path) -> std::io::Result<String> {
        let token = crate::keys::random_token(32);
        crate::files::write_private(&token_file(socket), token.as_bytes())?;
        Ok(token)
    }

    /// Whether a request carries `token`, compared in time that depends only
    /// on the lengths.
    pub fn token_ok(token: &str, given: Option<&str>) -> bool {
        given.is_some_and(|g| {
            token.len() == g.len()
                && token
                    .bytes()
                    .zip(g.bytes())
                    .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                    == 0
        })
    }

    /// The request a client sends on the socket `path`. The token is read
    /// after the connection is made: a server writes it right after it binds
    /// the socket.
    pub fn request_line(path: &Path, method: &str, params: Value) -> Value {
        let token = std::fs::read_to_string(token_file(path)).ok();
        json!(CtlRequest {
            method: method.to_string(),
            params,
            token,
        })
    }

    /// One call: sends the request and returns the answer.
    pub async fn call(path: &Path, method: &str, params: Value) -> Result<Value, String> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|_| NOT_RUNNING.to_string())?;
        let (r, mut w) = stream.into_split();
        write_line(&mut w, &request_line(path, method, params))
            .await
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(r)
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;
        answer(&line)
    }

    fn answer(line: &str) -> Result<Value, String> {
        let v: Value = serde_json::from_str(line)
            .map_err(|_| "the node closed without answering".to_string())?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(e.to_string());
        }
        Ok(v.get("ok").cloned().unwrap_or(Value::Null))
    }

    /// A following call: every item goes to `each` until the server closes.
    pub async fn follow(
        path: &Path,
        method: &str,
        params: Value,
        mut each: impl FnMut(Value),
    ) -> Result<(), String> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|_| NOT_RUNNING.to_string())?;
        let (r, mut w) = stream.into_split();
        write_line(&mut w, &request_line(path, method, params))
            .await
            .map_err(|e| e.to_string())?;
        let mut lines = BufReader::new(r).lines();
        while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
            let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            if let Some(item) = v.get("item") {
                each(item.clone());
            } else {
                answer(&line)?;
                return Ok(());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn calls_and_follows() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("run/ctl.sock");
            let p2 = p.clone();
            tokio::spawn(async move {
                serve(&p2, |req, peer| async move {
                    match req.method.as_str() {
                        "echo" => Reply::Ok(json!({"params": req.params, "uid": peer.uid})),
                        "follow" => {
                            let (tx, rx) = mpsc::channel(4);
                            tokio::spawn(async move {
                                for i in 0..3 {
                                    let _ = tx.send(json!(i)).await;
                                }
                            });
                            Reply::Follow(rx)
                        }
                        _ => Reply::Err("unknown method".into()),
                    }
                })
                .await
                .unwrap();
            });
            for _ in 0..100 {
                if p.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let v = call(&p, "echo", json!({"a": 1})).await.unwrap();
            assert_eq!(v["params"]["a"], 1);
            assert_eq!(v["uid"], crate::net::euid());
            assert_eq!(
                call(&p, "nope", json!({})).await.unwrap_err(),
                "unknown method"
            );
            let mut got = vec![];
            follow(&p, "follow", json!({}), |v| got.push(v))
                .await
                .unwrap();
            assert_eq!(got, vec![json!(0), json!(1), json!(2)]);
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            // A second server on a live socket is refused.
            assert!(bind(&p).await.is_err());
            assert_eq!(
                call(&d.path().join("none.sock"), "echo", json!({}))
                    .await
                    .unwrap_err(),
                NOT_RUNNING
            );
        }

        #[test]
        fn a_token_is_compared_whole() {
            assert!(token_ok("abc", Some("abc")));
            for given in [None, Some(""), Some("ab"), Some("abd"), Some("abcd")] {
                assert!(!token_ok("abc", given), "{given:?}");
            }
        }

        /// A client sends the token it finds beside the socket, and none where
        /// there is no file; a token is new per start and the file is private.
        #[tokio::test]
        async fn a_call_carries_the_token_beside_the_socket() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("run/ctl.sock");
            let listener = bind(&p).await.unwrap();
            tokio::spawn(serve_on(listener, |req, _| async move {
                if req.method == "follow" {
                    let (tx, rx) = mpsc::channel(1);
                    tx.try_send(json!(req.token)).unwrap();
                    return Reply::Follow(rx);
                }
                Reply::Ok(json!(req.token))
            }));
            let items = |p: std::path::PathBuf| async move {
                let mut got = vec![];
                follow(&p, "follow", json!({}), |v| got.push(v))
                    .await
                    .unwrap();
                got
            };
            assert_eq!(call(&p, "echo", json!({})).await.unwrap(), Value::Null);
            assert_eq!(items(p.clone()).await, vec![Value::Null]);
            let token = write_token(&p).unwrap();
            assert_eq!(token_file(&p), d.path().join("run/ctl.token"));
            assert_eq!(call(&p, "echo", json!({})).await.unwrap(), json!(token));
            assert_eq!(items(p.clone()).await, vec![json!(token)]);
            assert_ne!(write_token(&p).unwrap(), token);
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(token_file(&p)).unwrap().permissions();
            assert_eq!(mode.mode() & 0o777, 0o600);
        }

        /// Set in the process `serving_outlasts_running_out_of_descriptors`
        /// starts for itself.
        #[cfg(target_os = "linux")]
        const OUT_OF_DESCRIPTORS: &str = "NERVE_TEST_CTL_OUT_OF_DESCRIPTORS";

        /// With no descriptor left to take a connection, the server goes on and
        /// answers once they are back. The limit on open files holds for a
        /// whole process, so the test runs again in a process of its own.
        #[cfg(target_os = "linux")]
        #[test]
        fn serving_outlasts_running_out_of_descriptors() {
            if std::env::var_os(OUT_OF_DESCRIPTORS).is_none() {
                let name = format!(
                    "{}::serving_outlasts_running_out_of_descriptors",
                    module_path!().split_once("::").unwrap().1
                );
                let out = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--test-threads=1"])
                    .env(OUT_OF_DESCRIPTORS, "1")
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&out.stdout).contains("1 passed"),
                    "the test did not run in its own process"
                );
                return;
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                use std::os::unix::io::AsRawFd;
                let d = tempfile::tempdir().unwrap();
                let p = d.path().join("ctl.sock");
                let listener = bind(&p).await.unwrap();
                // Connections that wait to be taken; each needs a descriptor.
                let waiting: Vec<_> = (0..8)
                    .map(|_| std::os::unix::net::UnixStream::connect(&p).unwrap())
                    .collect();
                let mut old = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                // SAFETY: the limits of this process, into a local.
                assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut old) }, 0);
                // The lowest free descriptor becomes the limit: none is left.
                let next = std::fs::File::open("/dev/null").unwrap().as_raw_fd();
                let none = libc::rlimit {
                    rlim_cur: next as libc::rlim_t,
                    rlim_max: old.rlim_max,
                };
                // SAFETY: as above.
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &none) }, 0);
                let server =
                    tokio::spawn(serve_on(listener, |_, _| async { Reply::Ok(json!("up")) }));
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                assert!(
                    std::fs::File::open("/dev/null").is_err(),
                    "a descriptor was left"
                );
                assert!(!server.is_finished(), "the server stopped");
                drop(waiting);
                // SAFETY: as above.
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &old) }, 0);
                let v = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    call(&p, "status", json!({})),
                )
                .await
                .expect("an answer in time");
                assert_eq!(v, Ok(json!("up")));
            });
        }

        /// Running out of epoll watches (ENOSPC when the new connection is
        /// registered with the reactor) does not end the socket, nor does any
        /// other error of one connection; only a broken listener or tokio
        /// itself does. Filling the real limit would disturb every process of
        /// the user, so this asks `passing` directly.
        #[test]
        fn only_a_broken_listener_ends_the_serving() {
            let os = std::io::Error::from_raw_os_error;
            for code in [
                libc::ENOSPC,
                libc::EMFILE,
                libc::ENFILE,
                libc::ENOMEM,
                libc::ECONNABORTED,
                libc::EPERM,
            ] {
                assert!(passing(&os(code)), "{} ends the serving", os(code));
            }
            for code in [
                libc::EBADF,
                libc::EINVAL,
                libc::ENOTSOCK,
                libc::EOPNOTSUPP,
                libc::EFAULT,
            ] {
                assert!(!passing(&os(code)), "{} does not end it", os(code));
            }
            assert!(!passing(&std::io::Error::other("the runtime shuts down")));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn ancestry() {
            let me = std::process::id();
            assert!(super::super::descends_from(me, me));
            let parent = super::super::parent_of(me).unwrap();
            assert!(super::super::descends_from(me, parent));
            assert!(!super::super::descends_from(parent, me));
        }
    }
}

#[cfg(unix)]
pub use unix::{
    NOT_RUNNING, Reply, bind, call, follow, request_line, serve, serve_on, token_ok, write_token,
};
