//! Local control sockets: how `nerve-node`'s CLI talks to the running node
//! (docs/dev/spec/node-local.md).
//!
//! One JSON object per line. The client sends `{"method", "params"}`; the
//! server answers with one line `{"ok": value}` or `{"error": "text"}`, or, for
//! a following call, with several `{"item": value}` lines until it closes.
//!
//! On Unix the socket is created 0600 in a 0700 folder, and every peer's
//! credentials are read: only the socket's own user or root may talk to it.
//! Windows named pipes with an owner-only ACL are not done in 0.0.1; there the
//! CLI works on the config files directly (see `nerve-node`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtlRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Who is on the other end of a control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: Option<u32>,
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

    use super::{CtlRequest, Peer};

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
    pub async fn serve_on<F, Fut>(listener: UnixListener, handler: F) -> std::io::Result<()>
    where
        F: Fn(CtlRequest, Peer) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Reply> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let me = crate::net::euid();
        loop {
            let (stream, _) = listener.accept().await?;
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

    /// One call: sends the request and returns the answer.
    pub async fn call(path: &Path, method: &str, params: Value) -> Result<Value, String> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|_| NOT_RUNNING.to_string())?;
        let (r, mut w) = stream.into_split();
        write_line(&mut w, &json!({"method": method, "params": params}))
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
        write_line(&mut w, &json!({"method": method, "params": params}))
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
pub use unix::{NOT_RUNNING, Reply, bind, call, follow, serve, serve_on};
