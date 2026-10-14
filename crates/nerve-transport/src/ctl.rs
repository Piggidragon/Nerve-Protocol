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
//! Windows has a named pipe instead, with the same lines on it
//! ([`serve_stream`], [`call_on`]); `nerve-node` makes it and checks who
//! is on the other end.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtlRequest {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    /// What the client read from [`token_file`], when it could. The pipe on
    /// Windows has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// The longest request line read.
const LINE_BYTES: usize = 1024 * 1024;

/// How long a connection may wait for its request line. A caller sends it
/// at once.
const IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// How many connections are served at once; one over it is answered with
/// [`BUSY`] and closed. With a request per connection and [`IDLE`] this
/// keeps a process of the node's user, which can connect, from using up
/// the node's descriptors with idle connections. It can still fill the
/// places for a while; the CLI is then told the node is busy and writes
/// nothing, and the way to stop the node anyway is to stop its process.
pub const MAX_CONNECTIONS: usize = 64;

/// What a handler sends back: one answer, or items of a following call.
pub enum Reply {
    Ok(Value),
    Err(String),
    /// Items until the sender is dropped.
    Follow(mpsc::Receiver<Value>),
    /// A connection the handler keeps (a capability provider's): `{"ok":
    /// value}` first, then each value of `out` as a line to the client, and
    /// each line the client sends, a JSON value of at most [`LINE_BYTES`],
    /// to `inbound`. It ends when the client closes or sends a line that is
    /// too long or no JSON, or when the handler drops the sender of `out` or
    /// the receiver of `inbound`; `inbound` is dropped then, which tells
    /// the handler.
    Session {
        ok: Value,
        out: mpsc::Receiver<Value>,
        inbound: mpsc::Sender<Value>,
    },
}

/// What [`read_line_within`] read.
enum Line {
    /// A line, without its line break.
    Text(String),
    /// The stream ended before another byte came.
    End,
    /// The line passed the limit, or was not UTF-8.
    Bad,
}

/// Reads one line of at most `max` bytes, its line break included, into
/// `buf`, which holds what an earlier call cancelled in a `select!` read of
/// it already. A last line without a line break counts as a line.
async fn read_line_within<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<Line> {
    let room = (max + 1).saturating_sub(buf.len()) as u64;
    (&mut *r).take(room).read_until(b'\n', buf).await?;
    if buf.len() > max {
        return Ok(Line::Bad);
    }
    // Without a line break and within the limit, the stream ended.
    if buf.is_empty() {
        return Ok(Line::End);
    }
    let mut text = std::mem::take(buf);
    if text.last() == Some(&b'\n') {
        text.pop();
    }
    Ok(String::from_utf8(text).map_or(Line::Bad, Line::Text))
}

/// Error when nothing listens.
pub const NOT_RUNNING: &str = "not running";

/// Error when a node listens but takes no connection now: its places are
/// taken, or its queue is full (EAGAIN).
pub const BUSY: &str = "the node does not take connections now; try again";

/// Serves one connection whose caller is `peer` (what the transport could
/// tell of it): one request, answered, and the connection ends. One that
/// sends nothing for [`IDLE`] ends unanswered.
pub async fn serve_stream<S, P, F, Fut>(stream: S, peer: P, handler: Arc<F>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite,
    F: Fn(CtlRequest, P) -> Fut,
    Fut: std::future::Future<Output = Reply>,
{
    serve_stream_within(stream, peer, handler, IDLE).await
}

/// [`serve_stream`], with `idle` as the time the request may take.
async fn serve_stream_within<S, P, F, Fut>(
    stream: S,
    peer: P,
    handler: Arc<F>,
    idle: std::time::Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite,
    F: Fn(CtlRequest, P) -> Fut,
    Fut: std::future::Future<Output = Reply>,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r);
    let mut buf = Vec::new();
    // One request per connection: every client sends one, and a connection
    // that stays for more would be a place held. Only a session (a
    // provider's) stays, and only after the handler took it.
    // No request in time, like none at all, ends the connection; so does
    // one that is too long.
    let line = match tokio::time::timeout(idle, read_line_within(&mut lines, LINE_BYTES, &mut buf))
        .await
    {
        Ok(read) => match read? {
            Line::Text(t) => t,
            Line::End | Line::Bad => return Ok(()),
        },
        Err(_) => return Ok(()),
    };
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
        }
        Reply::Session {
            ok,
            mut out,
            inbound,
        } => {
            write_line(&mut w, &json!({"ok": ok})).await?;
            // Each direction runs on its own: a write that waits for the
            // client to read must not stop the reading. A client that answers
            // one line before it reads the next would else wait on the node
            // writing while the node waits on it, for good, as soon as a
            // line in each direction fills the socket's buffer.
            let reading = async {
                loop {
                    let Line::Text(text) =
                        read_line_within(&mut lines, LINE_BYTES, &mut buf).await?
                    else {
                        return Ok(());
                    };
                    let Ok(v) = serde_json::from_str::<Value>(&text) else {
                        return Ok(());
                    };
                    if inbound.send(v).await.is_err() {
                        return Ok::<(), std::io::Error>(());
                    }
                }
            };
            let writing = async {
                while let Some(v) = out.recv().await {
                    write_line(&mut w, &v).await?;
                }
                Ok::<(), std::io::Error>(())
            };
            // Whichever ends first ends the session.
            tokio::select! {
                r = reading => r?,
                r = writing => r?,
            }
        }
    }
    Ok(())
}

async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, v: &Value) -> std::io::Result<()> {
    let mut s = v.to_string();
    s.push('\n');
    w.write_all(s.as_bytes()).await?;
    w.flush().await
}

/// One call on a connection made already: sends the request and returns
/// the answer.
pub async fn call_on<S: AsyncRead + AsyncWrite>(
    stream: S,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    call_stream(stream, json!({"method": method, "params": params}), |e| {
        e.to_string()
    })
    .await
}

/// [`call_on`] with the whole `request`, saying an error after the connect
/// with `io_error`.
async fn call_stream<S: AsyncRead + AsyncWrite>(
    stream: S,
    request: Value,
    io_error: fn(&std::io::Error) -> String,
) -> Result<Value, String> {
    let (r, mut w) = tokio::io::split(stream);
    // A node over its places answers BUSY and closes, possibly before the
    // request is written: read the answer all the same.
    let sent = write_line(&mut w, &request).await;
    let mut line = String::new();
    BufReader::new(r.take(LINE_BYTES as u64))
        .read_line(&mut line)
        .await
        .map_err(|e| io_error(&e))?;
    if line.is_empty()
        && let Err(e) = sent
    {
        return Err(io_error(&e));
    }
    answer(&line)
}

fn answer(line: &str) -> Result<Value, String> {
    let v: Value =
        serde_json::from_str(line).map_err(|_| "the node closed without answering".to_string())?;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    Ok(v.get("ok").cloned().unwrap_or(Value::Null))
}

/// The file that holds the token of the server on the socket `socket`.
pub fn token_file(socket: &std::path::Path) -> std::path::PathBuf {
    socket.with_file_name("ctl.token")
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
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use super::{
        BUSY, CtlRequest, IDLE, MAX_CONNECTIONS, NOT_RUNNING, Peer, Reply, answer, call_stream,
        serve_stream_within, token_file, write_line,
    };

    /// How long [`call`] waits for an answer. The slowest handler, the check
    /// of a sudo password, ends after 30 s itself. A node that does not
    /// accept (it is out of descriptors) never answers a call that sits in
    /// its queue.
    const ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(90);

    /// Error when [`call`] got no answer in time.
    pub const NO_ANSWER: &str = "the node did not answer in time; try again";

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
        serve_limited(listener, handler, IDLE, MAX_CONNECTIONS).await
    }

    /// [`serve_on`], with `idle` as the time a connection may wait for its
    /// request and `max` connections served at once.
    async fn serve_limited<F, Fut>(
        listener: UnixListener,
        handler: F,
        idle: std::time::Duration,
        max: usize,
    ) -> std::io::Result<()>
    where
        F: Fn(CtlRequest, Peer) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Reply> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let places = Arc::new(tokio::sync::Semaphore::new(max));
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
            let Ok(place) = places.clone().try_acquire_owned() else {
                // Said without waiting: the caller has written its request
                // and may find the connection reset when it reads.
                // A fresh connection has room for the line; `writable` only
                // lets tokio learn that.
                if stream.writable().await.is_ok() {
                    let _ = stream.try_write(format!("{}\n", json!({"error": BUSY})).as_bytes());
                }
                continue;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let _place = place;
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
                let _ = serve_stream_within(stream, peer, handler, idle).await;
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

    /// The start of the error for a connect that failed for any other reason.
    pub const CANNOT_CONNECT: &str = "cannot connect to the node's control socket";

    /// What a failed connect means. Only a missing socket (ENOENT) and one
    /// nobody listens on (ECONNREFUSED) say that no node runs: any other
    /// error leaves the node that may run unknown, and a caller that took it
    /// for none would write the change into the file and call it done.
    fn connect_error(e: &std::io::Error) -> String {
        match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                NOT_RUNNING.to_string()
            }
            std::io::ErrorKind::WouldBlock => BUSY.to_string(),
            _ => format!("{CANNOT_CONNECT}: {e}"),
        }
    }

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
        call_within(path, method, params, ANSWER_WAIT).await
    }

    async fn call_within(
        path: &Path,
        method: &str,
        params: Value,
        limit: std::time::Duration,
    ) -> Result<Value, String> {
        tokio::time::timeout(limit, call_unlimited(path, method, params))
            .await
            .unwrap_or_else(|_| Err(NO_ANSWER.to_string()))
    }

    async fn call_unlimited(path: &Path, method: &str, params: Value) -> Result<Value, String> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| connect_error(&e))?;
        call_stream(stream, request_line(path, method, params), io_error).await
    }

    /// What an error after a connect says. A connection the node reset or
    /// closed on the caller is the node over its places.
    fn io_error(e: &std::io::Error) -> String {
        match e.kind() {
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => {
                BUSY.to_string()
            }
            _ => e.to_string(),
        }
    }

    /// Whether the outcome of a call says that a node is there: an answer, a
    /// refusal, a node that takes no connection now or answers too late. Only
    /// a missing socket or a refused connect says none. A connect that failed
    /// for any other reason says nothing either way, and comes back as the
    /// error (a socket path too long, a folder in the way).
    pub fn node_is_there(outcome: &Result<Value, String>) -> Result<bool, String> {
        match outcome {
            Err(e) if e == NOT_RUNNING => Ok(false),
            Err(e) if e.starts_with(CANNOT_CONNECT) => Err(e.clone()),
            _ => Ok(true),
        }
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
            .map_err(|e| connect_error(&e))?;
        let (r, mut w) = stream.into_split();
        let sent = write_line(&mut w, &request_line(path, method, params)).await;
        let mut lines = BufReader::new(r).lines();
        while let Some(line) = lines.next_line().await.map_err(|e| io_error(&e))? {
            let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            if let Some(item) = v.get("item") {
                each(item.clone());
            } else {
                answer(&line)?;
                return Ok(());
            }
        }
        sent.map_err(|e| io_error(&e))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::mpsc;

        /// A session on a real socket does not wedge when the node writes a
        /// line larger than the socket's buffer while the client writes one
        /// too: a client that answers each line before it reads the next
        /// still gets every line, and the node every answer.
        #[tokio::test]
        async fn a_session_reads_while_it_writes_a_large_line() {
            let (client, server) = UnixStream::pair().unwrap();
            let (ends_tx, mut ends_rx) = mpsc::channel(1);
            let handler = Arc::new(move |_: CtlRequest, _: ()| {
                let ends_tx = ends_tx.clone();
                async move {
                    let (out_tx, out) = mpsc::channel(4);
                    let (inbound, in_rx) = mpsc::channel(4);
                    let _ = ends_tx.send((out_tx, in_rx)).await;
                    Reply::Session {
                        ok: json!({}),
                        out,
                        inbound,
                    }
                }
            });
            let task = tokio::spawn(crate::ctl::serve_stream(server, (), handler));
            let (r, mut w) = client.into_split();
            let mut lines = BufReader::new(r).lines();
            w.write_all(b"{\"method\": \"hello\"}\n").await.unwrap();
            let (out_tx, mut in_rx) = ends_rx.recv().await.unwrap();
            assert!(lines.next_line().await.unwrap().is_some());
            let big = "x".repeat(300 * 1024);
            for i in 0..2 {
                out_tx.send(json!({"call": i, "pad": big})).await.unwrap();
            }
            let wedge = std::time::Duration::from_secs(20);
            tokio::time::timeout(wedge, async {
                for i in 0..2 {
                    let line = lines.next_line().await.unwrap().unwrap();
                    let v: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(v["call"], i);
                    let answer = json!({"answer": i, "pad": big});
                    w.write_all(format!("{answer}\n").as_bytes()).await.unwrap();
                }
                for i in 0..2 {
                    assert_eq!(in_rx.recv().await.unwrap()["answer"], i);
                }
            })
            .await
            .expect("the session wedged");
            drop(w);
            drop(lines);
            task.await.unwrap().unwrap();
        }

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

        /// A listener whose queue is full answers `connect` with EAGAIN: the
        /// node runs, it only takes no connection now. That is not "not
        /// running", which sends a caller on to change the file itself.
        #[tokio::test]
        async fn a_node_with_a_full_queue_is_not_taken_for_none() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("ctl.sock");
            let listener = bind(&p).await.unwrap();
            // A backlog of one: a few connections fill it, and nothing
            // accepts them.
            {
                use std::os::unix::io::AsRawFd;
                // SAFETY: listen on a socket this test owns.
                assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
            }
            let mut queued = vec![];
            loop {
                match UnixStream::connect(&p).await {
                    Ok(s) => queued.push(s),
                    Err(e) => {
                        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "{e}");
                        break;
                    }
                }
                assert!(queued.len() < 100, "the queue never filled");
            }
            let busy = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                call(&p, "status", json!({})),
            )
            .await
            .expect("an answer in time");
            assert_eq!(busy, Err(BUSY.to_string()));
            let followed = follow(&p, "status", json!({}), |_| {}).await;
            assert_eq!(followed, Err(BUSY.to_string()));
            // A socket file nobody listens on is no node.
            drop(listener);
            drop(queued);
            // A process forked meanwhile (the descriptor test below forks
            // this binary) holds a copy of the listener until it execs, so
            // the socket may take a moment to be gone.
            let mut gone = call(&p, "status", json!({})).await;
            for _ in 0..200 {
                if gone == Err(NOT_RUNNING.to_string()) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                gone = call(&p, "status", json!({})).await;
            }
            assert_eq!(gone, Err(NOT_RUNNING.to_string()));
            // Any other error says what it is.
            let under_a_file = d.path().join("run/ctl.sock");
            std::fs::write(d.path().join("run"), b"").unwrap();
            let e = call(&under_a_file, "status", json!({})).await.unwrap_err();
            assert!(e.starts_with(CANNOT_CONNECT), "{e}");
            // Only a connect that failed for another reason is no answer to
            // whether a node is there.
            assert_eq!(node_is_there(&Err(e.clone())), Err(e.clone()));
            assert_eq!(node_is_there(&Err(NOT_RUNNING.into())), Ok(false));
            assert_eq!(node_is_there(&Err(BUSY.into())), Ok(true));
            assert_eq!(node_is_there(&Err(NO_ANSWER.into())), Ok(true));
            assert_eq!(node_is_there(&Ok(json!(1))), Ok(true));
            assert_ne!(e, NOT_RUNNING);
        }

        /// A call that sits in the queue of a node that never accepts ends
        /// with its own error, and a connection that sends nothing is closed
        /// by the node.
        #[tokio::test]
        async fn waits_for_an_answer_and_for_a_request_end() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("ctl.sock");
            let silent = bind(&p).await.unwrap();
            // Bounded here, so that a call without its limit fails this test
            // and does not hang it.
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                call_within(
                    &p,
                    "status",
                    json!({}),
                    std::time::Duration::from_millis(200),
                ),
            )
            .await
            .expect("call_within ends by itself");
            assert_eq!(r, Err(NO_ANSWER.to_string()));
            drop(silent);

            let p = d.path().join("idle.sock");
            let listener = bind(&p).await.unwrap();
            tokio::spawn(serve_limited(
                listener,
                |_, _| async { Reply::Ok(json!("up")) },
                std::time::Duration::from_millis(200),
                MAX_CONNECTIONS,
            ));
            let mut idle = UnixStream::connect(&p).await.unwrap();
            let mut byte = [0u8; 1];
            let eof = tokio::time::timeout(std::time::Duration::from_secs(5), idle.read(&mut byte))
                .await
                .expect("the node closes a connection that sends nothing");
            assert_eq!(eof.unwrap(), 0);
            assert_eq!(call(&p, "status", json!({})).await, Ok(json!("up")));
        }

        /// A process that can connect holds no more than `max` places, and a
        /// connection that sends a request every few moments is closed after
        /// its answer, so it cannot stay and use up the node's descriptors.
        #[tokio::test]
        async fn connections_are_bounded_and_serve_one_request() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("ctl.sock");
            let listener = bind(&p).await.unwrap();
            tokio::spawn(serve_limited(
                listener,
                |_, _| async { Reply::Ok(json!("up")) },
                std::time::Duration::from_secs(30),
                2,
            ));
            // Two places held without a word; a call over them is told the
            // node is busy, with the request written or not.
            let held = [
                UnixStream::connect(&p).await.unwrap(),
                UnixStream::connect(&p).await.unwrap(),
            ];
            // Let the node take both before the third comes.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            for _ in 0..20 {
                let r = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    call(&p, "status", json!({})),
                )
                .await
                .expect("the node answers a call over its places");
                assert_eq!(r, Err(BUSY.to_string()));
            }
            // A connection that only listens is told the same and closed.
            let mut told = String::new();
            let mut over = UnixStream::connect(&p).await.unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                over.read_to_string(&mut told),
            )
            .await
            .expect("the node closes the connection")
            .unwrap();
            assert_eq!(told, format!("{{\"error\":\"{BUSY}\"}}\n"));
            // A request too big for the socket's buffer fails its write when
            // the node closes the connection; the answer is read all the
            // same and the failed write is not what the caller is told.
            for _ in 0..5 {
                let r = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    call(&p, "config.write", json!({"config": "x".repeat(4 << 20)})),
                )
                .await
                .expect("the node answers a big call over its places");
                assert_eq!(r, Err(BUSY.to_string()));
            }
            drop(held);
            // A place is free again once its holder is gone.
            let mut v = Err(String::new());
            for _ in 0..100 {
                v = call(&p, "status", json!({})).await;
                if v.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(v, Ok(json!("up")));
            // The connection ends with its answer: a second request on it
            // gets none.
            let mut s = UnixStream::connect(&p).await.unwrap();
            s.write_all(b"{\"method\":\"a\"}\n{\"method\":\"b\"}\n")
                .await
                .unwrap();
            let mut got = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                s.read_to_string(&mut got),
            )
            .await
            .expect("the node closes the connection")
            .unwrap();
            assert_eq!(got, "{\"ok\":\"up\"}\n");
        }

        /// A node that closes a connection on the caller without a word (the
        /// request unread, so the close is a reset or the write breaks) is a
        /// node that does not take the call now.
        #[tokio::test]
        async fn a_connection_closed_on_the_caller_reads_as_busy() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("ctl.sock");
            let listener = bind(&p).await.unwrap();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    drop(stream);
                }
            });
            for _ in 0..10 {
                let r = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    call(&p, "config.write", json!({"config": "x".repeat(4 << 20)})),
                )
                .await
                .expect("the call ends");
                assert_eq!(r, Err(BUSY.to_string()));
            }
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
    CANNOT_CONNECT, NO_ANSWER, bind, call, follow, node_is_there, request_line, serve, serve_on,
    token_ok, write_token,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The lines of the protocol on any stream, as Windows' pipe carries
    /// them: a call gets its answer or its error, a bad line an error, and
    /// the handler sees the peer the transport told.
    #[tokio::test]
    async fn the_lines_on_any_stream() {
        let serve = |server| {
            tokio::spawn(serve_stream(
                server,
                7u32,
                Arc::new(|req: CtlRequest, peer: u32| async move {
                    match req.method.as_str() {
                        "echo" => Reply::Ok(json!({"params": req.params, "peer": peer})),
                        _ => Reply::Err("unknown method".into()),
                    }
                }),
            ))
        };
        let (client, server) = tokio::io::duplex(4096);
        let task = serve(server);
        let v = call_on(client, "echo", json!({"a": 1})).await.unwrap();
        assert_eq!(v, json!({"params": {"a": 1}, "peer": 7}));
        task.await.unwrap().unwrap();
        let (client, server) = tokio::io::duplex(4096);
        serve(server);
        assert_eq!(
            call_on(client, "nope", json!({})).await.unwrap_err(),
            "unknown method"
        );
        // A line that is no request is answered, and the connection ends
        // with its answer.
        let (mut client, server) = tokio::io::duplex(4096);
        let task = serve(server);
        client
            .write_all(b"{\"params\": 1}\n{\"method\": \"echo\"}\n")
            .await
            .unwrap();
        let mut got = String::new();
        client.read_to_string(&mut got).await.unwrap();
        assert!(
            answer(&got).unwrap_err().starts_with("bad request"),
            "{got}"
        );
        assert_eq!(got.lines().count(), 1, "{got}");
        task.await.unwrap().unwrap();
        // A server that reads the call and closes without a word gives no
        // answer.
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut line = String::new();
            let _ = BufReader::new(server).read_line(&mut line).await;
        });
        assert_eq!(
            call_on(client, "echo", json!({})).await.unwrap_err(),
            "the node closed without answering"
        );
    }

    /// A line longer than a request may be ends the connection unanswered,
    /// and so does a connection that sends nothing in time.
    #[tokio::test]
    async fn an_overlong_or_idle_connection_ends_unanswered() {
        let handler = Arc::new(|_: CtlRequest, _: ()| async { Reply::Ok(json!("taken")) });
        let (client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(serve_stream(server, (), handler.clone()));
        let long = "x".repeat(LINE_BYTES + 1);
        let r = call_on(client, "echo", json!({"pad": long})).await;
        assert_eq!(r.unwrap_err(), "the node closed without answering");
        task.await.unwrap().unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve_stream_within(
            server,
            (),
            handler,
            std::time::Duration::from_millis(100),
        ));
        let mut got = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_string(&mut got),
        )
        .await
        .expect("the connection ends")
        .unwrap();
        assert_eq!(got, "");
        task.await.unwrap().unwrap();
    }

    /// A session stays after its answer: lines go both ways until the
    /// client closes, which the handler learns from `inbound`; a line that
    /// is too long or no JSON ends it, and so does the handler dropping its
    /// sender.
    #[tokio::test]
    async fn a_session_carries_lines_both_ways_until_one_side_ends_it() {
        use tokio::io::AsyncBufReadExt;
        type Ends = (mpsc::Sender<Value>, mpsc::Receiver<Value>);
        let (ends_tx, mut ends_rx) = mpsc::channel::<Ends>(4);
        let handler = Arc::new(move |req: CtlRequest, _: ()| {
            let ends_tx = ends_tx.clone();
            async move {
                let (out_tx, out) = mpsc::channel(4);
                let (inbound, in_rx) = mpsc::channel(4);
                let _ = ends_tx.send((out_tx, in_rx)).await;
                Reply::Session {
                    ok: json!({"took": req.method}),
                    out,
                    inbound,
                }
            }
        });
        let start = |handler| {
            let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
            let task = tokio::spawn(serve_stream(server, (), handler));
            (client, task)
        };
        let (client, task) = start(handler.clone());
        let (r, mut w) = tokio::io::split(client);
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"{\"method\": \"hello\"}\n").await.unwrap();
        let (out_tx, mut in_rx) = ends_rx.recv().await.unwrap();
        let first = lines.next_line().await.unwrap().unwrap();
        assert_eq!(answer(&first).unwrap(), json!({"took": "hello"}));
        for i in 0..100 {
            w.write_all(format!("{{\"n\": {i}}}\n").as_bytes())
                .await
                .unwrap();
            assert_eq!(in_rx.recv().await.unwrap(), json!({"n": i}));
            out_tx.send(json!({"back": i})).await.unwrap();
            let line = lines.next_line().await.unwrap().unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap(),
                json!({"back": i})
            );
        }
        // The client goes: the handler hears it.
        drop(w);
        drop(lines);
        assert_eq!(in_rx.recv().await, None);
        task.await.unwrap().unwrap();
        drop(out_tx);

        // A line too long, or one that is no JSON, ends it.
        for bad in ["x".repeat(LINE_BYTES + 1), "not json".to_string()] {
            let (mut client, task) = start(handler.clone());
            client
                .write_all(b"{\"method\": \"hello\"}\n")
                .await
                .unwrap();
            let (_out_tx, mut in_rx) = ends_rx.recv().await.unwrap();
            client.write_all(bad.as_bytes()).await.unwrap();
            client.write_all(b"\n{\"n\": 1}\n").await.unwrap();
            assert_eq!(in_rx.recv().await, None);
            task.await.unwrap().unwrap();
        }

        // The handler drops its sender: the client sees the end.
        let (client, task) = start(handler);
        let (r, mut w) = tokio::io::split(client);
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"{\"method\": \"hello\"}\n").await.unwrap();
        let (out_tx, _in_rx) = ends_rx.recv().await.unwrap();
        assert!(lines.next_line().await.unwrap().is_some());
        drop(out_tx);
        assert_eq!(lines.next_line().await.unwrap(), None);
        task.await.unwrap().unwrap();
    }
}
