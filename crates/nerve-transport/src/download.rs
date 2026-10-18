//! One redirecting HTTP(S) download, shared by the node's `update` (a release
//! program and its `SHA256SUMS`) and the center's one-click install of the
//! action checker's local model (a llama.cpp build and a model file of a few
//! gigabytes).
//!
//! It streams the body to a writer, so a large file never sits in memory. It
//! follows up to [`Options::hops`] redirects and never from https to http,
//! goes through the proxy `HTTPS_PROXY` names for https, caps the body at
//! [`Options::max`], and gives up on a connection that sends nothing for
//! [`Options::idle`] (a peer that vanished without a FIN would otherwise
//! hold the download for good). Errors name the host, not the whole address,
//! which may carry a signed query.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use nerve_proto::link::CenterUrl;

/// How a download is bounded.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The most bytes the body may have.
    pub max: u64,
    /// The longest the connection may stay silent: while waiting for the
    /// head, and between two reads of the body.
    pub idle: Duration,
    /// The most redirects followed.
    pub hops: usize,
    /// Set to `true` to stop the download; the next read returns an error.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Options {
    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }
}

/// The largest response head read.
const HEAD_MAX: usize = 64 * 1024;

/// Downloads `url` into `out`, following redirects. `on_progress(done,
/// total)` is called as bytes arrive; `total` is the `Content-Length`, when
/// the server sends one. Returns the number of body bytes written.
pub async fn fetch(
    url: &str,
    out: &mut (dyn Write + Send),
    opts: &Options,
    on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
) -> Result<u64, String> {
    let mut url = url.to_string();
    for _ in 0..=opts.hops {
        let (at, target) = split_url(&url)?;
        let proxy = if at.tls {
            crate::net::Proxy::from_env(&at.host)?
        } else {
            None
        };
        let mut io = crate::net::open(&at, None, proxy.as_ref()).await?;
        let req = format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\nUser-Agent: nerve/{}\r\n\r\n",
            at.authority(),
            env!("CARGO_PKG_VERSION")
        );
        io.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("{}: {e}", at.host))?;
        let head = read_head(&mut io, opts.idle)
            .await
            .map_err(|e| format!("{}: {e}", at.host))?;
        match head.status {
            200 => {
                return read_body(&mut io, head, out, opts, on_progress)
                    .await
                    .map_err(|e| format!("{}: {e}", at.host));
            }
            301 | 302 | 303 | 307 | 308 => {
                let to = head
                    .location
                    .ok_or_else(|| format!("{} redirects without a Location", at.host))?;
                url = next_url(&at, &to)?;
            }
            s => return Err(format!("{} answered HTTP {s}", at.host)),
        }
    }
    Err("too many redirects".into())
}

/// Where a redirect from `at` to `location` goes: made absolute, and refused
/// when it would leave https for http.
pub fn next_url(at: &CenterUrl, location: &str) -> Result<String, String> {
    let next = if location.contains("://") {
        location.to_string()
    } else if location.starts_with('/') {
        format!(
            "{}://{}{location}",
            if at.tls { "https" } else { "http" },
            at.authority()
        )
    } else {
        return Err(format!("{} redirects to a relative place", at.host));
    };
    if at.tls && !next.to_ascii_lowercase().starts_with("https://") {
        return Err(format!("{} redirects from https to http", at.host));
    }
    Ok(next)
}

/// The server and the request target (path and query) of an http(s) URL.
pub fn split_url(url: &str) -> Result<(CenterUrl, String), String> {
    let scheme_end = url.find("://").ok_or("not an http(s) address")?;
    let rest = &url[scheme_end + 3..];
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let mut target = rest[end..].to_string();
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    let at = CenterUrl::parse(&format!("{}{}", &url[..scheme_end + 3], &rest[..end]))
        .map_err(|_| "not an http(s) address".to_string())?;
    Ok((at, target))
}

struct Head {
    status: u16,
    length: Option<u64>,
    location: Option<String>,
    chunked: bool,
    /// Body bytes read together with the head.
    rest: Vec<u8>,
}

async fn read_some<R: AsyncRead + Unpin>(
    io: &mut R,
    buf: &mut [u8],
    idle: Duration,
) -> Result<usize, String> {
    tokio::time::timeout(idle, io.read(buf))
        .await
        .map_err(|_| format!("no data for {} s; the download stalled", idle.as_secs()))?
        .map_err(|e| e.to_string())
}

async fn read_head<R: AsyncRead + Unpin>(io: &mut R, idle: Duration) -> Result<Head, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf[..end + 4]) {
                Ok(httparse::Status::Complete(_)) => {}
                _ => return Err("malformed HTTP answer".into()),
            }
            let header = |name: &str| {
                resp.headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(name))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .map(|v| v.trim().to_string())
            };
            return Ok(Head {
                status: resp.code.unwrap_or(0),
                length: header("content-length").and_then(|v| v.parse().ok()),
                location: header("location"),
                chunked: header("transfer-encoding")
                    .is_some_and(|v| v.to_ascii_lowercase().contains("chunked")),
                rest: buf[end + 4..].to_vec(),
            });
        }
        if buf.len() > HEAD_MAX {
            return Err("the answer's head is too large".into());
        }
        let n = read_some(io, &mut chunk, idle).await?;
        if n == 0 {
            return Err("the connection closed before the answer's head".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn read_body<R: AsyncRead + Unpin>(
    io: &mut R,
    head: Head,
    out: &mut (dyn Write + Send),
    opts: &Options,
    on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
) -> Result<u64, String> {
    if head.length.is_some_and(|l| l > opts.max) {
        return Err("answer over the size limit".into());
    }
    let mut done = 0u64;
    let mut put = |data: &[u8], done: &mut u64| -> Result<(), String> {
        *done += data.len() as u64;
        if *done > opts.max {
            return Err("answer over the size limit".into());
        }
        out.write_all(data).map_err(|e| e.to_string())
    };
    if head.chunked {
        dechunk(io, head.rest, opts.idle, opts.cancel.clone(), &mut |d| {
            put(d, &mut done)?;
            on_progress(done, None);
            Ok(())
        })
        .await?;
        return Ok(done);
    }
    let total = head.length;
    put(&head.rest, &mut done)?;
    on_progress(done, total);
    let mut chunk = vec![0u8; 64 * 1024];
    while total.is_none_or(|t| done < t) {
        if opts.cancelled() {
            return Err("the download was cancelled".into());
        }
        let n = read_some(io, &mut chunk, opts.idle).await?;
        if n == 0 {
            break;
        }
        let take = match total {
            Some(t) => n.min((t - done) as usize),
            None => n,
        };
        put(&chunk[..take], &mut done)?;
        on_progress(done, total);
    }
    if total.is_some_and(|t| done < t) {
        return Err("the answer ended before its Content-Length".into());
    }
    Ok(done)
}

/// Decodes a chunked body (RFC 9112 §7.1) as it arrives, handing each piece
/// to `put`. Extensions and trailers are skipped.
async fn dechunk<R: AsyncRead + Unpin>(
    io: &mut R,
    mut buf: Vec<u8>,
    idle: Duration,
    cancel: Option<Arc<AtomicBool>>,
    put: &mut (dyn FnMut(&[u8]) -> Result<(), String> + Send),
) -> Result<(), String> {
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        if cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err("the download was cancelled".into());
        }
        // The size line.
        let eol = loop {
            if let Some(p) = buf.windows(2).position(|w| w == b"\r\n") {
                break p;
            }
            if buf.len() > 1024 {
                return Err("malformed chunked answer".into());
            }
            let n = read_some(io, &mut chunk, idle).await?;
            if n == 0 {
                return Err("the chunked answer was cut short".into());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let line = std::str::from_utf8(&buf[..eol]).map_err(|_| "malformed chunked answer")?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "malformed chunked answer".to_string())?;
        buf.drain(..eol + 2);
        if size == 0 {
            return Ok(());
        }
        // The chunk and its CRLF.
        let mut left = size;
        while left > 0 {
            if buf.is_empty() {
                let n = read_some(io, &mut chunk, idle).await?;
                if n == 0 {
                    return Err("the chunked answer was cut short".into());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let take = left.min(buf.len());
            put(&buf[..take])?;
            buf.drain(..take);
            left -= take;
        }
        while buf.len() < 2 {
            let n = read_some(io, &mut chunk, idle).await?;
            if n == 0 {
                return Err("the chunked answer was cut short".into());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if &buf[..2] != b"\r\n" {
            return Err("malformed chunked answer".into());
        }
        buf.drain(..2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    /// A loopback server that answers each connection with what `answer`
    /// returns for the request's path: the bytes to send, and whether to hold
    /// the connection open and silent afterwards.
    fn serve(answer: fn(&str) -> (Vec<u8>, bool)) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut c) = conn else { break };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let n = c.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (bytes, hold) = answer(&path);
                    let _ = c.write_all(&bytes);
                    if hold {
                        std::thread::sleep(Duration::from_secs(30));
                    }
                });
            }
        });
        port
    }

    fn ok(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn opts() -> Options {
        Options {
            max: 1 << 20,
            idle: Duration::from_secs(2),
            hops: 6,
            cancel: None,
        }
    }

    async fn get(url: &str, o: &Options) -> Result<Vec<u8>, String> {
        let mut v = Vec::new();
        fetch(url, &mut v, o, &mut |_, _| {}).await.map(|_| v)
    }

    #[tokio::test]
    async fn a_redirect_is_followed_and_a_chunked_body_decoded() {
        let port = serve(|p| {
            match p {
            "/a" => (
                b"HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n".to_vec(),
                false,
            ),
            "/b" => (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n"
                    .to_vec(),
                false,
            ),
            _ => (
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
                false,
            ),
        }
        });
        let body = get(&format!("http://127.0.0.1:{port}/a"), &opts())
            .await
            .unwrap();
        assert_eq!(body, b"hello world");
        let e = get(&format!("http://127.0.0.1:{port}/zz"), &opts())
            .await
            .unwrap_err();
        assert!(e.contains("answered HTTP 404"), "{e}");
    }

    #[tokio::test]
    async fn a_short_or_oversized_body_is_refused() {
        let port = serve(|p| match p {
            // Says 100 bytes, sends 5, closes.
            "/short" => (
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello".to_vec(),
                false,
            ),
            _ => (ok(&"x".repeat(5000)), false),
        });
        let e = get(&format!("http://127.0.0.1:{port}/short"), &opts())
            .await
            .unwrap_err();
        assert!(e.contains("ended before its Content-Length"), "{e}");
        let small = Options { max: 100, ..opts() };
        let e = get(&format!("http://127.0.0.1:{port}/big"), &small)
            .await
            .unwrap_err();
        assert!(e.contains("size limit"), "{e}");
    }

    /// A server that sends the head and a few bytes, then nothing, is given
    /// up on after `idle` instead of holding the download for good (review r2,
    /// finding 5).
    #[tokio::test]
    async fn a_stalled_download_ends() {
        let port = serve(|p| match p {
            // The head and ten bytes, then silence with the connection open.
            "/body" => (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789".to_vec(),
                true,
            ),
            // Nothing at all.
            _ => (Vec::new(), true),
        });
        let o = Options {
            idle: Duration::from_millis(300),
            ..opts()
        };
        for path in ["/body", "/head"] {
            let t = std::time::Instant::now();
            let e = get(&format!("http://127.0.0.1:{port}{path}"), &o)
                .await
                .unwrap_err();
            assert!(e.contains("stalled"), "{path}: {e}");
            assert!(t.elapsed() < Duration::from_secs(5), "{path}");
        }
    }

    #[test]
    fn redirects_never_leave_https() {
        let (at, _) = split_url("https://github.com/x").unwrap();
        assert_eq!(
            next_url(&at, "https://cdn.example/y").unwrap(),
            "https://cdn.example/y"
        );
        assert_eq!(next_url(&at, "/z").unwrap(), "https://github.com/z");
        assert!(
            next_url(&at, "http://cdn.example/y")
                .unwrap_err()
                .contains("https to http")
        );
        assert!(next_url(&at, "HTTP://cdn.example/y").is_err());
        assert!(next_url(&at, "relative").is_err());
        let (plain, _) = split_url("http://127.0.0.1:9/x").unwrap();
        assert!(next_url(&plain, "http://127.0.0.1:9/y").is_ok());
    }
}
