//! Just enough HTTP/1.1 for Nerve: the center's listeners read one request per
//! connection (pairing, the WebSocket upgrade, the web UI and the MCP
//! endpoint), and a node posts its pairing request.
//!
//! Connections are not kept alive: every response carries `Connection: close`.
//! That keeps the parser small and is plenty for the traffic these endpoints see.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest request or response head read.
pub const HEAD_BYTES: usize = 16 * 1024;
/// How long a peer may take to send its request head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path without the query.
    pub path: String,
    pub query: String,
    /// Header names lowercased; a repeated header keeps its last value.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The value of `key` in the query string, percent-decoded.
    pub fn query_param(&self, key: &str) -> Option<String> {
        param(&self.query, key)
    }

    /// The value of `key` in an `application/x-www-form-urlencoded` body,
    /// decoded the same way.
    pub fn form_param(&self, key: &str) -> Option<String> {
        param(&String::from_utf8_lossy(&self.body), key)
    }

    /// The bearer token of `Authorization`, if any.
    pub fn bearer(&self) -> Option<&str> {
        let v = self.header("authorization")?;
        let (scheme, token) = v.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then_some(token.trim())
    }

    pub fn is_upgrade(&self) -> bool {
        self.header("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    }
}

fn param(encoded: &str, key: &str) -> Option<String> {
    encoded.split('&').find_map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        (k == key).then(|| pct_decode(v))
    })
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads up to the blank line ending a head. Returns the head and whatever
/// was read past it.
async fn read_head<R: AsyncRead + Unpin>(io: &mut R) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((buf, rest));
        }
        if buf.len() > HEAD_BYTES {
            return Err("HTTP head over 16 KiB".into());
        }
        let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before the HTTP head ended".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Reads one request, its body capped at `max_body` bytes. Chunked request
/// bodies are refused; every Nerve client sends `Content-Length`.
pub async fn read_request<R: AsyncRead + Unpin>(
    io: &mut R,
    max_body: usize,
) -> Result<Request, String> {
    let (head, mut rest) = tokio::time::timeout(HEAD_TIMEOUT, read_head(io))
        .await
        .map_err(|_| "timed out waiting for the HTTP request".to_string())??;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("malformed HTTP request".into()),
    }
    let target = req.path.unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut map = BTreeMap::new();
    for h in req.headers.iter() {
        map.insert(
            h.name.to_ascii_lowercase(),
            String::from_utf8_lossy(h.value).trim().to_string(),
        );
    }
    let mut out = Request {
        method: req.method.unwrap_or("").to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers: map,
        body: Vec::new(),
    };
    if out.header("transfer-encoding").is_some() {
        return Err("chunked request bodies are not supported".into());
    }
    let len: usize = match out.header("content-length") {
        None => 0,
        Some(v) => v.parse().map_err(|_| "bad Content-Length".to_string())?,
    };
    if len > max_body {
        return Err(format!("request body of {len} bytes over the limit"));
    }
    if rest.len() > len {
        rest.truncate(len);
    }
    let mut body = rest;
    while body.len() < len {
        let mut chunk = vec![0u8; (len - body.len()).min(64 * 1024)];
        let n = tokio::time::timeout(HEAD_TIMEOUT, io.read(&mut chunk))
            .await
            .map_err(|_| "timed out reading the request body".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed inside the request body".into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    out.body = body;
    Ok(out)
}

/// A response to write.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body: body.into(),
        }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Response {
        Response::new(status, "application/json", v.to_string())
    }

    pub fn text(status: u16, s: &str) -> Response {
        Response::new(status, "text/plain; charset=utf-8", s.as_bytes().to_vec())
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Response {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, io: &mut W) -> std::io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (k, v) in &self.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
            self.body.len()
        ));
        io.write_all(head.as_bytes()).await?;
        io.write_all(&self.body).await?;
        io.flush().await
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// A response a client read.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    pub status: u16,
    /// The `Location` header, which a redirect carries.
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// Sends `POST path` with a JSON body over `io` and reads the answer, its body
/// capped at `max_body`.
pub async fn post_json<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    path: &str,
    body: &serde_json::Value,
    max_body: usize,
) -> Result<ClientResponse, String> {
    let body = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: nerve/{}\r\n\r\n{body}",
        body.len(),
        env!("CARGO_PKG_VERSION")
    );
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    read_response(io, max_body).await
}

/// Sends `GET target` (a path with its query) over `io` and reads the
/// answer, its body capped at `max_body`. A redirect is returned as it is,
/// with its `location`.
pub async fn get<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    target: &str,
    max_body: usize,
) -> Result<ClientResponse, String> {
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\nUser-Agent: nerve/{}\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    io.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    read_response(io, max_body).await
}

/// Reads an answer to a request sent with `Connection: close`: up to its
/// `Content-Length`, or to the end of the connection; a chunked body is
/// decoded.
async fn read_response<S: AsyncRead + Unpin>(
    io: &mut S,
    max_body: usize,
) -> Result<ClientResponse, String> {
    let (head, rest) = tokio::time::timeout(HEAD_TIMEOUT, read_head(io))
        .await
        .map_err(|_| "timed out waiting for the answer".to_string())??;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&head) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err("malformed HTTP answer".into()),
    }
    let status = resp.code.unwrap_or(0);
    let header = |name: &str| {
        resp.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(|v| v.trim().to_string())
    };
    let len = header("content-length").and_then(|v| v.parse::<usize>().ok());
    let chunked = header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let location = header("location");
    if len.is_some_and(|l| l > max_body) {
        return Err("answer over the size limit".into());
    }
    let mut body = rest;
    let mut chunk = [0u8; 8192];
    loop {
        if len.is_some_and(|l| body.len() >= l) {
            break;
        }
        if body.len() > max_body {
            return Err("answer over the size limit".into());
        }
        let n = tokio::time::timeout(HEAD_TIMEOUT, io.read(&mut chunk))
            .await
            .map_err(|_| "timed out reading the answer".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if let Some(l) = len {
        if body.len() < l {
            return Err("the answer ended before its Content-Length".into());
        }
        body.truncate(l);
    } else if chunked {
        body = dechunk(&body).ok_or("malformed chunked answer")?;
    }
    Ok(ClientResponse {
        status,
        location,
        body,
    })
}

/// A chunked body (RFC 9112 §7.1) without its framing; `None` when it is cut
/// short or malformed. Extensions and trailers are skipped.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(b.len());
    loop {
        let eol = find(b, b"\r\n")?;
        let size = std::str::from_utf8(&b[..eol]).ok()?;
        let size = size.split(';').next()?.trim();
        let n = usize::from_str_radix(size, 16).ok()?;
        b = &b[eol + 2..];
        if n == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..n)?);
        b = b.get(n..)?.strip_prefix(b"\r\n")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_requests_and_answers() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            post_json(
                &mut a,
                "c.example",
                "/nerve/v0/pair?x=a%20b",
                &serde_json::json!({"code": "abc"}),
                1024,
            )
            .await
            .unwrap()
        });
        let req = read_request(&mut b, 1024).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/nerve/v0/pair");
        assert_eq!(req.query_param("x").as_deref(), Some("a b"));
        assert_eq!(req.header("Content-Type"), Some("application/json"));
        let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(v["code"], "abc");
        Response::json(201, &serde_json::json!({"ok": true}))
            .write(&mut b)
            .await
            .unwrap();
        let resp = client.await.unwrap();
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, br#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn refuses_big_bodies_and_chunks() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\n")
            .await
            .unwrap();
        assert!(read_request(&mut b, 10).await.is_err());
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        assert!(read_request(&mut b, 10).await.is_err());
    }

    #[tokio::test]
    async fn get_reads_lengths_chunks_and_redirects() {
        async fn answer(raw: &'static [u8], max: usize) -> Result<ClientResponse, String> {
            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let req = read_request(&mut b, 0).await.unwrap();
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, "/a/b");
                assert_eq!(req.query_param("x").as_deref(), Some("1"));
                b.write_all(raw).await.unwrap();
            });
            let r = get(&mut a, "h.example", "/a/b?x=1", max).await;
            server.await.unwrap();
            r
        }
        let r = answer(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef", 10)
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"abc"[..]));
        let r = answer(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
            64,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"abcde");
        let r = answer(
            b"HTTP/1.1 302 Found\r\nLocation: /next?s=1\r\nContent-Length: 0\r\n\r\n",
            10,
        )
        .await
        .unwrap();
        assert_eq!((r.status, r.location.as_deref()), (302, Some("/next?s=1")));
        // Too big, cut short, or a broken chunk: an error, not a short body.
        for raw in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc",
        ] {
            assert!(
                answer(raw, 10).await.is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn bearer_and_decode() {
        let mut r = Request {
            method: "GET".into(),
            path: "/".into(),
            query: "a=%41%zz+b".into(),
            headers: BTreeMap::new(),
            body: vec![],
        };
        r.headers
            .insert("authorization".into(), "Bearer  tok ".into());
        assert_eq!(r.bearer(), Some("tok"));
        assert_eq!(r.query_param("a").as_deref(), Some("A%zz b"));
        // A form body decodes like a query string.
        r.body = b"password=p%26w%3Dd+x&next=%2F".to_vec();
        assert_eq!(r.form_param("password").as_deref(), Some("p&w=d x"));
        assert_eq!(r.form_param("next").as_deref(), Some("/"));
        assert_eq!(r.form_param("missing"), None);
        assert_eq!(reason(303), "See Other");
    }
}
