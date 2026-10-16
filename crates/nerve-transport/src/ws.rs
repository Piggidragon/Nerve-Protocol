//! The WebSocket under the node link: the node dials, the center accepts.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::USER_AGENT;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use nerve_proto::link::CenterUrl;
use nerve_proto::{CONNECT_PATH, NODE_HEADER};

use crate::http::Request;
use crate::net::{BoxIo, Proxy};

pub use tokio_tungstenite::tungstenite::Message as WsMessage;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Text frames are capped at the message limit, binary frames are far smaller.
pub fn config(max_message: usize) -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message))
}

/// Whether a read error comes from what the peer sent (a frame over the
/// limit, a broken frame) rather than from the connection. Such a frame would
/// break the next connection the same way, so the link is not resumed over it
/// (docs/dev/spec/protocol.md §4.9).
pub fn broken_frame(e: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error;
    use tokio_tungstenite::tungstenite::error::ProtocolError;
    match e {
        Error::Capacity(_) | Error::Utf8(_) | Error::AttackAttempt => true,
        Error::Protocol(p) => !matches!(p, ProtocolError::ResetWithoutClosingHandshake),
        _ => false,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// HTTP 401 on the upgrade: the center does not know this node (any more).
    Unknown,
    Other(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Unknown => write!(f, "the center does not know this node"),
            ConnectError::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Opens the node link's WebSocket to `url`, naming the node in `Nerve-Node`.
pub async fn connect(
    url: &CenterUrl,
    pin: Option<&str>,
    proxy: Option<&Proxy>,
    node_id: &str,
    max_message: usize,
) -> Result<WebSocketStream<BoxIo>, ConnectError> {
    connect_pins(url, pin.as_slice(), proxy, node_id, max_message).await
}

/// [`connect`] to a center that may present any of `pins`
/// ([`crate::net::open_pins`]).
pub async fn connect_pins(
    url: &CenterUrl,
    pins: &[&str],
    proxy: Option<&Proxy>,
    node_id: &str,
    max_message: usize,
) -> Result<WebSocketStream<BoxIo>, ConnectError> {
    connect_pins_seen(url, pins, proxy, node_id, max_message)
        .await
        .map(|(ws, _)| ws)
}

/// [`connect_pins`], also giving the pin of the certificate the center
/// showed ([`crate::net::open_pins_seen`]).
pub async fn connect_pins_seen(
    url: &CenterUrl,
    pins: &[&str],
    proxy: Option<&Proxy>,
    node_id: &str,
    max_message: usize,
) -> Result<(WebSocketStream<BoxIo>, Option<String>), ConnectError> {
    let (io, seen) = crate::net::open_pins_seen(url, pins, proxy)
        .await
        .map_err(ConnectError::Other)?;
    let mut req = url
        .ws(CONNECT_PATH)
        .into_client_request()
        .map_err(|e| ConnectError::Other(e.to_string()))?;
    let id = HeaderValue::from_str(node_id)
        .map_err(|_| ConnectError::Other("the node id is not a header value".into()))?;
    req.headers_mut().insert(NODE_HEADER, id);
    if let Ok(ua) = HeaderValue::from_str(&format!("nerve-node/{}", env!("CARGO_PKG_VERSION"))) {
        req.headers_mut().insert(USER_AGENT, ua);
    }
    let handshake = tokio_tungstenite::client_async_with_config(req, io, Some(config(max_message)));
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
        Err(_) => Err(ConnectError::Other(
            "the WebSocket handshake timed out".into(),
        )),
        Ok(Ok((ws, _))) => Ok((ws, seen)),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
            let status = resp.status().as_u16();
            if status == 401 {
                Err(ConnectError::Unknown)
            } else {
                Err(ConnectError::Other(format!(
                    "the center answered {status} instead of a WebSocket"
                )))
            }
        }
        Ok(Err(e)) => Err(ConnectError::Other(e.to_string())),
    }
}

/// Answers an upgrade request the caller already read and checked, and hands
/// back the WebSocket.
pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    req: &Request,
    max_message: usize,
) -> Result<WebSocketStream<S>, String> {
    let key = req
        .header("sec-websocket-key")
        .ok_or("no Sec-WebSocket-Key")?;
    if req.header("sec-websocket-version") != Some("13") {
        return Err("unsupported WebSocket version".into());
    }
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    io.write_all(resp.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    io.flush().await.map_err(|e| e.to_string())?;
    Ok(WebSocketStream::from_raw_socket(io, Role::Server, Some(config(max_message))).await)
}
