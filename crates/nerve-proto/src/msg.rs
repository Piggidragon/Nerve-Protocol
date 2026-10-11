//! Typed `params` of the node link's methods (spec/node-link.md, spec/core.md).
//!
//! What a center sends to a node is parsed with `deny_unknown_fields`: a node
//! acts on these, so a field it does not understand is an error rather than
//! something it silently ignores (D2). What a node sends to a center is read
//! tolerantly.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::descriptor::Detail;

/// Method names, in one place so both ends spell them the same.
pub mod method {
    pub const CHALLENGE: &str = "challenge";
    pub const HELLO: &str = "hello";
    pub const WELCOME: &str = "welcome";
    pub const DESCRIBE: &str = "describe";
    pub const INVOKE: &str = "invoke";
    pub const PROGRESS: &str = "progress";
    pub const CANCEL: &str = "cancel";
    pub const GET: &str = "get";
    pub const SUB: &str = "sub";
    pub const UNSUB: &str = "unsub";
    pub const EVENT: &str = "event";
    pub const STATE: &str = "state";
    pub const STREAM_OPEN: &str = "stream.open";
    pub const STREAM_CLOSE: &str = "stream.close";
    pub const SESSION_END: &str = "session.end";
    pub const BYE: &str = "bye";
}

/// Limits a side announces for what it receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "d_message")]
    pub message_bytes: u64,
    #[serde(default = "d_blob")]
    pub blob_bytes: u64,
    #[serde(default = "d_calls")]
    pub calls: u32,
    #[serde(default = "d_streams")]
    pub streams: u32,
}

fn d_message() -> u64 {
    crate::limits::MESSAGE_BYTES
}
fn d_blob() -> u64 {
    crate::limits::BLOB_BYTES
}
fn d_calls() -> u32 {
    crate::limits::CALLS
}
fn d_streams() -> u32 {
    crate::limits::STREAMS
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            message_bytes: d_message(),
            blob_bytes: d_blob(),
            calls: d_calls(),
            streams: d_streams(),
        }
    }
}

/// The center's first frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// 32 random bytes, lowercase hex.
    pub nonce: String,
    pub center_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Auth {
    /// Ed25519 signature over `connect_message(center_id, nonce)`, lowercase hex.
    pub sig: String,
}

/// The node's answer to the challenge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub node_id: String,
    pub auth: Auth,
    /// Protocol versions the node speaks; 0.0.1 knows only "0".
    pub versions: Vec<String>,
    pub software: Software,
    #[serde(default)]
    pub limits: Limits,
    /// The descriptor revision the node will describe.
    pub rev: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub version: String,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Describe {
    #[serde(default)]
    pub detail: Detail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
}

/// Context a center attaches to a call. It can only narrow what a node does:
/// `tainted` makes a node refuse writes and commands it would allow. Other
/// fields are refused (D8).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ctx {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tainted: bool,
}

/// The longest session id a node accepts.
pub const SESSION_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoke {
    pub cap: String,
    pub action: String,
    #[serde(default)]
    pub args: Map<String, Value>,
    #[serde(default)]
    pub ctx: Ctx,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Blob ids this call's arguments reference, sent as binary frames first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<u32>,
}

impl Invoke {
    /// Checks what serde cannot: the session's length.
    pub fn check(&self) -> Result<(), crate::RpcError> {
        if let Some(s) = &self.ctx.session
            && (s.is_empty() || s.len() > SESSION_BYTES)
        {
            return Err(crate::RpcError::invalid_args(
                "ctx.session must be 1 to 256 bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Progress {
    pub id: Value,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub id: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Get {
    pub cap: String,
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topics {
    pub topics: Vec<String>,
}

/// A parsed topic: `<cap>/<event>`, `<cap>/state` or `<cap>/*`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Topic {
    Event(String, String),
    State(String),
    All(String),
}

impl Topic {
    pub fn parse(s: &str) -> Option<Topic> {
        let (cap, rest) = s.split_once('/')?;
        if cap.is_empty() || rest.is_empty() || rest.contains('/') {
            return None;
        }
        Some(match rest {
            "state" => Topic::State(cap.into()),
            "*" => Topic::All(cap.into()),
            e => Topic::Event(cap.into(), e.into()),
        })
    }

    pub fn cap(&self) -> &str {
        match self {
            Topic::Event(c, _) | Topic::State(c) | Topic::All(c) => c,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub cap: String,
    pub name: String,
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateChange {
    pub cap: String,
    pub seq: u64,
    pub ts: u64,
    pub changed: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOpen {
    pub cap: String,
    pub stream: String,
    #[serde(default)]
    pub params: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamClose {
    pub sid: u32,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnd {
    pub session: String,
}

/// Why a side closes the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByeReason {
    Shutdown,
    Paused,
    Unpaired,
    Revoked,
    Duplicate,
    Replaced,
    UnsupportedVersion,
    ProtocolError,
}

impl ByeReason {
    /// Whether a node stops dialling this center after the bye.
    pub fn stops_node(self) -> bool {
        matches!(
            self,
            ByeReason::Revoked | ByeReason::Unpaired | ByeReason::UnsupportedVersion
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ByeReason::Shutdown => "shutdown",
            ByeReason::Paused => "paused",
            ByeReason::Unpaired => "unpaired",
            ByeReason::Revoked => "revoked",
            ByeReason::Duplicate => "duplicate",
            ByeReason::Replaced => "replaced",
            ByeReason::UnsupportedVersion => "unsupported_version",
            ByeReason::ProtocolError => "protocol_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bye {
    pub reason: ByeReason,
}

/// Lowercase hex, for nonces and signatures.
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(v(p[0])? << 4 | v(p[1])?))
        .collect()
}

/// Milliseconds since the Unix epoch, for `ts`.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invoke_is_strict() {
        let ok: Invoke = serde_json::from_value(json!({
            "cap": "fs", "action": "read", "args": {"path": "/x"},
            "ctx": {"session": "s1", "tainted": true}
        }))
        .unwrap();
        assert!(ok.ctx.tainted);
        assert!(ok.check().is_ok());
        assert!(
            serde_json::from_value::<Invoke>(json!({
                "cap": "fs", "action": "read", "ctx": {"mode": "full"}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<Invoke>(json!({"cap": "fs", "action": "read", "x": 1}))
                .is_err()
        );
        let long = Invoke {
            ctx: Ctx {
                session: Some("s".repeat(257)),
                tainted: false,
            },
            ..ok
        };
        assert!(long.check().is_err());
    }

    #[test]
    fn hello_is_tolerant() {
        let h: Hello = serde_json::from_value(json!({
            "node_id": "n", "auth": {"sig": "00"}, "versions": ["0"],
            "software": {"name": "x", "version": "1"}, "rev": 1, "x-extra": true
        }))
        .unwrap();
        assert_eq!(h.limits, Limits::default());
    }

    #[test]
    fn topics() {
        assert_eq!(
            Topic::parse("exec/exit"),
            Some(Topic::Event("exec".into(), "exit".into()))
        );
        assert_eq!(
            Topic::parse("node/state"),
            Some(Topic::State("node".into()))
        );
        assert_eq!(Topic::parse("fs/*"), Some(Topic::All("fs".into())));
        assert_eq!(Topic::parse("fs"), None);
        assert_eq!(Topic::parse("a/b/c"), None);
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn bye_reasons() {
        let b: Bye = serde_json::from_value(json!({"reason": "unsupported_version"})).unwrap();
        assert!(b.reason.stops_node());
        assert!(!ByeReason::Shutdown.stops_node());
    }
}
