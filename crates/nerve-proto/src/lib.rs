//! Types and codecs of the Nerve Protocol (spec/), without any I/O.
//!
//! Everything a node, a center or a harness binding puts on the wire is defined
//! here once, so both ends of a link share one definition. Parameters a center
//! sends to a node are parsed strictly (unknown fields are errors, spec D2);
//! data a node sends is read tolerantly, since a center must accept newer minor
//! versions and `x-` members.
//!
//! The crate only depends on `serde` and `serde_json`. It is not built as
//! `no_std` in 0.0.1; nothing in it needs more than `alloc`, so that can follow
//! when a constrained node exists.

pub mod base32;
pub mod descriptor;
pub mod error;
pub mod frame;
pub mod link;
pub mod msg;
pub mod rpc;

pub use descriptor::{Capability, Descriptor, Detail, Effect, Exposure};
pub use error::{ErrorCode, RpcError};
pub use rpc::{Id, Message};

/// The protocol version of all of 0.0.x and 0.x (spec/core.md §Versioning).
pub const PROTOCOL_VERSION: &str = "0";

/// The HTTP path a node pairs on.
pub const PAIR_PATH: &str = "/nerve/v0/pair";
/// The HTTP path a node opens its WebSocket link on.
pub const CONNECT_PATH: &str = "/nerve/v0/connect";
/// The upgrade header that names the node on `CONNECT_PATH`.
pub const NODE_HEADER: &str = "Nerve-Node";
/// What the node signs before the center id and the nonce.
pub const CONNECT_CONTEXT: &[u8] = b"nerve-connect/0";

/// The bytes a node signs to answer a challenge:
/// `"nerve-connect/0" || center_id || nonce`.
pub fn connect_message(center_id: &str, nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(CONNECT_CONTEXT.len() + center_id.len() + nonce.len());
    m.extend_from_slice(CONNECT_CONTEXT);
    m.extend_from_slice(center_id.as_bytes());
    m.extend_from_slice(nonce);
    m
}

/// Default limits (spec/node-link.md §Limits): what a side receives unless it
/// announces otherwise.
pub mod limits {
    pub const MESSAGE_BYTES: u64 = 4 * 1024 * 1024;
    pub const BLOB_BYTES: u64 = 64 * 1024 * 1024;
    pub const CALLS: u32 = 64;
    pub const STREAMS: u32 = 16;
    /// Frames each side queues before a reliable stream waits.
    pub const SEND_QUEUE: usize = 64;
}

/// Node names: 1 to 32 of `a-z0-9-` (spec/node-link.md §Identity).
pub fn valid_node_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A node name made from a host name: lowercased, other characters as `-`,
/// cut to 32; `node` when nothing is left.
pub fn node_name_from_host(host: &str) -> String {
    let mut s: String = host
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    s.truncate(32);
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "node".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_names() {
        assert!(valid_node_name("laptop-2"));
        assert!(!valid_node_name(""));
        assert!(!valid_node_name("Laptop"));
        assert!(!valid_node_name(&"a".repeat(33)));
        assert_eq!(node_name_from_host("My.Host_01"), "my-host-01");
        assert_eq!(node_name_from_host("..."), "node");
    }

    #[test]
    fn connect_message_layout() {
        let m = connect_message("c1", &[1, 2]);
        assert_eq!(m, b"nerve-connect/0c1\x01\x02");
    }
}
