//! Transport of the Nerve Protocol: TLS with certificate pinning, the loopback
//! rule for plain HTTP, `CONNECT` proxies, the WebSocket under the node link,
//! the node's Ed25519 identity, the sealed sudo password, a small HTTP/1.1 server side, and local control
//! sockets. Shared by `nerve-node` and `nerve-center`.

pub mod backoff;
pub mod ctl;
pub mod files;
pub mod http;
pub mod keys;
pub mod net;
pub mod sudo;
pub mod tls;
pub mod ws;

pub use net::{BoxIo, Proxy};

/// Installs ring as rustls' process-wide crypto provider. Every config this
/// crate builds names its provider itself; this covers code that does not.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
