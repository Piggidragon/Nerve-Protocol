//! The node's Ed25519 key per center, its node id, and the connect signature
//! (spec/node-link.md §Identity).
//!
//! 0.0.1 keeps the key as a 0600 file next to the node's config. Keeping it in
//! the system keyring (`machine.secret_storage = "keyring"`) is not done yet;
//! see the README's list of what is missing.

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use nerve_proto::msg::{hex, unhex};

pub struct NodeKey {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
}

impl NodeKey {
    pub fn generate() -> Result<NodeKey, String> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "cannot generate a key".to_string())?;
        NodeKey::from_pkcs8(pkcs8.as_ref())
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<NodeKey, String> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| "the node key file is not an Ed25519 key".to_string())?;
        Ok(NodeKey {
            pair,
            pkcs8: pkcs8.to_vec(),
        })
    }

    /// The key as stored: PKCS#8, hex encoded, one line.
    pub fn to_text(&self) -> String {
        hex(&self.pkcs8) + "\n"
    }

    pub fn from_text(s: &str) -> Result<NodeKey, String> {
        let raw = unhex(s.trim()).ok_or("the node key file is not hex")?;
        NodeKey::from_pkcs8(&raw)
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    pub fn public_hex(&self) -> String {
        hex(&self.public_key())
    }

    pub fn node_id(&self) -> String {
        node_id(&self.public_key())
    }

    /// The `auth.sig` of `hello`: hex Ed25519 over the connect message.
    pub fn sign_connect(&self, center_id: &str, nonce: &[u8]) -> String {
        hex(self
            .pair
            .sign(&nerve_proto::connect_message(center_id, nonce))
            .as_ref())
    }

    /// The `sig` of a `settings.sudo_offer` result: hex Ed25519 over
    /// [`crate::sudo::Offer::message`].
    pub fn sign_sudo_offer(&self, center_id: &str, offer: &crate::sudo::Offer) -> String {
        hex(self.pair.sign(&offer.message(center_id)).as_ref())
    }
}

/// A node id: base32 of the first 16 bytes of sha256 of the public key.
pub fn node_id(public_key: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, public_key);
    nerve_proto::base32::encode(&d.as_ref()[..16])
}

/// Checks a sudo offer's signature against a node's stored public key (hex).
pub fn verify_sudo_offer(
    public_hex: &str,
    center_id: &str,
    offer: &crate::sudo::Offer,
    sig_hex: &str,
) -> bool {
    let (Some(pk), Some(sig)) = (unhex(public_hex), unhex(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(&offer.message(center_id), &sig)
        .is_ok()
}

/// Checks a `hello` signature against a node's stored public key (hex).
pub fn verify_connect(public_hex: &str, center_id: &str, nonce: &[u8], sig_hex: &str) -> bool {
    let (Some(pk), Some(sig)) = (unhex(public_hex), unhex(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(&nerve_proto::connect_message(center_id, nonce), &sig)
        .is_ok()
}

/// `n` random bytes from the system.
pub fn random_bytes(n: usize) -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut b = vec![0u8; n];
    // A failing system RNG leaves nothing sensible to do but stop.
    SystemRandom::new()
        .fill(&mut b)
        .expect("the system random generator failed");
    b
}

/// A random token of `n` characters from `a-z0-9` (pairing codes, harness
/// tokens), drawn without modulo bias.
pub fn random_token(n: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for b in random_bytes(n) {
            // 252 = 7 * 36: bytes at or above it would favour the first letters.
            if b < 252 && out.len() < n {
                out.push(A[(b % 36) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_offers_are_signed_for_one_center() {
        let k = NodeKey::generate().unwrap();
        let p = crate::sudo::Pending::new(5).unwrap();
        let sig = k.sign_sudo_offer("c1", p.offer());
        assert!(verify_sudo_offer(&k.public_hex(), "c1", p.offer(), &sig));
        assert!(!verify_sudo_offer(&k.public_hex(), "c2", p.offer(), &sig));
        let mut other = p.offer().clone();
        other.ts += 1;
        assert!(!verify_sudo_offer(&k.public_hex(), "c1", &other, &sig));
    }

    #[test]
    fn sign_and_verify() {
        let k = NodeKey::generate().unwrap();
        let back = NodeKey::from_text(&k.to_text()).unwrap();
        assert_eq!(back.public_key(), k.public_key());
        assert_eq!(k.node_id().len(), 26);
        let nonce = random_bytes(32);
        let sig = k.sign_connect("c1", &nonce);
        assert!(verify_connect(&k.public_hex(), "c1", &nonce, &sig));
        assert!(!verify_connect(&k.public_hex(), "c2", &nonce, &sig));
        let other = NodeKey::generate().unwrap();
        assert!(!verify_connect(&other.public_hex(), "c1", &nonce, &sig));
        assert!(!verify_connect("zz", "c1", &nonce, &sig));
        assert!(NodeKey::from_text("abcd").is_err());
    }

    #[test]
    fn tokens() {
        let t = random_token(20);
        assert_eq!(t.len(), 20);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        assert_ne!(random_token(20), t);
    }
}
