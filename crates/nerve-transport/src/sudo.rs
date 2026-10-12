//! The sudo password on its way to the node (docs/dev/spec/protocol.md §7.4.1).
//!
//! The node offers a fresh X25519 key, signed with its pairing key for that
//! center. The client agrees a key with it from its own fresh X25519 key
//! (HKDF-SHA256, then AES-256-GCM) and seals the password with the offer id
//! and a timestamp. A center relays the sealed box and cannot open it. The
//! node opens an offer at most once and only within [`OFFER_TTL_MS`], so a
//! replayed box finds no offer. Every piece is in WebCrypto as well, so the
//! center's web UI seals in the browser.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// How long an offer stays open, and how far the client's timestamp may be
/// from the node's clock.
pub const OFFER_TTL_MS: u64 = 60_000;

/// The HKDF salt; the offer id is the HKDF info and the AEAD's associated
/// data.
pub const HKDF_SALT: &[u8] = b"nerve-sudo-v1";

/// What `settings.sudo-offer` returns (without the signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    /// Base64 of 16 random bytes; names this offer once.
    pub offer: String,
    /// Base64 of the node's fresh X25519 public key.
    pub key: String,
    /// When the node made the offer (ms since the epoch).
    pub ts: u64,
}

impl Offer {
    /// The bytes the node signs, so a client knows the key is the paired
    /// node's and meant for this center.
    pub fn message(&self, center_id: &str) -> Vec<u8> {
        format!(
            "nerve-sudo-offer\n{center_id}\n{}\n{}\n{}",
            self.offer, self.key, self.ts
        )
        .into_bytes()
    }
}

/// The sealed password in `settings.sudo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    /// The offer this box answers.
    pub offer: String,
    /// Base64 of the client's fresh X25519 public key.
    pub key: String,
    /// Base64 of the 12-byte AES-GCM nonce.
    pub iv: String,
    /// Base64 of the ciphertext and tag.
    pub ct: String,
}

/// What is inside the box.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner {
    password: String,
    offer: String,
    ts: u64,
}

/// The node's side of one offer. Opening consumes it.
pub struct Pending {
    offer: Offer,
    private: EphemeralPrivateKey,
}

fn aead_key(shared: &[u8], offer: &str) -> Result<LessSafeKey, String> {
    let info = [offer.as_bytes()];
    let prk = Salt::new(HKDF_SHA256, HKDF_SALT).extract(shared);
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| "cannot derive the key".to_string())?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn unb64(s: &str, what: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|_| format!("{what} is not base64"))
}

impl Pending {
    pub fn new(now_ms: u64) -> Result<Pending, String> {
        let rng = SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| "cannot make a key".to_string())?;
        let public = private
            .compute_public_key()
            .map_err(|_| "cannot make a key".to_string())?;
        let mut id = [0u8; 16];
        rng.fill(&mut id)
            .map_err(|_| "cannot make an offer id".to_string())?;
        Ok(Pending {
            offer: Offer {
                offer: B64.encode(id),
                key: B64.encode(public.as_ref()),
                ts: now_ms,
            },
            private,
        })
    }

    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    /// The password in `sealed`, if it answers this offer, in time.
    pub fn open(self, sealed: &Sealed, now_ms: u64) -> Result<String, String> {
        if sealed.offer != self.offer.offer {
            return Err("the sealed password answers another offer".into());
        }
        if now_ms.saturating_sub(self.offer.ts) > OFFER_TTL_MS {
            return Err("the sudo offer has expired; ask for a new one".into());
        }
        let peer = unb64(&sealed.key, "key")?;
        let iv = unb64(&sealed.iv, "iv")?;
        let mut buf = unb64(&sealed.ct, "ct")?;
        let nonce = Nonce::try_assume_unique_for_key(&iv)
            .map_err(|_| format!("iv must be {NONCE_LEN} bytes"))?;
        let offer = self.offer.offer.clone();
        let key = agree_ephemeral(
            self.private,
            &UnparsedPublicKey::new(&X25519, &peer),
            |shared| aead_key(shared, &offer),
        )
        .map_err(|_| "key is not an X25519 public key".to_string())??;
        let plain = key
            .open_in_place(nonce, Aad::from(offer.as_bytes()), &mut buf)
            .map_err(|_| "the sealed password does not open".to_string())?;
        let inner: Inner = serde_json::from_slice(plain)
            .map_err(|_| "the sealed password is not the expected JSON".to_string())?;
        buf.fill(0);
        if inner.offer != offer {
            return Err("the sealed password names another offer".into());
        }
        if inner.ts.abs_diff(now_ms) > OFFER_TTL_MS {
            return Err("the sealed password's timestamp is too far from the node's clock".into());
        }
        Ok(inner.password)
    }
}

/// The client's side: seals `password` for `offer`.
pub fn seal(offer: &Offer, password: &str, now_ms: u64) -> Result<Sealed, String> {
    let rng = SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|_| "cannot make a key".to_string())?;
    let public = private
        .compute_public_key()
        .map_err(|_| "cannot make a key".to_string())?;
    let peer = unb64(&offer.key, "the offer's key")?;
    let key = agree_ephemeral(private, &UnparsedPublicKey::new(&X25519, &peer), |shared| {
        aead_key(shared, &offer.offer)
    })
    .map_err(|_| "the offer's key is not an X25519 public key".to_string())??;
    let mut iv = [0u8; NONCE_LEN];
    rng.fill(&mut iv)
        .map_err(|_| "cannot make a nonce".to_string())?;
    let mut buf = serde_json::to_vec(&Inner {
        password: password.into(),
        offer: offer.offer.clone(),
        ts: now_ms,
    })
    .map_err(|e| e.to_string())?;
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(iv),
        Aad::from(offer.offer.as_bytes()),
        &mut buf,
    )
    .map_err(|_| "cannot seal".to_string())?;
    Ok(Sealed {
        offer: offer.offer.clone(),
        key: B64.encode(public.as_ref()),
        iv: B64.encode(iv),
        ct: B64.encode(&buf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn opens_what_the_client_sealed() {
        let p = Pending::new(NOW).unwrap();
        let s = seal(p.offer(), "hunter2", NOW + 10).unwrap();
        assert!(!s.ct.contains("hunter2"));
        assert_eq!(p.open(&s, NOW + 20).unwrap(), "hunter2");
    }

    #[test]
    fn refuses_late_tampered_and_foreign_boxes() {
        let p = Pending::new(NOW).unwrap();
        let s = seal(p.offer(), "pw", NOW).unwrap();
        assert!(
            p.open(&s, NOW + OFFER_TTL_MS + 1)
                .unwrap_err()
                .contains("expired")
        );

        let p = Pending::new(NOW).unwrap();
        let mut s = seal(p.offer(), "pw", NOW).unwrap();
        let mut ct = B64.decode(&s.ct).unwrap();
        ct[0] ^= 1;
        s.ct = B64.encode(ct);
        assert!(p.open(&s, NOW).unwrap_err().contains("does not open"));

        // A box for one offer does not open another, even with its id.
        let a = Pending::new(NOW).unwrap();
        let b = Pending::new(NOW).unwrap();
        let mut s = seal(a.offer(), "pw", NOW).unwrap();
        assert!(
            b.open(&s.clone(), NOW)
                .unwrap_err()
                .contains("another offer")
        );
        let c = Pending::new(NOW).unwrap();
        s.offer = c.offer().offer.clone();
        assert!(c.open(&s, NOW).is_err());

        // The client's clock is checked too.
        let p = Pending::new(NOW).unwrap();
        let s = seal(p.offer(), "pw", NOW - 2 * OFFER_TTL_MS).unwrap();
        assert!(p.open(&s, NOW).unwrap_err().contains("timestamp"));
    }
}
