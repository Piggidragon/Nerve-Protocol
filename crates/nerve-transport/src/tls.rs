//! TLS for every connection to a center that is not on this machine, and the
//! center's own certificate.
//!
//! With a pin (from the pairing link) the certificate must carry exactly that public
//! key, whoever signed it: a self-signed center certificate works, and a CA cannot
//! substitute another key. Without a pin the certificate is checked against the
//! system's root certificates as a browser would.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

/// The pin of a certificate: base64url (no padding) sha256 of its
/// SubjectPublicKeyInfo, the same value `openssl ... | openssl dgst -sha256` gives.
pub fn pin_of_cert(cert_der: &[u8]) -> Option<String> {
    spki_of(cert_der).map(pin_of_spki)
}

pub fn pin_of_spki(spki_der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, spki_der))
}

/// base64url without padding, as pins and `center.rotate` carry bytes.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of [`b64url`] text; `None` when it is not that.
pub fn unb64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// Checks a pin's form and returns its 32 bytes.
pub fn decode_pin(pin: &str) -> Result<[u8; 32], String> {
    let raw = URL_SAFE_NO_PAD
        .decode(pin.trim_end_matches('='))
        .map_err(|_| "the certificate pin is not base64url".to_string())?;
    raw.try_into()
        .map_err(|_| "the certificate pin is not a sha256 hash".to_string())
}

/// The SubjectPublicKeyInfo element (tag and length included) of an X.509
/// certificate in DER.
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (tag, cert_body, _) = der_element(cert)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = der_element(cert_body)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // version [0] EXPLICIT is optional.
    let (tag, _, after) = der_element(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        let (_, _, after) = der_element(rest)?;
        rest = after;
    }
    let (tag, _, after) = der_element(rest)?;
    if tag != 0x30 {
        return None;
    }
    Some(&rest[..rest.len() - after.len()])
}

/// The key algorithms a center's key may have for a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpkiAlg {
    P256,
    P384,
    Ed25519,
}

/// The AlgorithmIdentifier of each, as DER: id-ecPublicKey with its curve,
/// and id-Ed25519.
const ALG_P256: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
];
const ALG_P384: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x22,
];
const ALG_ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// The algorithm and the raw public key of a SubjectPublicKeyInfo; `None`
/// for any other algorithm or a malformed one.
fn spki_key(spki: &[u8]) -> Option<(SpkiAlg, &[u8])> {
    let (tag, body, rest) = der_element(spki)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (_, _, after_alg) = der_element(body)?;
    let alg_id = &body[..body.len() - after_alg.len()];
    let alg = match alg_id {
        a if a == ALG_P256 => SpkiAlg::P256,
        a if a == ALG_P384 => SpkiAlg::P384,
        a if a == ALG_ED25519 => SpkiAlg::Ed25519,
        _ => return None,
    };
    let (tag, bits, rest) = der_element(after_alg)?;
    // A BIT STRING without unused bits, and nothing after it.
    if tag != 0x03 || !rest.is_empty() || bits.first() != Some(&0) {
        return None;
    }
    Some((alg, &bits[1..]))
}

/// Whether `sig` is a signature over `message` by the key of the
/// SubjectPublicKeyInfo `spki` (DER), as [`ServerIdentity::sign`] makes it.
pub fn verify_spki_signature(spki: &[u8], message: &[u8], sig: &[u8]) -> bool {
    use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519};
    let Some((alg, key)) = spki_key(spki) else {
        return false;
    };
    let alg: &dyn ring::signature::VerificationAlgorithm = match alg {
        SpkiAlg::P256 => &ECDSA_P256_SHA256_ASN1,
        SpkiAlg::P384 => &ECDSA_P384_SHA384_ASN1,
        SpkiAlg::Ed25519 => &ED25519,
    };
    ring::signature::UnparsedPublicKey::new(alg, key)
        .verify(message, sig)
        .is_ok()
}

/// The tag, contents and remainder of the DER element at the start of `d`.
fn der_element(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *d.first()?;
    // Multi-byte tags do not occur in the parts of a certificate walked here.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *d.get(1)?;
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *d.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    if end > d.len() {
        return None;
    }
    Some((tag, &d[header..end], &d[end..]))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The client configuration for a center: pinned when `pin` is set, else the
/// system's roots.
pub fn client_config(pin: Option<&str>) -> Result<Arc<ClientConfig>, String> {
    match pin {
        Some(p) => client_config_pins(&[p]),
        None => client_config_pins(&[]),
    }
}

/// The client configuration for a center that may present any of `pins`:
/// the one it paired with and, while a rotation of the center's key is in
/// its grace (docs/dev/spec/protocol.md §4.10), the other one. No pin: the
/// system's roots.
pub fn client_config_pins(pins: &[&str]) -> Result<Arc<ClientConfig>, String> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let config = if pins.is_empty() {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = rustls::RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(loaded.certs);
        if added == 0 {
            return Err(
                "no system root certificates found; pair with a link that carries the certificate pin"
                    .into(),
            );
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                pins: pins
                    .iter()
                    .map(|p| decode_pin(p))
                    .collect::<Result<_, _>>()?,
                algs: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

/// Accepts exactly the pinned keys. The handshake signature is still verified, so
/// the server has to hold the private key; name and expiry do not matter, as with
/// an ssh host key.
#[derive(Debug)]
struct PinVerifier {
    pins: Vec<[u8; 32]>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let spki = spki_of(end_entity.as_ref())
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let got = ring::digest::digest(&ring::digest::SHA256, spki);
        // The pins are public (they are in the pairing link), so a plain comparison is fine.
        if self.pins.iter().any(|p| got.as_ref() == p) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The center's TLS identity: a self-signed certificate and its key, kept as
/// PEM files in the center's state folder.
pub struct ServerIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl ServerIdentity {
    /// A new self-signed certificate for `names` (host names or addresses the
    /// center is reached at; `localhost` is always added).
    pub fn generate(names: &[String]) -> Result<ServerIdentity, String> {
        let mut names: Vec<String> = names.to_vec();
        if !names.iter().any(|n| n == "localhost") {
            names.push("localhost".into());
        }
        let ck = rcgen::generate_simple_self_signed(names).map_err(|e| e.to_string())?;
        Ok(ServerIdentity {
            cert_der: ck.cert.der().to_vec(),
            key_der: ck.signing_key.serialize_der(),
        })
    }

    pub fn pin(&self) -> String {
        pin_of_cert(&self.cert_der).unwrap_or_default()
    }

    /// The certificate's SubjectPublicKeyInfo in DER.
    pub fn spki(&self) -> Vec<u8> {
        spki_of(&self.cert_der).unwrap_or_default().to_vec()
    }

    /// Signs `message` with the identity's key, as [`verify_spki_signature`]
    /// checks it against [`ServerIdentity::spki`]: ECDSA (ASN.1) for a P-256
    /// or P-384 key, Ed25519 for an Ed25519 key. Other keys cannot sign a
    /// rotation (docs/dev/spec/protocol.md §4.10).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        use ring::signature::{
            ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
            EcdsaSigningAlgorithm, Ed25519KeyPair,
        };
        let spki = self.spki();
        let (alg, _) = spki_key(&spki).ok_or(
            "the center's key is not an ECDSA P-256, P-384 or Ed25519 key, so it cannot sign a rotation",
        )?;
        let rng = ring::rand::SystemRandom::new();
        let bad = "the center's private key does not read as its certificate says";
        let ecdsa = |a: &'static EcdsaSigningAlgorithm| {
            EcdsaKeyPair::from_pkcs8(a, &self.key_der, &rng)
                .map_err(|_| bad.to_string())?
                .sign(&rng, message)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| "signing with the center's key failed".to_string())
        };
        match alg {
            SpkiAlg::P256 => ecdsa(&ECDSA_P256_SHA256_ASN1_SIGNING),
            SpkiAlg::P384 => ecdsa(&ECDSA_P384_SHA384_ASN1_SIGNING),
            SpkiAlg::Ed25519 => Ok(Ed25519KeyPair::from_pkcs8_maybe_unchecked(&self.key_der)
                .map_err(|_| bad.to_string())?
                .sign(message)
                .as_ref()
                .to_vec()),
        }
    }

    /// The certificate and key as one PEM text.
    pub fn to_pem(&self) -> String {
        format!(
            "{}{}",
            pem("CERTIFICATE", &self.cert_der),
            pem("PRIVATE KEY", &self.key_der)
        )
    }

    pub fn from_pem(text: &str) -> Result<ServerIdentity, String> {
        let cert_der = unpem(text, "CERTIFICATE").ok_or("no certificate in the PEM file")?;
        let key_der = unpem(text, "PRIVATE KEY").ok_or("no private key in the PEM file")?;
        if spki_of(&cert_der).is_none() {
            return Err("the certificate is not valid DER".into());
        }
        Ok(ServerIdentity { cert_der, key_der })
    }

    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(self.key_der.clone().into());
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(self.cert_der.clone())], key)
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(config))
    }
}

/// The server side of TLS for one [`ServerIdentity`], for a listener outside
/// the center: a node's relay (docs/dev/spec/protocol.md §4.8), and the tests,
/// in front of the conformance suite's fake center, which speaks plain HTTP.
#[derive(Clone)]
pub struct Acceptor(tokio_rustls::TlsAcceptor);

impl Acceptor {
    pub fn new(identity: &ServerIdentity) -> Result<Acceptor, String> {
        Ok(Acceptor(tokio_rustls::TlsAcceptor::from(
            identity.server_config()?,
        )))
    }

    /// Runs the server's handshake on `tcp`.
    pub async fn accept(&self, tcp: tokio::net::TcpStream) -> Result<crate::BoxIo, String> {
        let tls = self.0.accept(tcp).await.map_err(|e| e.to_string())?;
        Ok(Box::new(tls))
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for line in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or(""));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

fn unpem(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = start + text[start..].find(&end)?;
    let b: String = text[start..stop].split_whitespace().collect();
    base64::engine::general_purpose::STANDARD.decode(b).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_need_32_bytes() {
        assert!(decode_pin(&"A".repeat(43)).is_ok());
        assert!(decode_pin("AAAA").is_err());
        assert!(decode_pin("not base64!").is_err());
    }

    #[test]
    fn der_walker_refuses_truncated_input() {
        assert!(spki_of(&[]).is_none());
        assert!(spki_of(&[0x30, 0x05, 0x30]).is_none());
        assert!(spki_of(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn identity_round_trips_through_pem() {
        let id = ServerIdentity::generate(&["center.example".into()]).unwrap();
        let back = ServerIdentity::from_pem(&id.to_pem()).unwrap();
        assert_eq!(back.cert_der, id.cert_der);
        assert_eq!(back.pin(), id.pin());
        assert!(decode_pin(&id.pin()).is_ok());
        assert!(back.server_config().is_ok());
        assert!(ServerIdentity::from_pem("junk").is_err());
    }

    /// A self-signed identity with an Ed25519 key, as an owner might put in
    /// place of the generated P-256 one.
    fn ed25519_identity() -> ServerIdentity {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        ServerIdentity {
            cert_der: cert.der().to_vec(),
            key_der: kp.serialize_der(),
        }
    }

    #[test]
    fn a_center_key_signs_what_its_spki_verifies() {
        for (old, new) in [
            (
                ServerIdentity::generate(&[]).unwrap(),
                ServerIdentity::generate(&[]).unwrap(),
            ),
            (ed25519_identity(), ed25519_identity()),
        ] {
            let msg = b"nerve-rotate-center/0c1 new pin";
            let sig = old.sign(msg).unwrap();
            assert!(verify_spki_signature(&old.spki(), msg, &sig));
            // Not another message, not under another key, not cut short.
            assert!(!verify_spki_signature(&old.spki(), b"other", &sig));
            assert!(!verify_spki_signature(&new.spki(), msg, &sig));
            assert!(!verify_spki_signature(&old.spki(), msg, &sig[1..]));
            let mut spki = old.spki();
            spki.push(0);
            assert!(!verify_spki_signature(&spki, msg, &sig));
            assert_eq!(pin_of_spki(&old.spki()), old.pin());
        }
        assert!(!verify_spki_signature(&[], b"m", b"s"));
    }

    #[test]
    fn several_pins_accept_each_of_their_keys_and_no_other() {
        let (a, b, c) = (
            ServerIdentity::generate(&[]).unwrap(),
            ServerIdentity::generate(&[]).unwrap(),
            ServerIdentity::generate(&[]).unwrap(),
        );
        let (pa, pb) = (a.pin(), b.pin());
        let v = PinVerifier {
            pins: [pa.as_str(), pb.as_str()]
                .iter()
                .map(|p| decode_pin(p).unwrap())
                .collect(),
            algs: provider().signature_verification_algorithms,
        };
        let name = ServerName::try_from("localhost").unwrap();
        let check = |id: &ServerIdentity| {
            v.verify_server_cert(
                &CertificateDer::from(id.cert_der.clone()),
                &[],
                &name,
                &[],
                UnixTime::now(),
            )
            .is_ok()
        };
        assert!(check(&a) && check(&b));
        assert!(!check(&c));
        assert!(client_config_pins(&[&pa, &pb]).is_ok());
        assert!(client_config_pins(&[&pa, "short"]).is_err());
    }
}
