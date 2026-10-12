//! Pairing with a center (spec §2): the preview the owner confirms, the
//! `POST /nerve/v0/pair`, and storing the key and the center entry.

use serde_json::Value;

use nerve_policy::config::{SettingsGrant, valid_center_name};
use nerve_policy::{CenterEntry, CenterPolicy};
use nerve_proto::PAIR_PATH;
use nerve_proto::link::{PairLink, PairRequest, PairResponse};
use nerve_transport::keys::NodeKey;

use crate::paths::NodePaths;

/// The largest pairing response the node reads.
const RESPONSE_MAX: usize = 64 * 1024;

/// What the owner sees before confirming: where the node will link to, and
/// what the center may do by default.
pub fn preview(link: &PairLink, name: Option<&str>) -> String {
    let mut s = format!("Pair this node with the center at {}\n", link.center);
    match &link.pin {
        Some(pin) => s.push_str(&format!("  certificate pin: {pin}\n")),
        None if link.center.tls => {
            s.push_str("  certificate: checked against the system's roots\n")
        }
        None => s.push_str("  WARNING: plain http, nothing on the way is encrypted\n"),
    }
    if let Some(n) = name {
        s.push_str(&format!("  local name: {n}\n"));
    }
    s.push_str(
        "Defaults for this center:\n  \
         mode allowlist (nothing is allowed until you add an allow rule or choose a mode)\n  \
         settings off (the center cannot change this node's settings)\n",
    );
    s
}

/// Pairs with the center in `link` and stores the result: the node key
/// (0600) under `keys/<name>.key` and a `[[center]]` entry with the default
/// policy. Returns the new entry.
pub async fn pair(
    paths: &NodePaths,
    link: &PairLink,
    name: Option<&str>,
) -> Result<CenterEntry, String> {
    nerve_transport::init_crypto();
    let (cfg, _) = crate::cli::read_config(paths).await?;
    let key = NodeKey::generate()?;
    let req = PairRequest {
        code: link.code.clone(),
        name: crate::descriptor::node_name(&cfg),
        platform: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        public_key: key.public_hex(),
    };
    let body = serde_json::to_value(&req).map_err(|e| e.to_string())?;
    let mut io = nerve_transport::net::open(&link.center, link.pin.as_deref(), None).await?;
    let path = format!("{}{}", link.center.base, PAIR_PATH);
    let resp = nerve_transport::http::post_json(
        &mut io,
        &link.center.authority(),
        &path,
        &body,
        RESPONSE_MAX,
    )
    .await?;
    let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    if resp.status != 200 {
        let why = v
            .get("error")
            .and_then(|e| e.get("message").or(Some(e)))
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| m.to_string())
            })
            .unwrap_or_else(|| format!("HTTP {}", resp.status));
        return Err(format!("the center refused the pairing: {why}"));
    }
    let r: PairResponse =
        serde_json::from_value(v).map_err(|e| format!("bad pairing response: {e}"))?;
    if r.node_id != key.node_id() {
        return Err("the center answered with another node id".into());
    }

    let entry_name = name
        .map(str::to_string)
        .unwrap_or_else(|| local_name(&r.center_name));
    if !valid_center_name(&entry_name) {
        return Err(format!(
            "{entry_name:?} is not a valid center name (1-64 of A-Z a-z 0-9 - _)"
        ));
    }
    let entry = CenterEntry {
        name: entry_name.clone(),
        url: link.center.to_string(),
        pin: link.pin.clone(),
        center_id: r.center_id.clone(),
        node_id: r.node_id.clone(),
        settings: SettingsGrant::Off,
        paused: false,
        revoked: false,
        unknown: false,
        policy: CenterPolicy::default(),
    };

    let key_file = paths.key_file(&entry_name);
    if let Some(dir) = key_file.parent() {
        nerve_transport::files::create_private_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // The key goes first: an entry without its key cannot dial, a key
    // without an entry is just a stray file that the next pairing replaces.
    if cfg.center(&entry_name).is_some() {
        return Err(format!("a center named {entry_name} is paired already"));
    }
    nerve_transport::files::write_private(&key_file, key.to_text().as_bytes())
        .map_err(|e| format!("{}: {e}", key_file.display()))?;
    let added = entry.clone();
    let r = crate::cli::edit(paths, move |c| {
        if c.center(&added.name).is_some() {
            return Err(format!("a center named {} is paired already", added.name));
        }
        if let Some(old) = c.centers.iter().find(|e| e.center_id == added.center_id) {
            return Err(format!("this center is paired already as {}", old.name));
        }
        c.centers.push(added.clone());
        Ok(())
    })
    .await;
    if let Err(e) = r {
        let _ = std::fs::remove_file(&key_file);
        return Err(e);
    }
    Ok(entry)
}

/// A local name from the center's display name: the allowed characters
/// kept, the rest turned into `-`.
fn local_name(center_name: &str) -> String {
    let s: String = center_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "center".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names() {
        assert_eq!(local_name("Home Lab"), "Home-Lab");
        assert_eq!(local_name("  "), "center");
        assert_eq!(local_name("conformance-center"), "conformance-center");
    }
}
