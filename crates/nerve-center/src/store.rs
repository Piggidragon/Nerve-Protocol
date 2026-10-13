//! The center's state file, `state.json` in the state folder (mode 0600).
//!
//! It holds what the center must remember across restarts: its id and name,
//! the paired nodes with their public keys and last descriptor, the harness
//! tokens (hashed) and the statistics. It never
//! holds file contents, command output or secrets: the descriptor cache is the
//! node's own description of itself, and the statistics are counts and timings.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use nerve_proto::Descriptor;
use nerve_transport::log::Level;

pub const FILE: &str = "state.json";
/// The default statistics retention.
pub const RETENTION_DAYS: u32 = 30;
/// The default lifetime of a pairing code, in minutes.
pub const PAIR_CODE_MINUTES: u32 = 10;
/// The longest lifetime the owner may set for a pairing code: 24 hours.
pub const PAIR_CODE_MAX_MINUTES: u32 = 1440;
const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub center_id: String,
    pub center_name: String,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeRecord>,
    #[serde(default)]
    pub harness_tokens: Vec<TokenRecord>,
    #[serde(default = "d_retention")]
    pub retention_days: u32,
    /// How long a pairing code made from now on stays valid, in minutes.
    #[serde(default = "d_pair_code_minutes")]
    pub pair_code_minutes: u32,
    #[serde(default)]
    pub stats: BTreeMap<String, NodeStats>,
    /// What the center logs (docs/user/logs.md); the `--log` flag overrides
    /// it for one run.
    #[serde(default)]
    pub log_level: Level,
}

fn d_retention() -> u32 {
    RETENTION_DAYS
}

fn d_pair_code_minutes() -> u32 {
    PAIR_CODE_MINUTES
}

impl Store {
    pub fn new(center_id: String, center_name: String) -> Store {
        Store {
            center_id,
            center_name,
            nodes: BTreeMap::new(),
            harness_tokens: Vec::new(),
            retention_days: RETENTION_DAYS,
            pair_code_minutes: PAIR_CODE_MINUTES,
            stats: BTreeMap::new(),
            log_level: Level::default(),
        }
    }

    pub fn load(dir: &Path) -> std::io::Result<Option<Store>> {
        match std::fs::read(dir.join(FILE)) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| {
                std::io::Error::other(format!("{} is not valid: {e}", dir.join(FILE).display()))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let text = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        nerve_transport::files::write_private(&dir.join(FILE), &text)
    }

    pub fn node_by_name(&self, name: &str) -> Option<&NodeRecord> {
        self.nodes.values().find(|n| n.name == name)
    }

    /// Today's statistics bucket of `node`.
    pub fn day(&mut self, node: &str, now_ms: u64) -> &mut DayStats {
        self.stats
            .entry(node.to_string())
            .or_default()
            .days
            .entry(now_ms / DAY_MS)
            .or_default()
    }

    /// Drops statistics days older than the retention.
    pub fn prune_stats(&mut self, now_ms: u64) {
        let keep_from = (now_ms / DAY_MS).saturating_sub(u64::from(self.retention_days));
        for s in self.stats.values_mut() {
            s.days.retain(|d, _| *d >= keep_from);
        }
        self.stats.retain(|_, s| !s.days.is_empty());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: String,
    /// The center's name for the node; unique among this center's nodes.
    pub name: String,
    /// The node's Ed25519 public key for this center, hex.
    pub public_key: String,
    pub platform: String,
    pub arch: String,
    pub paired_ms: u64,
    /// The owner switched the node off in the center: it stays paired and
    /// connected, but the agent is offered none of its tools and no call
    /// reaches it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default)]
    pub last_seen_ms: u64,
    /// Why the node said it was going away before its last link dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub going_away: Option<String>,
    /// The last full descriptor, so tools stay listed while the node is offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<Descriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub label: String,
    /// Hex SHA-256 of the token; the token itself is shown once and not kept.
    pub hash: String,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    /// Day number (days since the Unix epoch) to that day's numbers.
    #[serde(default)]
    pub days: BTreeMap<u64, DayStats>,
}

/// One node's numbers for one day. Counts and timings only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DayStats {
    #[serde(default)]
    pub online_ms: u64,
    #[serde(default)]
    pub links: u64,
    /// Links that ended without a `bye`.
    #[serde(default)]
    pub drops: u64,
    /// `cap.action` to its calls.
    #[serde(default)]
    pub calls: BTreeMap<String, CallStats>,
    /// Error code to count.
    #[serde(default)]
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CallStats {
    pub count: u64,
    pub errors: u64,
    pub total_ms: u64,
    pub max_ms: u64,
}

impl DayStats {
    pub fn add(&mut self, o: &DayStats) {
        self.online_ms += o.online_ms;
        self.links += o.links;
        self.drops += o.drops;
        for (k, c) in &o.calls {
            let m = self.calls.entry(k.clone()).or_default();
            m.count += c.count;
            m.errors += c.errors;
            m.total_ms += c.total_ms;
            m.max_ms = m.max_ms.max(c.max_ms);
        }
        for (k, n) in &o.errors {
            *self.errors.entry(k.clone()).or_default() += n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pairing_code_lifetime_defaults_to_ten_minutes() {
        assert_eq!(Store::new("c".into(), "home".into()).pair_code_minutes, 10);
        // A state file without the setting reads as ten minutes.
        let old = r#"{"center_id": "c", "center_name": "home"}"#;
        let s: Store = serde_json::from_str(old).unwrap();
        assert_eq!(s.pair_code_minutes, 10);
    }

    #[test]
    fn stats_are_pruned_by_retention() {
        let mut s = Store::new("c".into(), "home".into());
        s.retention_days = 2;
        let today = 100 * DAY_MS;
        s.day("n", today - 5 * DAY_MS).links = 1;
        s.day("n", today).links = 2;
        s.prune_stats(today);
        let days = &s.stats["n"].days;
        assert_eq!(days.len(), 1);
        assert_eq!(days[&100].links, 2);
    }

    fn record(id: &str) -> NodeRecord {
        NodeRecord {
            id: id.into(),
            name: id.into(),
            public_key: "00".into(),
            platform: "linux".into(),
            arch: "x86_64".into(),
            paired_ms: 1,
            disabled: false,
            last_seen_ms: 0,
            going_away: None,
            descriptor: None,
        }
    }

    #[test]
    fn the_disabled_flag_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::new("c".into(), "home".into());
        s.nodes.insert("a".into(), record("a"));
        s.nodes.insert("b".into(), record("b"));
        s.nodes.get_mut("b").unwrap().disabled = true;
        s.save(dir.path()).unwrap();
        let back = Store::load(dir.path()).unwrap().unwrap();
        assert!(!back.nodes["a"].disabled);
        assert!(back.nodes["b"].disabled);
    }

    #[test]
    fn a_state_file_without_the_flag_reads_a_node_as_enabled() {
        let old = r#"{"center_id":"c","center_name":"home","nodes":{"a":{"id":"a","name":"a",
            "public_key":"00","platform":"linux","arch":"x86_64","paired_ms":1}}}"#;
        let s: Store = serde_json::from_str(old).unwrap();
        assert!(!s.nodes["a"].disabled);
    }
}
