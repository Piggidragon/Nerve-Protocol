//! The center's state file, `state.json` in the state folder (mode 0600).
//!
//! It holds what the center must remember across restarts: its id and name,
//! the paired nodes with their public keys and last descriptor, the harness
//! tokens (hashed), the center-side approval rules and the statistics. It never
//! holds file contents, command output or secrets: the descriptor cache is the
//! node's own description of itself, and the statistics are counts and timings.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use nerve_proto::Descriptor;

pub const FILE: &str = "state.json";
/// The default statistics retention.
pub const RETENTION_DAYS: u32 = 30;
const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub center_id: String,
    pub center_name: String,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeRecord>,
    #[serde(default)]
    pub harness_tokens: Vec<TokenRecord>,
    #[serde(default)]
    pub center_policy: CenterPolicy,
    #[serde(default = "d_retention")]
    pub retention_days: u32,
    #[serde(default)]
    pub stats: BTreeMap<String, NodeStats>,
}

fn d_retention() -> u32 {
    RETENTION_DAYS
}

impl Store {
    pub fn new(center_id: String, center_name: String) -> Store {
        Store {
            center_id,
            center_name,
            nodes: BTreeMap::new(),
            harness_tokens: Vec::new(),
            center_policy: CenterPolicy::default(),
            retention_days: RETENTION_DAYS,
            stats: BTreeMap::new(),
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

/// What the center does with a call of a given effect before it sends it to
/// the node (§5.5 of the design): `on` passes it, `ask` holds it for a person
/// in the web UI, `off` refuses it. The node's own policy applies on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rule {
    On,
    Ask,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CenterPolicy {
    /// Effect name to rule; an effect not listed is `on`.
    pub effects: BTreeMap<String, Rule>,
}

impl Default for CenterPolicy {
    /// A generic MCP harness cannot show approvals in its chat or see its own
    /// context, so the effects that change the machine ask at the center.
    fn default() -> CenterPolicy {
        let mut effects = BTreeMap::new();
        for e in ["read", "sense", "write"] {
            effects.insert(e.to_string(), Rule::On);
        }
        effects.insert("execute".into(), Rule::Ask);
        effects.insert("actuate".into(), Rule::Ask);
        CenterPolicy { effects }
    }
}

impl CenterPolicy {
    pub fn rule(&self, effect: &str) -> Rule {
        self.effects.get(effect).copied().unwrap_or(Rule::On)
    }
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
    #[serde(default)]
    pub approvals_asked: u64,
    /// Who answered (`center`, `local`, `timeout`, ...) to count.
    #[serde(default)]
    pub approvals_by: BTreeMap<String, u64>,
    #[serde(default)]
    pub approval_wait_ms: u64,
    #[serde(default)]
    pub approval_wait_max_ms: u64,
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
        self.approvals_asked += o.approvals_asked;
        for (k, n) in &o.approvals_by {
            *self.approvals_by.entry(k.clone()).or_default() += n;
        }
        self.approval_wait_ms += o.approval_wait_ms;
        self.approval_wait_max_ms = self.approval_wait_max_ms.max(o.approval_wait_max_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_default_center_policy_asks_for_execute_and_actuate() {
        let p = CenterPolicy::default();
        assert_eq!(p.rule("execute"), Rule::Ask);
        assert_eq!(p.rule("actuate"), Rule::Ask);
        assert_eq!(p.rule("read"), Rule::On);
        assert_eq!(p.rule("x-new"), Rule::On);
    }
}
