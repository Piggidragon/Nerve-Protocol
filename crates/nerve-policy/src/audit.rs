//! The local audit log: one JSON line per decision, per settings change and
//! per refused config file, in the node's state directory. It is the owner's record and client-only: no
//! center can read or change the file (centers see their own decisions as
//! `audit/decision` events at most).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// One decision on one call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub center: String,
    pub cap: String,
    pub action: String,
    pub target: String,
    /// `allowed` or `forbidden`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

impl Entry {
    /// The `audit/decision` event's data (spec §7.5): the entry without the
    /// center, which is the one the event goes to.
    pub fn event_data(&self) -> Value {
        let mut v = serde_json::to_value(self).expect("an audit entry serializes");
        if let Some(o) = v.as_object_mut() {
            o.remove("center");
        }
        v
    }

    pub fn is_refusal(&self) -> bool {
        self.decision == "forbidden"
    }
}

/// One changed setting: a dotted key and its old and new value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub key: String,
    pub old: Value,
    pub new: Value,
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> AuditLog {
        AuditLog { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&self, v: &Value) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            nerve_transport::files::create_private_dir(dir)?;
        }
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&self.path)?;
        let mut line = v.to_string();
        line.push('\n');
        // One write per line, so concurrent appends do not interleave.
        f.write_all(line.as_bytes())
    }

    pub fn decision(&self, e: &Entry) -> std::io::Result<()> {
        self.append(&serde_json::to_value(e).expect("an audit entry serializes"))
    }

    /// A settings change; `by` is `local` or `center <name>`.
    pub fn settings(&self, by: &str, version: u64, changes: &[Change]) -> std::io::Result<()> {
        self.append(&json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "settings",
            "by": by,
            "version": version,
            "changes": changes,
        }))
    }

    /// Something that happened to the config file itself: `refused` (it was
    /// changed outside the owner's path and is not applied), `signed` (the
    /// node signed a file from before it kept a MAC) or `accepted` (the owner
    /// took a refused file as it is).
    pub fn config(&self, event: &str, file: &Path, reason: &str) -> std::io::Result<()> {
        self.append(&json!({
            "ts": nerve_proto::msg::now_ms(),
            "kind": "config",
            "event": event,
            "file": file.display().to_string(),
            "reason": reason,
        }))
    }

    /// Every line, oldest first; lines that do not parse are skipped.
    pub fn read(&self) -> std::io::Result<Vec<Value>> {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => Ok(t
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

/// The leaves that differ between `old` and `new`, as dotted keys. Arrays
/// count as leaves.
pub fn diff(old: &Value, new: &Value) -> Vec<Change> {
    let mut out = Vec::new();
    walk("", old, new, &mut out);
    out
}

fn walk(prefix: &str, old: &Value, new: &Value, out: &mut Vec<Change>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk(
                    &key,
                    a.get(k).unwrap_or(&Value::Null),
                    b.get(k).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (a, b) if a != b => out.push(Change {
            key: prefix.into(),
            old: a.clone(),
            new: b.clone(),
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_and_reads_back() {
        let d = tempfile::tempdir().unwrap();
        let log = AuditLog::new(d.path().join("state/audit.jsonl"));
        assert!(log.read().unwrap().is_empty());
        let e = Entry {
            ts: 1,
            center: "home".into(),
            cap: "fs".into(),
            action: "read".into(),
            target: "/x".into(),
            decision: "forbidden".into(),
            code: Some("forbidden".into()),
            session: None,
        };
        log.decision(&e).unwrap();
        log.settings(
            "center home",
            3,
            &diff(&json!({"mode": "folder"}), &json!({"mode": "user"})),
        )
        .unwrap();
        let lines = log.read().unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["center"], "home");
        assert_eq!(lines[1]["by"], "center home");
        assert_eq!(lines[1]["changes"][0]["key"], "mode");
        assert_eq!(lines[1]["changes"][0]["new"], "user");
        assert!(e.event_data().get("center").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(log.path()).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    #[test]
    fn diffs_nested_leaves() {
        let c = diff(
            &json!({"a": {"b": 1, "c": [1]}, "d": true}),
            &json!({"a": {"b": 2, "c": [1]}, "e": 1}),
        );
        let keys: Vec<&str> = c.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["a.b", "d", "e"]);
    }
}
