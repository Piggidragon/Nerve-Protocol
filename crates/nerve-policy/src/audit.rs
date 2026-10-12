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

/// The size at which `audit.jsonl` is moved aside to `audit.jsonl.1`, which
/// replaces the older one: the log never takes more than twice this.
pub const AUDIT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// The most characters of a target (a command line, a path) one decision
/// logs; a longer one is cut and says so.
pub const TARGET_MAX_CHARS: usize = 512;

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

    /// The one older file the log keeps.
    fn old_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".1");
        p.into()
    }

    fn append(&self, v: &Value) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            nerve_transport::files::create_private_dir(dir)?;
        }
        let mut line = v.to_string();
        line.push('\n');
        // A center can make refused calls as fast as the link allows, and
        // each is logged; so the log is bounded.
        if let Ok(m) = std::fs::metadata(&self.path)
            && m.len() > 0
            && m.len() + line.len() as u64 > AUDIT_MAX_BYTES
        {
            std::fs::rename(&self.path, self.old_path())?;
        }
        let mut o = std::fs::OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&self.path)?;
        // One write per line, so concurrent appends do not interleave.
        f.write_all(line.as_bytes())
    }

    pub fn decision(&self, e: &Entry) -> std::io::Result<()> {
        let mut v = serde_json::to_value(e).expect("an audit entry serializes");
        let n = e.target.chars().count();
        if n > TARGET_MAX_CHARS {
            let head: String = e.target.chars().take(TARGET_MAX_CHARS).collect();
            v["target"] = format!("{head}… [cut at {TARGET_MAX_CHARS} of {n} characters]").into();
        }
        self.append(&v)
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

    /// Every line, oldest first, the older file's included; lines that do
    /// not parse are skipped.
    pub fn read(&self) -> std::io::Result<Vec<Value>> {
        let mut out = Vec::new();
        for p in [self.old_path(), self.path.clone()] {
            match std::fs::read_to_string(&p) {
                Ok(t) => out.extend(t.lines().filter_map(|l| serde_json::from_str(l).ok())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
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

    /// A refused call with a huge command line logs only its start.
    #[test]
    fn a_long_target_is_cut() {
        let d = tempfile::tempdir().unwrap();
        let log = AuditLog::new(d.path().join("audit.jsonl"));
        let e = Entry {
            ts: 1,
            center: "home".into(),
            cap: "exec".into(),
            action: "run".into(),
            target: "ü".repeat(3000),
            decision: "forbidden".into(),
            code: Some("forbidden".into()),
            session: None,
        };
        log.decision(&e).unwrap();
        let line = &log.read().unwrap()[0];
        let target = line["target"].as_str().unwrap();
        assert!(target.starts_with(&"ü".repeat(512)), "{target}");
        assert!(!target.starts_with(&"ü".repeat(513)), "{target}");
        assert!(
            target.ends_with("[cut at 512 of 3000 characters]"),
            "{target}"
        );
        // A short one stays as it is.
        log.decision(&Entry {
            target: "ls".into(),
            ..e
        })
        .unwrap();
        assert_eq!(log.read().unwrap()[1]["target"], "ls");
    }

    /// The log moves aside at its size limit, and only one old file is kept.
    #[test]
    fn the_log_rotates_and_keeps_one_old_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        let big = json!("x".repeat(1024 * 1024));
        let lines = 25;
        for v in 0..lines {
            let change = Change {
                key: "k".into(),
                old: Value::Null,
                new: big.clone(),
            };
            log.settings("center home", v, &[change]).unwrap();
        }
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let old = d.path().join("audit.jsonl.1");
        assert!(size(&path) <= AUDIT_MAX_BYTES, "{}", size(&path));
        assert!(size(&old) <= AUDIT_MAX_BYTES, "{}", size(&old));
        assert!(size(&old) > 0, "no old file");
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2);
        // Oldest first, newest last; the oldest lines are gone.
        let read = log.read().unwrap();
        assert!(read.len() < lines as usize, "{}", read.len());
        assert_eq!(read.last().unwrap()["version"], lines - 1);
        let versions: Vec<u64> = read
            .iter()
            .map(|l| l["version"].as_u64().unwrap())
            .collect();
        assert!(
            versions.windows(2).all(|w| w[1] == w[0] + 1),
            "{versions:?}"
        );
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
