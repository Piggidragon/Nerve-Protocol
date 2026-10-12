//! The local audit log: one JSON line per decision, per settings change and
//! per refused config file, in the node's state directory. It is the owner's record and client-only: no
//! center can read or change the file (centers see their own decisions as
//! `audit/decision` events at most).

use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// center, which is the one the event goes to. The target is cut as the
    /// log cuts it, so a huge command line never crosses the link.
    pub fn event_data(&self) -> Value {
        let mut v = serde_json::to_value(self).expect("an audit entry serializes");
        if let Some(o) = v.as_object_mut() {
            o.remove("center");
        }
        v["target"] = cut_target(&self.target).into();
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
/// The most of a full `audit.jsonl` that refused calls may take before the
/// oldest of them are dropped instead of the file being moved aside. A
/// center can make refused calls as fast as the link allows; with this it
/// never rotates the log by itself, and an entry of what the node allowed or
/// changed leaves the log only after at least this much newer such entries.
pub const REFUSED_MAX_BYTES: u64 = AUDIT_MAX_BYTES / 2;
/// How much of its newest refusals the file keeps when it drops the older.
const REFUSED_KEEP_BYTES: u64 = REFUSED_MAX_BYTES / 2;
/// The most characters of a target (a command line, a path) one decision
/// logs; a longer one is cut and says so.
pub const TARGET_MAX_CHARS: usize = 512;

/// `target` as an audit record keeps it: its first [`TARGET_MAX_CHARS`]
/// characters and how long it was. The node's log, its `audit/decision`
/// event and the center's audit feed all cut with this. A target cut once
/// stays as it is, so the center can cut what a node already cut.
pub fn cut_target(target: &str) -> Cow<'_, str> {
    let Some((end, _)) = target.char_indices().nth(TARGET_MAX_CHARS) else {
        return Cow::Borrowed(target);
    };
    if is_cut_target(target) {
        return Cow::Borrowed(target);
    }
    let n = TARGET_MAX_CHARS + target[end..].chars().count();
    Cow::Owned(format!(
        "{}… [cut at {TARGET_MAX_CHARS} of {n} characters]",
        &target[..end]
    ))
}

/// Whether `target` looks like what [`cut_target`] makes of a longer one.
/// A call's own target can look like this only at that same short length,
/// so one taken for cut is never longer than a cut one.
pub fn is_cut_target(target: &str) -> bool {
    let Some(rest) = target.strip_suffix(" characters]") else {
        return false;
    };
    let Some((head, n)) = rest.rsplit_once(&format!("… [cut at {TARGET_MAX_CHARS} of ")) else {
        return false;
    };
    head.chars().count() == TARGET_MAX_CHARS
        && n.parse::<usize>().is_ok_and(|n| n > TARGET_MAX_CHARS)
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    /// Whether the log could not be kept within its bound and said so; it
    /// says so once until it can again.
    unbounded: Arc<AtomicBool>,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> AuditLog {
        AuditLog {
            path: path.into(),
            unbounded: Arc::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The one older file the log keeps.
    pub fn old_path(&self) -> PathBuf {
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
        // each is logged; so the log is bounded. When it cannot be (a rename
        // that fails), the entry is written all the same.
        let mut unbounded = None;
        if let Ok(m) = std::fs::metadata(&self.path)
            && m.len() > 0
            && m.len() + line.len() as u64 > AUDIT_MAX_BYTES
        {
            match self.make_room(line.len() as u64) {
                Ok(()) => self.unbounded.store(false, Ordering::SeqCst),
                Err(e) => unbounded = Some(e),
            }
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
        f.write_all(line.as_bytes())?;
        match unbounded {
            Some(e) if !self.unbounded.swap(true, Ordering::SeqCst) => Err(std::io::Error::new(
                e.kind(),
                format!(
                    "the audit log could not be rotated ({e}); the entry was written, past the \
                     log's {} MiB bound, and so is every next one until it can be",
                    AUDIT_MAX_BYTES / (1024 * 1024)
                ),
            )),
            _ => Ok(()),
        }
    }

    /// Makes room in the full current file for a line of `len` bytes. When
    /// refused calls take more than [`REFUSED_MAX_BYTES`] of it, its oldest
    /// refusals are dropped, so they cannot push the older file out;
    /// otherwise, or when that is not room enough, the file is moved aside.
    fn make_room(&self, len: u64) -> std::io::Result<()> {
        let text = std::fs::read(&self.path)?;
        let refusal = |l: &[u8]| {
            serde_json::from_slice::<Value>(l)
                .is_ok_and(|v| v["decision"].as_str() == Some("forbidden"))
        };
        let refused: u64 = text
            .split_inclusive(|b| *b == b'\n')
            .filter(|l| refusal(l))
            .map(|l| l.len() as u64)
            .sum();
        if refused > REFUSED_MAX_BYTES {
            let mut extra = refused - REFUSED_KEEP_BYTES;
            let mut kept = Vec::with_capacity(text.len());
            for l in text.split_inclusive(|b| *b == b'\n') {
                if extra > 0 && refusal(l) {
                    extra = extra.saturating_sub(l.len() as u64);
                } else {
                    kept.extend_from_slice(l);
                }
            }
            nerve_transport::files::write_private(&self.path, &kept)?;
            if kept.len() as u64 + len <= AUDIT_MAX_BYTES {
                return Ok(());
            }
        }
        std::fs::rename(&self.path, self.old_path())
    }

    pub fn decision(&self, e: &Entry) -> std::io::Result<()> {
        let mut v = serde_json::to_value(e).expect("an audit entry serializes");
        v["target"] = cut_target(&e.target).into();
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
        Ok(self
            .lines()?
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    /// Every whole line as it is written, oldest first: the older file's,
    /// then the current one's. A last line still being written is left out.
    pub fn lines(&self) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        for p in [self.old_path(), self.path.clone()] {
            match std::fs::read(&p) {
                Ok(t) => {
                    let whole = t.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                    let t = String::from_utf8_lossy(&t[..whole]);
                    out.extend(t.lines().map(str::to_string));
                }
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
        // The event to the center carries the same cut target, so the full
        // one never crosses the link.
        let sent = e.event_data()["target"].as_str().unwrap().to_string();
        assert!(
            sent == target,
            "the event carries {} characters",
            sent.chars().count()
        );
        // A short one stays as it is.
        log.decision(&Entry {
            target: "ls".into(),
            ..e
        })
        .unwrap();
        assert_eq!(log.read().unwrap()[1]["target"], "ls");
    }

    /// Cutting twice changes nothing, and only a cut target reads as one.
    #[test]
    fn a_cut_target_is_cut_once() {
        let long = "a".repeat(600);
        let cut = cut_target(&long).into_owned();
        assert!(cut.ends_with("… [cut at 512 of 600 characters]"), "{cut}");
        assert!(is_cut_target(&cut));
        assert_eq!(cut_target(&cut), cut);
        assert_eq!(cut_target(&"a".repeat(512)), "a".repeat(512));
        assert!(!is_cut_target(&"a".repeat(512)));
        assert!(!is_cut_target("ls… [cut at 512 of 600 characters]"));
        let short_head = format!("{}… [cut at 512 of 512 characters]", "a".repeat(512));
        assert!(!is_cut_target(&short_head));
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

    fn refusal(ts: u64, target: String) -> Entry {
        Entry {
            ts,
            center: "lab".into(),
            cap: "exec".into(),
            action: "run".into(),
            target,
            decision: "forbidden".into(),
            code: Some("forbidden".into()),
            session: None,
        }
    }

    /// A center that makes refused calls as fast as it can does not push
    /// what the node allowed or changed out of the log: refusals have half of
    /// a file, and past that the oldest refusals go first. The log stays
    /// within twice its size limit and keeps the newest refusals (code
    /// review 2 of PR #19, finding 3).
    #[test]
    fn refusals_do_not_push_out_what_was_allowed() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        for ts in 0..3 {
            log.decision(&Entry {
                decision: "allowed".into(),
                code: None,
                ..refusal(ts, format!("allowed {ts}"))
            })
            .unwrap();
        }
        log.settings("center lab", 7, &diff(&json!({"m": 1}), &json!({"m": 2})))
            .unwrap();
        // 30 MiB of refusals, three times the size limit.
        let long = "x".repeat(600);
        let n = 3 * AUDIT_MAX_BYTES / 700;
        for ts in 10..10 + n {
            log.decision(&refusal(ts, format!("{ts} {long}"))).unwrap();
        }
        let read = log.read().unwrap();
        let allowed: Vec<&Value> = read.iter().filter(|l| l["decision"] == "allowed").collect();
        assert_eq!(allowed.len(), 3, "allowed entries were pushed out");
        assert!(
            read.iter().any(|l| l["kind"] == "settings"),
            "the settings entry was pushed out"
        );
        let last = read.last().unwrap();
        assert!(
            last["target"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{} ", 9 + n)),
            "the newest refusal is not the last line"
        );
        let refused = read.iter().filter(|l| l["decision"] == "forbidden").count() as u64;
        assert!(refused > 1000, "only {refused} refusals kept");
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let old = d.path().join("audit.jsonl.1");
        assert!(size(&path) <= AUDIT_MAX_BYTES, "{}", size(&path));
        assert!(size(&old) <= AUDIT_MAX_BYTES, "{}", size(&old));
        // The refusals kept are the newest, in order.
        let ts: Vec<u64> = read
            .iter()
            .filter(|l| l["decision"] == "forbidden")
            .filter_map(|l| l["ts"].as_u64())
            .collect();
        assert!(ts.windows(2).all(|w| w[0] < w[1]), "out of order");
    }

    /// A rotation that fails (here `audit.jsonl.1` is a directory, so the
    /// rename cannot replace it) does not drop the entry: it is written past
    /// the bound, and the failure is reported once (code review 2 of PR #19,
    /// finding 5).
    #[test]
    fn a_failed_rotation_still_writes_the_entry() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("audit.jsonl");
        let log = AuditLog::new(&path);
        let big = json!("x".repeat(1024 * 1024));
        let change = |v: u64| {
            log.settings(
                "center home",
                v,
                &[Change {
                    key: "k".into(),
                    old: Value::Null,
                    new: big.clone(),
                }],
            )
        };
        for v in 0..9 {
            change(v).unwrap();
        }
        let blocker = d.path().join("audit.jsonl.1");
        std::fs::create_dir(&blocker).unwrap();
        std::fs::write(blocker.join("x"), "").unwrap();
        let first = change(9);
        let second = change(10);
        let text = std::fs::read_to_string(&path).unwrap();
        let versions: Vec<u64> = text
            .lines()
            .map(|l| {
                serde_json::from_str::<Value>(l).unwrap()["version"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(versions, (0..11).collect::<Vec<u64>>());
        let e = first.unwrap_err();
        assert!(e.to_string().contains("was written"), "{e}");
        assert!(second.is_ok(), "the failure was reported twice: {second:?}");
        // Once the rotation works again, the log is bounded again.
        std::fs::remove_dir_all(&blocker).unwrap();
        change(11).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() < AUDIT_MAX_BYTES);
        assert!(blocker.is_file());
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
