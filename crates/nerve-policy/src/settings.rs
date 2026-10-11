//! The settings store: `node.toml` with a version, written by the owner (CLI,
//! control socket) and, with the settings grant `write`, by a center for its
//! own [`CenterDocument`] (architecture §5.2, §5.3; spec §7.5).
//!
//! Every change is whole-document with `if_version`, so two writers never
//! overwrite each other unseen, is validated before it is saved, and lands in
//! the audit log with its old and new values and who made it.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::audit::{AuditLog, diff};
use crate::config::{CapSetting, CenterDocument, FULL_MAX_MS, Mode, NodeConfig, SettingsGrant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetError {
    /// `if_version` is not the current version.
    Conflict { current: u64 },
    /// A client-only field changed, or the center has no settings grant.
    Forbidden(String),
    /// The new document does not parse or validate.
    Invalid(String),
    /// Saving failed.
    Io(String),
}

impl std::fmt::Display for SetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetError::Conflict { current } => {
                write!(f, "the settings changed; the current version is {current}")
            }
            SetError::Forbidden(s) | SetError::Invalid(s) | SetError::Io(s) => write!(f, "{s}"),
        }
    }
}

/// Who changes the settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer<'a> {
    Local,
    Center(&'a str),
}

impl Writer<'_> {
    pub fn label(&self) -> String {
        match self {
            Writer::Local => "local".into(),
            Writer::Center(n) => format!("center {n}"),
        }
    }
}

pub struct SettingsStore {
    path: PathBuf,
    audit: AuditLog,
    config: NodeConfig,
}

impl SettingsStore {
    /// Loads `path` (a missing file is the default config).
    pub fn open(path: impl Into<PathBuf>, audit: AuditLog) -> Result<SettingsStore, String> {
        let path = path.into();
        let config = NodeConfig::load(&path)?;
        Ok(SettingsStore {
            path,
            audit,
            config,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn version(&self) -> u64 {
        self.config.version
    }

    /// Reads the file again (SIGHUP, or the CLI edited it while the daemon
    /// ran). A file that does not validate leaves the old config in force.
    pub fn reload(&mut self) -> Result<bool, String> {
        let fresh = NodeConfig::load(&self.path)?;
        let changed = fresh != self.config;
        self.config = fresh;
        Ok(changed)
    }

    /// Replaces the whole config as the owner; `if_version` guards against a
    /// concurrent writer.
    pub fn set_local(&mut self, new: NodeConfig, if_version: Option<u64>) -> Result<u64, SetError> {
        if let Some(v) = if_version
            && v != self.config.version
        {
            return Err(SetError::Conflict {
                current: self.config.version,
            });
        }
        self.commit(Writer::Local, new)
    }

    /// Changes the config as the owner through a closure (CLI commands).
    pub fn update(
        &mut self,
        f: impl FnOnce(&mut NodeConfig) -> Result<(), String>,
    ) -> Result<u64, SetError> {
        let mut new = self.config.clone();
        f(&mut new).map_err(SetError::Invalid)?;
        self.commit(Writer::Local, new)
    }

    /// Updates bookkeeping the node itself sets (revoked, unknown) without
    /// counting it as a settings change by anyone.
    pub fn mark(&mut self, f: impl FnOnce(&mut NodeConfig)) -> Result<(), String> {
        let mut new = self.config.clone();
        f(&mut new);
        if new == self.config {
            return Ok(());
        }
        new.version = self.config.version + 1;
        new.save(&self.path)?;
        self.config = new;
        Ok(())
    }

    /// The document `settings.get` shows `center`.
    pub fn center_document(&self, center: &str) -> Option<CenterDocument> {
        self.config.center(center).map(|c| CenterDocument {
            paused: c.paused,
            policy: c.policy.clone(),
        })
    }

    /// `settings.set` from `center`: the whole document, checked against
    /// `if_version`. `is_sense(cap)` says whether a capability senses
    /// (camera, microphone, screen): only the owner may turn those on.
    pub fn set_center_document(
        &mut self,
        center: &str,
        document: Value,
        if_version: u64,
        now_ms: u64,
        is_sense: impl Fn(&str) -> bool,
    ) -> Result<u64, SetError> {
        let entry = self
            .config
            .center(center)
            .ok_or_else(|| SetError::Forbidden(format!("no center {center}")))?;
        if entry.settings != SettingsGrant::Write {
            return Err(SetError::Forbidden(
                "this node does not let this center change its settings".into(),
            ));
        }
        if if_version != self.config.version {
            return Err(SetError::Conflict {
                current: self.config.version,
            });
        }
        let new: CenterDocument =
            serde_json::from_value(document).map_err(|e| SetError::Invalid(e.to_string()))?;
        new.policy
            .validate()
            .map_err(|e| SetError::Invalid(e.to_string()))?;
        let old = CenterDocument {
            paused: entry.paused,
            policy: entry.policy.clone(),
        };
        client_only(&old, &new, now_ms, &is_sense).map_err(SetError::Forbidden)?;
        let mut cfg = self.config.clone();
        let e = cfg.center_mut(center).expect("checked above");
        e.paused = new.paused;
        e.policy = new.policy;
        self.commit(Writer::Center(center), cfg)
    }

    fn commit(&mut self, by: Writer, mut new: NodeConfig) -> Result<u64, SetError> {
        new.version = self.config.version;
        new.validate().map_err(SetError::Invalid)?;
        if new == self.config {
            return Ok(self.config.version);
        }
        new.version = self.config.version + 1;
        new.save(&self.path).map_err(SetError::Io)?;
        let changes = diff(&to_json(&self.config), &to_json(&new));
        let version = new.version;
        self.config = new;
        // The change is saved; an audit log that cannot be written is logged
        // by the caller's tracing, not a reason to undo it.
        let _ = self.audit.settings(&by.label(), version, &changes);
        Ok(version)
    }
}

fn to_json(c: &NodeConfig) -> Value {
    let mut v = serde_json::to_value(c).expect("the node config serializes");
    if let Some(o) = v.as_object_mut() {
        o.remove("version");
    }
    v
}

/// The fields of its own document a center may not change (architecture
/// §5.3). The whole document is refused, naming the first such field.
fn client_only(
    old: &CenterDocument,
    new: &CenterDocument,
    now_ms: u64,
    is_sense: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    if old.paused && !new.paused {
        return Err("paused: only the owner can unpause".into());
    }
    let (o, n) = (&old.policy, &new.policy);
    for (key, setting) in &n.caps {
        let cap = key.split('.').next().unwrap_or(key);
        if *setting == CapSetting::On && o.caps.get(key) != Some(&CapSetting::On) && is_sense(cap) {
            return Err(format!(
                "policy.caps.{key}: only the owner can turn sensing on"
            ));
        }
    }
    if n.protected.allow != o.protected.allow {
        // Releasing a protected path is the owner's call; adding more is fine.
        return Err("policy.protected.allow: only the owner can release protected paths".into());
    }
    if n.mode == Mode::Full
        && n.full_until != o.full_until
        && n.full_until.is_some_and(|u| u > now_ms + FULL_MAX_MS)
    {
        return Err("policy.full_until: at most 8 hours from now".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CenterEntry, CenterPolicy};
    use serde_json::json;

    fn store(dir: &Path, grant: SettingsGrant) -> SettingsStore {
        let mut s = SettingsStore::open(
            dir.join("node.toml"),
            AuditLog::new(dir.join("audit.jsonl")),
        )
        .unwrap();
        s.update(|c| {
            c.centers.push(CenterEntry {
                name: "home".into(),
                url: "https://center.example".into(),
                pin: None,
                center_id: "c".into(),
                node_id: "n".into(),
                settings: grant,
                approvals: Default::default(),
                paused: false,
                revoked: false,
                unknown: false,
                policy: CenterPolicy::default(),
            });
            Ok(())
        })
        .unwrap();
        s
    }

    fn doc(s: &SettingsStore) -> Value {
        serde_json::to_value(s.center_document("home").unwrap()).unwrap()
    }

    #[test]
    fn center_sets_with_version_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["mode"] = json!("folders");
        let v2 = s
            .set_center_document("home", new.clone(), v, 0, |_| false)
            .unwrap();
        assert_eq!(v2, v + 1);
        assert_eq!(
            s.config().center("home").unwrap().policy.mode,
            Mode::Folders
        );
        // A stale version conflicts.
        assert_eq!(
            s.set_center_document("home", new, v, 0, |_| false),
            Err(SetError::Conflict { current: v2 })
        );
        // Saved and reloaded.
        let again = SettingsStore::open(
            d.path().join("node.toml"),
            AuditLog::new(d.path().join("a")),
        )
        .unwrap();
        assert_eq!(again.version(), v2);
        let log = s.audit().read().unwrap();
        let last = log.last().unwrap();
        assert_eq!(last["by"], "center home");
        assert_eq!(last["changes"][0]["key"], "center");
    }

    #[test]
    fn refuses_client_only_fields_and_missing_grant() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Write);
        let v = s.version();
        let mut new = doc(&s);
        new["policy"]["caps"] = json!({"camera": "on"});
        let e = s
            .set_center_document("home", new, v, 0, |c| c == "camera")
            .unwrap_err();
        assert!(matches!(&e, SetError::Forbidden(m) if m.contains("policy.caps.camera")));
        let mut new = doc(&s);
        new["policy"]["protected"] = json!({"allow": ["~/.ssh"]});
        assert!(matches!(
            s.set_center_document("home", new, v, 0, |_| false),
            Err(SetError::Forbidden(_))
        ));
        let mut new = doc(&s);
        new["policy"]["mode"] = json!("full");
        new["policy"]["full_until"] = json!(FULL_MAX_MS + 1);
        assert!(matches!(
            s.set_center_document("home", new, v, 0, |_| false),
            Err(SetError::Forbidden(_))
        ));
        let mut new = doc(&s);
        new["policy"]["nope"] = json!(1);
        assert!(matches!(
            s.set_center_document("home", new, v, 0, |_| false),
            Err(SetError::Invalid(_))
        ));
        // The center may pause, not unpause.
        let mut new = doc(&s);
        new["paused"] = json!(true);
        let v = s.set_center_document("home", new, v, 0, |_| false).unwrap();
        let mut new = doc(&s);
        new["paused"] = json!(false);
        assert!(matches!(
            s.set_center_document("home", new, v, 0, |_| false),
            Err(SetError::Forbidden(_))
        ));
        assert_eq!(s.version(), v);

        let d2 = tempfile::tempdir().unwrap();
        let mut off = store(d2.path(), SettingsGrant::Off);
        let v = off.version();
        let new = doc(&off);
        assert!(matches!(
            off.set_center_document("home", new, v, 0, |_| false),
            Err(SetError::Forbidden(_))
        ));
    }

    #[test]
    fn local_writes_check_version_and_validate() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path(), SettingsGrant::Off);
        let v = s.version();
        let mut c = s.config().clone();
        c.limits.max_running = 0;
        assert!(matches!(s.set_local(c, Some(v)), Err(SetError::Invalid(_))));
        let mut c = s.config().clone();
        c.limits.max_running = 2;
        assert_eq!(
            s.set_local(c.clone(), Some(v + 7)),
            Err(SetError::Conflict { current: v })
        );
        assert_eq!(s.set_local(c, Some(v)).unwrap(), v + 1);
        let log = s.audit().read().unwrap();
        assert_eq!(log.last().unwrap()["by"], "local");
        // An unchanged config is no new version.
        let same = s.config().clone();
        assert_eq!(s.set_local(same, None).unwrap(), v + 1);
    }
}
