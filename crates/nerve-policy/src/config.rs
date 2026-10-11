//! The node's configuration, `node.toml` (architecture §8.3).
//!
//! Every table is parsed with `deny_unknown_fields`: a misspelt key in a policy
//! file must be an error, not a rule that silently does nothing.
//!
//! What one center may read and change (with the settings grant `write`) is its
//! [`CenterDocument`]: its policy and its `paused` flag. Everything else, the
//! center list, pairing, grants, machine options, proxy, is client-only.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The longest `full` mode a center may set: 8 hours (architecture §5.1).
pub const FULL_MAX_MS: u64 = 8 * 3600 * 1000;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Counts every saved change; `settings.set` and the control socket check
    /// it (`if_version`) so two writers cannot overwrite each other unseen.
    #[serde(default)]
    pub version: u64,
    /// Set by `nerve-node panic`: every link is closed and nothing runs until
    /// `nerve-node unlock`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub locked: bool,
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub machine: Machine,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub connection: Connection,
    #[serde(default, rename = "center", skip_serializing_if = "Vec::is_empty")]
    pub centers: Vec<CenterEntry>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// The name the node pairs with; derived from the host name when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    /// The shell `exec.run` uses; `/bin/sh` (PowerShell on Windows) when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Whether the node may run as root at all.
    #[serde(default)]
    pub allow_root: bool,
    #[serde(default)]
    pub elevation: Elevation,
    #[serde(default)]
    pub secret_storage: SecretStorage,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Elevation {
    #[default]
    Off,
    /// Not done in 0.0.1 (see `nerve_sandbox::elevation`).
    Sudo,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretStorage {
    /// A 0600 key file per center below the config directory.
    #[default]
    File,
    /// The system keyring. Not done in 0.0.1.
    Keyring,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Commands running at once, over every center.
    #[serde(default = "d_max_running")]
    pub max_running: u32,
    /// stdout and stderr of one command are each cut at this size.
    #[serde(default = "d_output_cap")]
    pub output_cap_bytes: u64,
}

fn d_max_running() -> u32 {
    16
}
fn d_output_cap() -> u64 {
    16 * 1024 * 1024
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_running: d_max_running(),
            output_cap_bytes: d_output_cap(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    /// `http://host:port`; `HTTPS_PROXY`/`NO_PROXY` apply when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Extra header lines for the proxy's `CONNECT` request.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingsGrant {
    #[default]
    Off,
    Write,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalsGrant {
    /// The center and the node's owner may both answer.
    #[default]
    Both,
    /// Only the owner on the node may answer.
    Local,
}

/// One paired center.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterEntry {
    /// The owner's name for the center; the CLI's `--center`.
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    pub center_id: String,
    /// This node's id at the center (from its key for this center).
    pub node_id: String,
    #[serde(default)]
    pub settings: SettingsGrant,
    #[serde(default)]
    pub approvals: ApprovalsGrant,
    /// The node does not dial while paused (the center may pause, only the
    /// owner may unpause).
    #[serde(default, skip_serializing_if = "is_false")]
    pub paused: bool,
    /// The center sent `bye revoked`: the node does not dial again.
    #[serde(default, skip_serializing_if = "is_false")]
    pub revoked: bool,
    /// The center answered 401: it no longer knows this node.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unknown: bool,
    #[serde(default)]
    pub policy: CenterPolicy,
}

impl CenterEntry {
    /// Whether the node should keep a link to this center.
    pub fn dials(&self) -> bool {
        !self.paused && !self.revoked && !self.unknown
    }
}

/// The access modes (architecture §5.1).
///
/// Open point p04: the architecture names the modes `ask`, `folders` and
/// `full`; issue p04 asks whether they should be named Folder/User/Sudo
/// instead. Not decided; 0.0.1 keeps the architecture's names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Every read, write and command asks.
    #[default]
    Ask,
    /// Allowed inside the folders by their access, asks outside.
    Folders,
    /// Allowed everywhere except protected and denied paths, until `full_until`.
    Full,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Ask => "ask",
            Mode::Folders => "folders",
            Mode::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Ro,
    Rw,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    /// Absolute, in this platform's form.
    pub path: String,
    #[serde(default)]
    pub access: Access,
    /// Commands may run with a working directory inside it.
    #[serde(default)]
    pub execute: bool,
}

/// A capability's or an action's exposure, as the owner sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapSetting {
    On,
    Ask,
    Off,
    /// Absent from this center's descriptor.
    Hidden,
}

impl CapSetting {
    pub fn parse(s: &str) -> Option<CapSetting> {
        match s {
            "on" => Some(CapSetting::On),
            "ask" => Some(CapSetting::Ask),
            "off" => Some(CapSetting::Off),
            "hidden" => Some(CapSetting::Hidden),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedOptions {
    /// More protected paths (`~/...` or absolute).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
    /// Built-in protected paths the owner released.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// Command rules: globs over the whole command line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRules {
    /// Never run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// When not empty, only matching commands run at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Ask even where the mode would allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub always_ask: Vec<String>,
    /// Run without asking (unless the call is tainted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub never_ask: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnTimeout {
    #[default]
    Deny,
    /// Allow this one call.
    Allow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalTiming {
    #[serde(default = "d_timeout")]
    pub timeout_s: u64,
    #[serde(default)]
    pub on_timeout: OnTimeout,
    /// What a `session` answer is remembered for at most.
    #[serde(default = "d_remember")]
    pub remember_minutes: u32,
    /// The longest `time` answer.
    #[serde(default = "d_max_minutes")]
    pub max_minutes: u32,
}

fn d_timeout() -> u64 {
    120
}
fn d_remember() -> u32 {
    480
}
fn d_max_minutes() -> u32 {
    480
}

impl Default for ApprovalTiming {
    fn default() -> ApprovalTiming {
        ApprovalTiming {
            timeout_s: d_timeout(),
            on_timeout: OnTimeout::default(),
            remember_minutes: d_remember(),
            max_minutes: d_max_minutes(),
        }
    }
}

/// What one center may do on this node.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterPolicy {
    #[serde(default)]
    pub mode: Mode,
    /// Milliseconds since the Unix epoch at which `full` falls back to
    /// `folders`. Required with `full`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_until: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<Folder>,
    /// `cap` or `cap.action` → setting; `cap.action` wins over `cap`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps: BTreeMap<String, CapSetting>,
    #[serde(default)]
    pub protected: ProtectedOptions,
    /// Paths nothing may touch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(default)]
    pub commands: CommandRules,
    #[serde(default)]
    pub approvals: ApprovalTiming,
}

impl CenterPolicy {
    /// The mode in force at `now_ms`: an expired `full` is `folders`.
    pub fn mode_at(&self, now_ms: u64) -> Mode {
        match self.mode {
            Mode::Full if self.full_until.is_none_or(|u| u <= now_ms) => Mode::Folders,
            m => m,
        }
    }

    /// The owner's setting for `cap.action`, else for `cap`.
    pub fn cap_setting(&self, cap: &str, action: Option<&str>) -> Option<CapSetting> {
        action
            .and_then(|a| self.caps.get(&format!("{cap}.{a}")))
            .or_else(|| self.caps.get(cap))
            .copied()
    }
}

/// The part of the config one center may read and set (`settings` profile).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterDocument {
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub policy: CenterPolicy,
}

impl NodeConfig {
    /// Parses and checks `node.toml`.
    pub fn parse(text: &str) -> Result<NodeConfig, String> {
        let c: NodeConfig = toml::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("the node config serializes")
    }

    /// Reads `path`; a missing file is the default config.
    pub fn load(path: &Path) -> Result<NodeConfig, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => NodeConfig::parse(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NodeConfig::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Writes `path` atomically, 0600.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        nerve_transport::files::write_private(path, self.to_toml().as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn center(&self, name: &str) -> Option<&CenterEntry> {
        self.centers.iter().find(|c| c.name == name)
    }

    pub fn center_mut(&mut self, name: &str) -> Option<&mut CenterEntry> {
        self.centers.iter_mut().find(|c| c.name == name)
    }

    /// The checks serde cannot do.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(n) = &self.node.name
            && !nerve_proto::valid_node_name(n)
        {
            return Err(format!(
                "node.name {n:?}: 1 to 32 characters of a-z, 0-9 and -"
            ));
        }
        if self.limits.max_running == 0 {
            return Err("limits.max_running must be at least 1".into());
        }
        if let Some(p) = &self.connection.proxy {
            let headers = self
                .connection
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            nerve_transport::Proxy::parse(p, headers)
                .map_err(|e| format!("connection.proxy: {e}"))?;
        }
        let mut names = std::collections::BTreeSet::new();
        for c in &self.centers {
            if !valid_center_name(&c.name) {
                return Err(format!(
                    "center name {:?}: 1 to 64 characters of a-z, A-Z, 0-9, - and _",
                    c.name
                ));
            }
            if !names.insert(c.name.as_str()) {
                return Err(format!("two centers are named {:?}", c.name));
            }
            nerve_proto::link::CenterUrl::parse(&c.url)
                .map_err(|e| format!("center {}: {e}", c.name))?;
            c.policy
                .validate()
                .map_err(|e| format!("center {}: {e}", c.name))?;
        }
        Ok(())
    }
}

/// A center's name as the CLI and the key file name use it.
pub fn valid_center_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl CenterPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.mode == Mode::Full && self.full_until.is_none() {
            return Err("mode full needs full_until".into());
        }
        for f in &self.folders {
            if !Path::new(&f.path).is_absolute() {
                return Err(format!("folder {:?} is not absolute", f.path));
            }
        }
        for d in &self.deny {
            if !(Path::new(d).is_absolute() || d.starts_with("~/") || d == "~") {
                return Err(format!("deny path {d:?} is neither absolute nor ~/..."));
            }
        }
        for p in self.protected.extra.iter().chain(&self.protected.allow) {
            if !(Path::new(p).is_absolute() || p.starts_with("~/")) {
                return Err(format!(
                    "protected path {p:?} is neither absolute nor ~/..."
                ));
            }
        }
        for key in self.caps.keys() {
            let ok = !key.is_empty()
                && key.split('.').count() <= 2
                && key.split('.').all(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                });
            if !ok {
                return Err(format!("caps key {key:?}: `cap` or `cap.action`"));
            }
        }
        let c = &self.commands;
        for g in c
            .deny
            .iter()
            .chain(&c.allow)
            .chain(&c.always_ask)
            .chain(&c.never_ask)
        {
            globset::Glob::new(g).map_err(|e| format!("command rule {g:?}: {e}"))?;
        }
        let a = &self.approvals;
        if a.timeout_s == 0 || a.timeout_s > 24 * 3600 {
            return Err("approvals.timeout_s must be 1 to 86400".into());
        }
        if a.max_minutes == 0 {
            return Err("approvals.max_minutes must be at least 1".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TEMPLATE: &str = r#"
[node]
name = "laptop"

[machine]
shell = "/bin/bash"
elevation = "off"

[limits]
max_running = 4

[connection]
proxy = "http://127.0.0.1:3128"

[[center]]
name = "home"
url = "https://center.example:8443"
pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
center_id = "c1"
node_id = "n1"
settings = "write"
approvals = "local"

[center.policy]
mode = "folders"
folders = [{ path = "FOLDER", access = "rw", execute = true }]
deny = ["~/private"]
caps = { exec = "ask", "fs.write" = "off" }

[center.policy.commands]
deny = ["rm -rf *"]

[center.policy.approvals]
timeout_s = 30
on_timeout = "allow"
"#;

    /// An absolute folder on the platform the tests run on.
    const FOLDER: &str = if cfg!(windows) {
        "C:/u/proj"
    } else {
        "/home/u/proj"
    };

    fn sample() -> String {
        SAMPLE_TEMPLATE.replace("FOLDER", FOLDER)
    }

    #[test]
    fn parses_round_trips_and_defaults() {
        let c = NodeConfig::parse(&sample()).unwrap();
        assert_eq!(c.limits.max_running, 4);
        assert_eq!(c.limits.output_cap_bytes, 16 * 1024 * 1024);
        let home = c.center("home").unwrap();
        assert_eq!(home.settings, SettingsGrant::Write);
        assert_eq!(home.approvals, ApprovalsGrant::Local);
        assert_eq!(home.policy.mode, Mode::Folders);
        assert_eq!(home.policy.approvals.on_timeout, OnTimeout::Allow);
        assert_eq!(home.policy.approvals.max_minutes, 480);
        assert_eq!(
            home.policy.cap_setting("fs", Some("write")),
            Some(CapSetting::Off)
        );
        assert_eq!(home.policy.cap_setting("fs", Some("read")), None);
        assert_eq!(
            home.policy.cap_setting("exec", Some("run")),
            Some(CapSetting::Ask)
        );
        let again = NodeConfig::parse(&c.to_toml()).unwrap();
        assert_eq!(again, c);
        assert_eq!(NodeConfig::parse("").unwrap(), NodeConfig::default());
    }

    #[test]
    fn refuses_unknown_keys_and_bad_values() {
        for (bad, why) in [
            ("[node]\nnmae = \"x\"\n", "unknown field"),
            ("[node]\nname = \"Bad Name\"\n", "node.name"),
            ("[limits]\nmax_running = 0\n", "max_running"),
            ("[connection]\nproxy = \"https://p:1\"\n", "proxy"),
            ("[machine]\nelevation = \"doas\"\n", "unknown variant"),
        ] {
            let e = NodeConfig::parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        let with = |extra: &str| {
            sample().replace(
                "[center.policy.commands]",
                &format!("{extra}\n[center.policy.commands]"),
            )
        };
        assert!(NodeConfig::parse(&with("full_until = 1\nfoo = 1")).is_err());
        let full = sample().replace("mode = \"folders\"", "mode = \"full\"");
        assert!(NodeConfig::parse(&full).unwrap_err().contains("full_until"));
        let rel = sample().replace(FOLDER, "proj");
        assert!(NodeConfig::parse(&rel).unwrap_err().contains("absolute"));
        let sample = sample();
        let two = format!(
            "{sample}\n{}",
            &sample[sample.find("[[center]]").unwrap()..]
        );
        assert!(NodeConfig::parse(&two).unwrap_err().contains("two centers"));
    }

    #[test]
    fn expired_full_is_folders() {
        let p = CenterPolicy {
            mode: Mode::Full,
            full_until: Some(1000),
            ..Default::default()
        };
        assert_eq!(p.mode_at(999), Mode::Full);
        assert_eq!(p.mode_at(1000), Mode::Folders);
    }

    #[test]
    fn saves_private_and_loads_back() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("cfg/node.toml");
        assert_eq!(NodeConfig::load(&path).unwrap(), NodeConfig::default());
        let c = NodeConfig::parse(&sample()).unwrap();
        c.save(&path).unwrap();
        assert_eq!(NodeConfig::load(&path).unwrap(), c);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
