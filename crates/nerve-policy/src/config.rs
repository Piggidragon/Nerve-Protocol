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
    /// The node's sudo switch (one per node, not per center). The password
    /// is never in this file; the node keeps it in memory while the switch
    /// is on, so a restarted node starts with the switch off.
    #[serde(default)]
    pub sudo: Sudo,
    /// The `sudo` program; `sudo` from `PATH` when unset. Only the owner
    /// sets it: a fake `sudo` would catch the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo_path: Option<String>,
    #[serde(default)]
    pub secret_storage: SecretStorage,
}

/// The sudo switch. Off, no command runs through `sudo`, whatever the rules
/// say. On, a `sudo` command runs only when the sudo allow list names it, in
/// every mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sudo {
    #[default]
    Off,
    On,
}

impl Sudo {
    pub fn as_str(self) -> &'static str {
        match self {
            Sudo::Off => "off",
            Sudo::On => "on",
        }
    }
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
    /// `http://host:port`, never with a user name and password;
    /// `HTTPS_PROXY`/`NO_PROXY` apply when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// The names of the extra header lines for the proxy's `CONNECT`
    /// request. Their values are secrets and live in the system keyring
    /// (`nerve-node proxy set`), never in this file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
}

/// Why a `node.toml` that keeps proxy secrets in the file is refused.
pub const PROXY_SECRETS_IN_FILE: &str = "connection holds proxy secrets (header values, or a user name and password in the proxy URL), which belong in the system keyring, not in node.toml: run `nerve-node proxy set` again (for a file of an earlier build, delete them from it and take it with `nerve-node config accept` first)";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingsGrant {
    #[default]
    Off,
    Write,
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

/// The permission modes (architecture §5.1). A call no mode and no rule
/// allows is refused at once; nothing waits for an answer. Deny rules work in
/// every mode and win over everything else; allow rules count only in
/// `allowlist`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Default deny: a call runs only when an allow rule lets it through.
    /// What a new center starts in.
    #[default]
    Allowlist,
    /// Full access inside the folders, by their flags: reading where `r` is
    /// set, writing where `w` is, commands where `x` is, in the folders and
    /// everything below them.
    Folder,
    /// Full access as the user, protected paths aside.
    User,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Allowlist => "allowlist",
            Mode::Folder => "folder",
            Mode::User => "user",
        }
    }
}

/// What a center may do with a folder: three independent flags, every
/// combination allowed. In the config it is the string of the letters that
/// are set, `"rx"` (`""` for none).
///
/// - `read`: read the files and list the directories (fs read actions).
/// - `write`: create, change and delete (fs write actions).
/// - `execute`: run commands with a working directory in it, and run the
///   programs it holds.
///
/// A write-only folder is legal: the sandbox grants the write rights without
/// the read rights, so a command can put files there but not read them back
/// or list the folder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Access {
    pub const NONE: Access = Access {
        read: false,
        write: false,
        execute: false,
    };
    pub const ALL: Access = Access {
        read: true,
        write: true,
        execute: true,
    };

    /// `r`, `w` or `x`, each at most once, in any order; `""` is none.
    pub fn parse(s: &str) -> Result<Access, String> {
        let mut a = Access::NONE;
        for c in s.chars() {
            let flag = match c {
                'r' => &mut a.read,
                'w' => &mut a.write,
                'x' => &mut a.execute,
                other => {
                    return Err(format!("{s:?}: {other:?} is not a folder flag (r, w or x)"));
                }
            };
            if std::mem::replace(flag, true) {
                return Err(format!("{s:?}: {c:?} is given twice"));
            }
        }
        Ok(a)
    }

    /// One chmod-style change: `=rwx` replaces all three flags with the
    /// letters after it (`=` alone clears them), `+x` sets the flags named and
    /// `-w` clears them; the others stay.
    pub fn change(self, spec: &str) -> Result<Access, String> {
        let (op, letters) = match spec.chars().next() {
            Some(op @ ('=' | '+' | '-')) => (op, &spec[1..]),
            _ => return Err(format!("{spec:?}: start with =, + or - (=rwx, +x, -w)")),
        };
        if letters.is_empty() && op != '=' {
            return Err(format!("{spec:?}: name at least one of r, w, x after {op}"));
        }
        let named = Access::parse(letters).map_err(|e| format!("{spec:?}: {e}"))?;
        Ok(match op {
            '=' => named,
            '+' => Access {
                read: self.read || named.read,
                write: self.write || named.write,
                execute: self.execute || named.execute,
            },
            _ => Access {
                read: self.read && !named.read,
                write: self.write && !named.write,
                execute: self.execute && !named.execute,
            },
        })
    }

    pub fn is_none(self) -> bool {
        self == Access::NONE
    }

    /// The flags that are set, as `ls -l` shows them: `rw-`, `r-x`, `---`.
    pub fn to_chmod(self) -> String {
        [(self.read, 'r'), (self.write, 'w'), (self.execute, 'x')]
            .iter()
            .map(|(on, c)| if *on { *c } else { '-' })
            .collect()
    }
}

/// The config form: the letters that are set, `rwx` order.
impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (on, c) in [(self.read, 'r'), (self.write, 'w'), (self.execute, 'x')] {
            if on {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

impl TryFrom<String> for Access {
    type Error = String;
    fn try_from(s: String) -> Result<Access, String> {
        Access::parse(&s)
    }
}

impl From<Access> for String {
    fn from(a: Access) -> String {
        a.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Folder {
    /// Absolute, in this platform's form.
    pub path: String,
    /// Without it the folder grants nothing.
    #[serde(default)]
    pub access: Access,
}

/// A capability's or an action's exposure, as the owner sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapSetting {
    /// Allows sense and actuate actions, which no mode allows; for the other
    /// actions the mode still decides.
    On,
    /// Refused.
    Off,
    /// Absent from this center's descriptor.
    Hidden,
}

impl CapSetting {
    pub fn parse(s: &str) -> Option<CapSetting> {
        match s {
            "on" => Some(CapSetting::On),
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

/// What one center may do on this node.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterPolicy {
    #[serde(default)]
    pub mode: Mode,
    /// An opt-in time limit for `folder` and `user`: milliseconds since the
    /// Unix epoch at which the mode runs out and the center falls back to
    /// `allowlist`. None means no limit: the mode stays until the owner
    /// changes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<Folder>,
    /// `cap` or `cap.action` → setting; `cap.action` wins over `cap`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub caps: BTreeMap<String, CapSetting>,
    #[serde(default)]
    pub protected: ProtectedOptions,
    /// Allow rules (`crate::rules`). They count only in `allowlist` mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Deny rules: they refuse in every mode and win over any allow.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    /// Globs over the whole command line of a `sudo` command. A sudo command
    /// runs only when one matches, in every mode (and only with the sudo
    /// switch on); the normal allow list does not count for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sudo_allow: Vec<String>,
}

impl CenterPolicy {
    /// The mode in force at `now_ms`: a `folder` or `user` whose limit has
    /// passed is `allowlist`.
    pub fn mode_at(&self, now_ms: u64) -> Mode {
        match self.mode {
            Mode::Folder | Mode::User if self.until.is_some_and(|u| u <= now_ms) => Mode::Allowlist,
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
    /// Parses and checks `node.toml`; unknown keys are errors.
    pub fn parse(text: &str) -> Result<NodeConfig, String> {
        refuse_proxy_secrets(text)?;
        let c: NodeConfig = toml::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("the node config serializes")
    }

    /// Reads `path`; a missing file is the default config. The MAC line the
    /// node writes is a comment here and is not checked: the daemon and the
    /// CLI read the file through `SettingsStore`, which checks it.
    pub fn load(path: &Path) -> Result<NodeConfig, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => NodeConfig::parse(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(NodeConfig::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Writes `path` atomically, 0600, without a MAC: once the node has its
    /// key it refuses such a file. The node writes through `SettingsStore`.
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
            if has_user_info(p) {
                return Err(PROXY_SECRETS_IN_FILE.into());
            }
            nerve_transport::Proxy::parse(p, Vec::new())
                .map_err(|e| format!("connection.proxy: {e}"))?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for (i, h) in self.connection.headers.iter().enumerate() {
            // Not echoed: a value typed where the name belongs is a secret.
            if !nerve_transport::net::valid_header_name(h) {
                return Err(format!(
                    "connection.headers: entry {} is not a header name (letters, digits and -)",
                    i + 1
                ));
            }
            if !seen.insert(h.to_ascii_lowercase()) {
                return Err(format!("connection.headers names {h} twice"));
            }
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

/// Refuses a file that keeps a proxy secret: a `connection.headers` table
/// (name to value, as earlier builds wrote it) or a proxy URL with a user name
/// and password. This runs on the raw TOML, before the typed parse, whose
/// errors quote the offending line and so would quote the secret. Anything
/// but a list of strings in `connection.headers` is refused the same way
/// without quoting it.
fn refuse_proxy_secrets(text: &str) -> Result<(), String> {
    let Ok(doc) = toml::from_str::<toml::Table>(text) else {
        // Not TOML at all: the typed parse says why.
        return Ok(());
    };
    let Some(conn) = doc.get("connection").and_then(toml::Value::as_table) else {
        return Ok(());
    };
    if let Some(p) = conn.get("proxy").and_then(toml::Value::as_str)
        && has_user_info(p)
    {
        return Err(PROXY_SECRETS_IN_FILE.into());
    }
    match conn.get("headers") {
        None => Ok(()),
        Some(toml::Value::Table(_)) => Err(PROXY_SECRETS_IN_FILE.into()),
        Some(toml::Value::Array(a)) if a.iter().all(toml::Value::is_str) => Ok(()),
        Some(_) => Err("connection.headers is a list of header names".into()),
    }
}

/// Whether a URL carries a user name or password (`http://user:pass@host`).
fn has_user_info(url: &str) -> bool {
    url.contains('@')
}

/// A center's name as the CLI and the key file name use it.
pub fn valid_center_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl CenterPolicy {
    pub fn validate(&self) -> Result<(), String> {
        for f in &self.folders {
            if !Path::new(&f.path).is_absolute() {
                return Err(format!("folder {:?} is not absolute", f.path));
            }
        }
        for rule in self.allow.iter().chain(&self.deny) {
            crate::rules::validate(rule)?;
        }
        for glob in &self.sudo_allow {
            crate::rules::validate_command_glob(glob)?;
        }
        for p in self.protected.extra.iter().chain(&self.protected.allow) {
            if !(Path::new(p).is_absolute() || p.starts_with("~/")) {
                return Err(format!(
                    "protected path {p:?} is neither absolute nor ~/..."
                ));
            }
        }
        for key in self.caps.keys() {
            if !crate::rules::valid_scope(key) {
                return Err(format!("caps key {key:?}: `cap` or `cap.action`"));
            }
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
sudo = "off"

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

[center.policy]
mode = "folder"
folders = [{ path = "FOLDER", access = "rwx" }]
caps = { exec = "on", "fs.write" = "off" }
allow = ["exec.run:git status", "fs.read:~/notes/*"]
deny = ["fs:~/private/*", "exec.run:rm -rf *"]
sudo_allow = ["sudo apt update"]
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
        assert_eq!(home.policy.mode, Mode::Folder);
        assert_eq!(
            home.policy.allow,
            ["exec.run:git status", "fs.read:~/notes/*"]
        );
        assert_eq!(home.policy.deny.len(), 2);
        assert_eq!(home.policy.sudo_allow, ["sudo apt update"]);
        assert_eq!(
            home.policy.cap_setting("fs", Some("write")),
            Some(CapSetting::Off)
        );
        assert_eq!(home.policy.cap_setting("fs", Some("read")), None);
        assert_eq!(
            home.policy.cap_setting("exec", Some("run")),
            Some(CapSetting::On)
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
            ("[machine]\nsudo = \"doas\"\n", "unknown variant"),
        ] {
            let e = NodeConfig::parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        let with = |extra: &str| format!("{}{extra}\n", sample());
        assert!(NodeConfig::parse(&with("until = 1\nfoo = 1")).is_err());
        // User mode needs no limit; none is the default.
        let user = sample().replace("mode = \"folder\"", "mode = \"user\"");
        let c = NodeConfig::parse(&user).unwrap();
        assert_eq!(c.centers[0].policy.until, None);
        assert_eq!(c.centers[0].policy.mode_at(u64::MAX), Mode::User);
        let rel = sample().replace(FOLDER, "proj");
        assert!(NodeConfig::parse(&rel).unwrap_err().contains("absolute"));
        let sample = sample();
        let two = format!(
            "{sample}\n{}",
            &sample[sample.find("[[center]]").unwrap()..]
        );
        assert!(NodeConfig::parse(&two).unwrap_err().contains("two centers"));
        // A rule must say what it is about; a bare path or command is no rule.
        for bad in [
            "deny = [\"~/private\"]",
            "allow = [\"git status\"]",
            "allow = [\"fs:/a/[\"]",
            "sudo_allow = [\"sudo [\"]",
            "caps = { \"a.b.c\" = \"on\" }",
        ] {
            assert!(NodeConfig::parse(&center(bad)).is_err(), "{bad}");
        }
        assert!(NodeConfig::parse(&center("allow = [\"fs:/a/*\"]")).is_ok());
    }

    /// A config with one center whose policy is `policy`.
    fn center(policy: &str) -> String {
        format!(
            "[[center]]\nname = \"home\"\nurl = \"https://c.example:8443\"\ncenter_id = \"c\"\nnode_id = \"n\"\n[center.policy]\n{policy}\n"
        )
    }

    #[test]
    fn a_new_center_starts_in_allowlist_mode_with_no_rule() {
        let p = CenterPolicy::default();
        assert_eq!(p.mode, Mode::Allowlist);
        assert!(p.allow.is_empty() && p.deny.is_empty() && p.sudo_allow.is_empty());
        let c = NodeConfig::parse(&center("")).unwrap();
        assert_eq!(c.centers[0].policy.mode, Mode::Allowlist);
        for m in [Mode::Allowlist, Mode::Folder, Mode::User] {
            let json = serde_json::json!(m.as_str());
            assert_eq!(serde_json::from_value::<Mode>(json).unwrap(), m);
        }
    }

    #[test]
    fn a_mode_without_a_limit_never_runs_out() {
        for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
            let p = CenterPolicy {
                mode,
                ..Default::default()
            };
            assert_eq!(p.mode_at(0), mode);
            assert_eq!(p.mode_at(u64::MAX), mode);
        }
    }

    #[test]
    fn an_expired_limit_falls_back_to_allowlist() {
        for mode in [Mode::Folder, Mode::User] {
            let p = CenterPolicy {
                mode,
                until: Some(1000),
                ..Default::default()
            };
            assert_eq!(p.mode_at(999), mode);
            assert_eq!(p.mode_at(1000), Mode::Allowlist);
        }
    }

    #[test]
    fn proxy_secrets_in_the_file_are_refused_without_quoting_them() {
        // What earlier builds wrote: header values, or credentials in the URL.
        for old in [
            "[connection]\nproxy = \"http://p:3128\"\nheaders = { X-Key = \"s3cret\" }\n",
            "[connection]\nproxy = \"http://user:s3cret@p:3128\"\n",
            "[connection]\nheaders = { Proxy-Authorization = \"Basic s3cret\" }\n",
        ] {
            let e = NodeConfig::parse(old).unwrap_err();
            assert!(e.contains("run `nerve-node proxy set` again"), "{old}: {e}");
            assert!(!e.contains("s3cret"), "{e}");
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("node.toml");
            std::fs::write(&path, old).unwrap();
            let e = NodeConfig::load(&path).unwrap_err();
            assert!(e.contains("proxy set") && !e.contains("s3cret"), "{e}");
        }
        // Not a list of names: refused, not quoted.
        let e = NodeConfig::parse("[connection]\nheaders = \"X-Key: s3cret\"\n").unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
        let e = NodeConfig::parse("[connection]\nheaders = [\"X-Key: s3cret\"]\n").unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
    }

    #[test]
    fn the_file_keeps_the_proxy_url_and_the_header_names() {
        let e = NodeConfig::parse("[connection]\nheaders = [\"X-Key\", \"x-key\"]\n").unwrap_err();
        assert!(e.contains("twice"), "{e}");
        let c = NodeConfig::parse(
            "[connection]\nproxy = \"http://p:3128\"\nheaders = [\"Proxy-Authorization\", \"X-Key\"]\n",
        )
        .unwrap();
        assert_eq!(c.connection.headers, ["Proxy-Authorization", "X-Key"]);
        assert_eq!(NodeConfig::parse(&c.to_toml()).unwrap(), c);
        // A credential set any other way (`config set`) is refused too.
        let mut c = NodeConfig::default();
        c.connection.proxy = Some("http://u:s3cret@p:3128".into());
        let e = c.validate().unwrap_err();
        assert!(e.contains("proxy set") && !e.contains("s3cret"), "{e}");
    }

    #[test]
    fn a_file_without_the_sudo_switch_loads_as_off() {
        let none = NodeConfig::parse("[machine]\nshell = \"/bin/sh\"\n").unwrap();
        assert_eq!(none.machine.sudo, Sudo::Off);
        let on =
            NodeConfig::parse("[machine]\nsudo = \"on\"\nsudo_path = \"/usr/bin/sudo\"\n").unwrap();
        assert_eq!(on.machine.sudo, Sudo::On);
        assert_eq!(NodeConfig::parse(&on.to_toml()).unwrap(), on);
    }

    #[test]
    fn keys_and_values_of_earlier_builds_are_errors() {
        for bad in [
            "mode = \"ask\"",
            "mode = \"full\"",
            "mode = \"folders\"",
            "[center.policy.commands]\npermit = [\"x\"]",
            "[center.policy.commands]\nallow = [\"x\"]",
            "approvals = \"both\"",
            "full_until = 5",
            "caps = { exec = \"ask\" }",
            "[center.policy.commands]\nalways_ask = [\"x\"]",
        ] {
            assert!(NodeConfig::parse(&center(bad)).is_err(), "{bad}");
        }
        assert!(NodeConfig::parse("[machine]\nelevation = \"off\"\n").is_err());
    }

    #[test]
    fn folder_access_is_three_independent_flags() {
        // Every combination parses, prints back as the letters in rwx order
        // and survives the config file.
        for bits in 0..8u8 {
            let a = Access {
                read: bits & 1 != 0,
                write: bits & 2 != 0,
                execute: bits & 4 != 0,
            };
            let text = a.to_string();
            assert_eq!(Access::parse(&text).unwrap(), a, "{text:?}");
            let policy = CenterPolicy {
                folders: vec![Folder {
                    path: FOLDER.into(),
                    access: a,
                }],
                ..Default::default()
            };
            let toml = toml::to_string(&policy).unwrap();
            assert!(toml.contains(&format!("access = \"{text}\"")), "{toml}");
            assert_eq!(toml::from_str::<CenterPolicy>(&toml).unwrap(), policy);
        }
        // Any order is read; the letters come back in rwx order.
        assert_eq!(Access::parse("xr").unwrap().to_string(), "rx");
        assert_eq!(Access::parse("").unwrap(), Access::NONE);
        assert_eq!(Access::ALL.to_chmod(), "rwx");
        assert_eq!(Access::parse("wx").unwrap().to_chmod(), "-wx");
        assert_eq!(Access::NONE.to_chmod(), "---");
        // A folder without the key grants nothing.
        let bare = format!("folders = [{{ path = \"{FOLDER}\" }}]");
        let p: CenterPolicy = toml::from_str(&bare).unwrap();
        assert!(p.folders[0].access.is_none());
    }

    #[test]
    fn folder_access_changes_apply_in_order() {
        let start = Access::parse("r").unwrap();
        let steps = |specs: &[&str]| {
            specs
                .iter()
                .try_fold(start, |a, s| a.change(s))
                .map(|a| a.to_string())
        };
        assert_eq!(steps(&["+x"]).unwrap(), "rx");
        assert_eq!(steps(&["+rw"]).unwrap(), "rw");
        assert_eq!(steps(&["-r"]).unwrap(), "");
        assert_eq!(steps(&["=rwx"]).unwrap(), "rwx");
        assert_eq!(steps(&["="]).unwrap(), "");
        // Left to right: the later change sees the earlier one.
        assert_eq!(steps(&["=rwx", "-w"]).unwrap(), "rx");
        assert_eq!(steps(&["-w", "=w", "+x"]).unwrap(), "wx");
        assert_eq!(steps(&["+w", "-w"]).unwrap(), "r");
        assert_eq!(steps(&["=x", "+w", "-x", "+r"]).unwrap(), "rw");
        for bad in ["rw", "+", "-", "+q", "-rr", "*r", ""] {
            assert!(start.change(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn folder_access_refuses_anything_but_r_w_x_once() {
        for bad in ["ro", "rw+", "rr", "RW", "r w", "all", "true"] {
            assert!(Access::parse(bad).is_err(), "{bad:?}");
            let text = format!("folders = [{{ path = \"{FOLDER}\", access = \"{bad}\" }}]");
            assert!(toml::from_str::<CenterPolicy>(&text).is_err(), "{bad:?}");
        }
        // The two keys of earlier builds are gone.
        let old = format!("folders = [{{ path = \"{FOLDER}\", access = \"rw\", execute = true }}]");
        assert!(toml::from_str::<CenterPolicy>(&old).is_err());
    }

    #[test]
    fn ask_is_not_a_value_of_new_input() {
        let ask = serde_json::json!({"mode": "ask"});
        assert!(serde_json::from_value::<CenterPolicy>(ask).is_err());
        let cap = serde_json::json!({"caps": {"fs": "ask"}});
        assert!(serde_json::from_value::<CenterPolicy>(cap).is_err());
        assert_eq!(CapSetting::parse("ask"), None);
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
