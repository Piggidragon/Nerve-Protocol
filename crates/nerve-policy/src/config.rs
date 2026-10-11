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

/// The longest `user` mode a center may set: 8 hours (architecture §5.1).
pub const USER_MAX_MS: u64 = 8 * 3600 * 1000;

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
/// say. On, a `sudo` command runs only when an explicit `permit` rule names
/// it, in either mode.
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
/// allows is refused at once; nothing waits for an answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Allowed inside the folders by their access, refused outside. With no
    /// folders nothing is allowed: the default.
    #[default]
    #[serde(alias = "folders")]
    Folder,
    /// Allowed everywhere except protected and denied paths, until
    /// `user_until`.
    #[serde(alias = "full")]
    User,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Folder => "folder",
            Mode::User => "user",
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
    /// Run in any mode.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permit: Vec<String>,
}

/// What one center may do on this node.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CenterPolicy {
    #[serde(default)]
    pub mode: Mode,
    /// Milliseconds since the Unix epoch at which `user` falls back to
    /// `folder`. Required with `user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_until: Option<u64>,
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
}

impl CenterPolicy {
    /// The mode in force at `now_ms`: an expired `user` is `folder`.
    pub fn mode_at(&self, now_ms: u64) -> Mode {
        match self.mode {
            Mode::User if self.user_until.is_none_or(|u| u <= now_ms) => Mode::Folder,
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
        if self.mode == Mode::User && self.user_until.is_none() {
            return Err("mode user needs user_until".into());
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
        for g in c.deny.iter().chain(&c.allow).chain(&c.permit) {
            globset::Glob::new(g).map_err(|e| format!("command rule {g:?}: {e}"))?;
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
folders = [{ path = "FOLDER", access = "rw", execute = true }]
deny = ["~/private"]
caps = { exec = "on", "fs.write" = "off" }

[center.policy.commands]
deny = ["rm -rf *"]
permit = ["git status"]
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
        assert_eq!(home.policy.commands.permit, ["git status"]);
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
        let with = |extra: &str| {
            sample().replace(
                "[center.policy.commands]",
                &format!("{extra}\n[center.policy.commands]"),
            )
        };
        assert!(NodeConfig::parse(&with("user_until = 1\nfoo = 1")).is_err());
        let user = sample().replace("mode = \"folder\"", "mode = \"user\"");
        assert!(NodeConfig::parse(&user).unwrap_err().contains("user_until"));
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
    fn expired_user_is_folder() {
        let p = CenterPolicy {
            mode: Mode::User,
            user_until: Some(1000),
            ..Default::default()
        };
        assert_eq!(p.mode_at(999), Mode::User);
        assert_eq!(p.mode_at(1000), Mode::Folder);
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
        let center = |policy: &str| {
            format!(
                "[[center]]\nname = \"home\"\nurl = \"https://c.example:8443\"\ncenter_id = \"c\"\nnode_id = \"n\"\n[center.policy]\n{policy}\n"
            )
        };
        for bad in [
            "mode = \"ask\"",
            "mode = \"full\"",
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
