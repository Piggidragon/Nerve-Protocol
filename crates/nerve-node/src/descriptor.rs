//! The descriptor one center sees (spec §6): the node's capabilities, cut to
//! what this center's policy shows.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use nerve_policy::config::{CapSetting, SettingsGrant};
use nerve_policy::{CenterEntry, NodeConfig};
use nerve_proto::descriptor::{
    Action, Capability, Descriptor, Direction, Effect, EventDecl, Exposure, NodeInfo, Software,
    StreamDecl, StreamKind,
};

pub const SOFTWARE: &str = "nerve-node";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capabilities whose events need no `sub` (spec §5.1).
pub const IMPLICIT: &[&str] = &["node", "settings"];

/// The node's name: `[node] name`, else derived from the host name.
pub fn node_name(cfg: &NodeConfig) -> String {
    cfg.node
        .name
        .clone()
        .unwrap_or_else(|| nerve_proto::node_name_from_host(&host_name()))
}

pub fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
        })
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "node".into())
}

fn action(effect: Effect, summary: &str, params: Value, result: Value) -> Action {
    Action {
        effect,
        summary: summary.into(),
        params,
        result,
    }
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": props, "required": required,
           "additionalProperties": false})
}

fn event(summary: &str, implicit: bool, data: Value) -> EventDecl {
    EventDecl {
        summary: summary.into(),
        implicit,
        data,
    }
}

fn cap(id: &str, profile: &str, exposure: Exposure, summary: &str) -> Capability {
    Capability {
        id: id.into(),
        profile: profile.into(),
        provider: "node".into(),
        exposure,
        summary: summary.into(),
        actions: BTreeMap::new(),
        events: BTreeMap::new(),
        state: Value::Null,
        streams: BTreeMap::new(),
    }
}

fn node_cap() -> Capability {
    let mut c = cap(
        "node",
        "node",
        Exposure::On,
        "This node: its status and changes.",
    );
    c.state = obj(
        json!({"status": {"enum": ["online", "busy", "paused"]}}),
        &["status"],
    );
    c.events.insert(
        "descriptor_changed".into(),
        event(
            "The descriptor changed; fetch it again.",
            true,
            obj(json!({"rev": {"type": "integer"}}), &["rev"]),
        ),
    );
    c.events.insert(
        "going_away".into(),
        event(
            "The node is about to drop the link.",
            true,
            obj(json!({"reason": {"type": "string"}}), &["reason"]),
        ),
    );
    c.events.insert(
        "capability_changed".into(),
        event(
            "A capability changed.",
            true,
            obj(json!({"cap": {"type": "string"}}), &["cap"]),
        ),
    );
    c
}

fn fs_cap(exposure: Exposure) -> Capability {
    let mut c = cap(
        "fs",
        "fs",
        exposure,
        "Files on this machine: stat, list, read, grep, find and write.",
    );
    let path = json!({"type": "string", "description": "absolute path"});
    let ty = json!({"enum": ["file", "dir", "link", "other"]});
    let a = &mut c.actions;
    a.insert(
        "stat".into(),
        action(
            Effect::Read,
            "Type, size and modification time of a path.",
            obj(json!({"path": path}), &["path"]),
            obj(
                json!({"type": ty, "size": {"type": "integer"}, "mtime_ms": {"type": "integer"}}),
                &["type", "size", "mtime_ms"],
            ),
        ),
    );
    a.insert(
        "list".into(),
        action(
            Effect::Read,
            "The entries of a directory.",
            obj(json!({"path": path}), &["path"]),
            obj(
                json!({"entries": {"type": "array", "items": obj(
                    json!({"name": {"type": "string"}, "type": ty, "size": {"type": "integer"}}),
                    &["name", "type", "size"])}}),
                &["entries"],
            ),
        ),
    );
    a.insert(
        "read".into(),
        action(
            Effect::Read,
            "A file's content, utf8 or base64, with its etag.",
            obj(
                json!({"path": path, "offset": {"type": "integer", "minimum": 0},
                       "length": {"type": "integer", "minimum": 0}}),
                &["path"],
            ),
            obj(
                json!({"content": {"type": "string"}, "encoding": {"enum": ["utf8", "base64"]},
                       "size": {"type": "integer"}, "etag": {"type": "string"}}),
                &["content", "encoding", "size", "etag"],
            ),
        ),
    );
    a.insert(
        "grep".into(),
        action(
            Effect::Read,
            "Lines containing a literal pattern, below a path.",
            obj(
                json!({"path": path, "pattern": {"type": "string"}, "glob": {"type": "string"},
                       "max": {"type": "integer", "minimum": 1}}),
                &["path", "pattern"],
            ),
            obj(
                json!({"matches": {"type": "array", "items": obj(
                    json!({"path": {"type": "string"}, "line": {"type": "integer"},
                           "text": {"type": "string"}}), &["path", "line", "text"])},
                       "truncated": {"type": "boolean"}}),
                &["matches", "truncated"],
            ),
        ),
    );
    a.insert(
        "find".into(),
        action(
            Effect::Read,
            "Paths below a path that match a glob.",
            obj(
                json!({"path": path, "glob": {"type": "string"},
                       "max": {"type": "integer", "minimum": 1}}),
                &["path", "glob"],
            ),
            obj(
                json!({"paths": {"type": "array", "items": {"type": "string"}},
                       "truncated": {"type": "boolean"}}),
                &["paths", "truncated"],
            ),
        ),
    );
    a.insert(
        "write".into(),
        action(
            Effect::Write,
            "Writes a whole file; if_match guards against a concurrent change.",
            obj(
                json!({"path": path, "content": {"type": "string"},
                       "encoding": {"enum": ["utf8", "base64"]}, "if_match": {"type": "string"}}),
                &["path", "content"],
            ),
            obj(
                json!({"etag": {"type": "string"}, "size": {"type": "integer"}}),
                &["etag", "size"],
            ),
        ),
    );
    c
}

fn exec_cap(exposure: Exposure) -> Capability {
    let mut c = cap(
        "exec",
        "exec",
        exposure,
        "Runs shell commands; output comes with the result.",
    );
    c.actions.insert(
        "run".into(),
        action(
            Effect::Execute,
            "Runs a command in the node's shell.",
            obj(
                json!({"command": {"type": "string"}, "cwd": {"type": "string"},
                       "timeout_ms": {"type": "integer", "minimum": 1}}),
                &["command"],
            ),
            obj(
                json!({"exit_code": {"type": ["integer", "null"]}, "signal": {"type": "string"},
                       "stdout": {"type": "string"}, "stderr": {"type": "string"},
                       "truncated": {"type": "boolean"}}),
                &["exit_code", "stdout", "stderr", "truncated"],
            ),
        ),
    );
    c.actions.insert(
        "signal".into(),
        action(
            Effect::Actuate,
            "Signals a running command of this center.",
            obj(
                json!({"call": {}, "signal": {"enum": ["term", "kill", "int"]}}),
                &["call", "signal"],
            ),
            obj(json!({}), &[]),
        ),
    );
    c.state = obj(
        json!({"shell": {"type": "string"}, "confinement": {"type": "string"}}),
        &["shell", "confinement"],
    );
    c.events.insert(
        "exit".into(),
        event(
            "A command ended.",
            false,
            obj(
                json!({"call": {}, "exit_code": {"type": ["integer", "null"]}}),
                &["call", "exit_code"],
            ),
        ),
    );
    // Declared for later versions; 0.0.1 sends output in the result.
    c.streams.insert(
        "output".into(),
        StreamDecl {
            kind: StreamKind::Reliable,
            direction: Direction::Up,
            summary: "Command output (not served in 0.0.1).".into(),
        },
    );
    c
}

fn settings_cap() -> Capability {
    let mut c = cap(
        "settings",
        "settings",
        Exposure::On,
        "This center's entry of the node config.",
    );
    c.actions.insert(
        "set".into(),
        action(
            Effect::Write,
            "Replaces the document; if_version guards against a concurrent change.",
            obj(
                json!({"document": {"type": "object"}, "if_version": {"type": "integer"}}),
                &["document", "if_version"],
            ),
            obj(json!({"version": {"type": "integer"}}), &["version"]),
        ),
    );
    c.actions.insert(
        "pause".into(),
        action(
            Effect::Actuate,
            "Pauses this center's link; only the owner unpauses.",
            obj(json!({}), &[]),
            obj(json!({}), &[]),
        ),
    );
    c.actions.insert(
        "sudo_offer".into(),
        action(
            Effect::Write,
            "A one-shot key to seal the sudo password for this node (spec §7.4.1).",
            obj(json!({}), &[]),
            obj(
                json!({"offer": {"type": "string"}, "key": {"type": "string"},
                       "ts": {"type": "integer"}, "sig": {"type": "string"}}),
                &["offer", "key", "ts", "sig"],
            ),
        ),
    );
    c.actions.insert(
        "sudo".into(),
        action(
            Effect::Write,
            "Turns the sudo switch on (with the sealed password) or off.",
            obj(
                json!({"on": {"type": "boolean"},
                       "sealed": {"type": "object", "properties": {
                           "offer": {"type": "string"}, "key": {"type": "string"},
                           "iv": {"type": "string"}, "ct": {"type": "string"}},
                        "required": ["offer", "key", "iv", "ct"]}}),
                &["on"],
            ),
            obj(json!({"sudo": {"enum": ["on", "off"]}}), &["sudo"]),
        ),
    );
    c.state = obj(
        json!({"document": {"type": "object"}, "version": {"type": "integer"},
               "sudo": {"enum": ["on", "off"]}}),
        &["document", "version", "sudo"],
    );
    c.events.insert(
        "changed".into(),
        event(
            "The node config changed.",
            true,
            obj(json!({"version": {"type": "integer"}}), &["version"]),
        ),
    );
    c
}

fn audit_cap() -> Capability {
    let mut c = cap(
        "audit",
        "audit",
        Exposure::On,
        "The node's decisions about this center's calls.",
    );
    c.events.insert(
        "decision".into(),
        event(
            "One decision.",
            false,
            obj(
                json!({"ts": {"type": "integer"}, "cap": {"type": "string"},
                       "action": {"type": "string"}, "target": {"type": "string"},
                       "decision": {"enum": ["allowed", "forbidden"]},
                       "code": {"type": "string"},
                       "session": {"type": "string"}}),
                &["ts", "cap", "action", "target", "decision"],
            ),
        ),
    );
    c
}

/// How a policy-governed capability is offered: on, unless its setting says
/// off or hidden. What a call may do is decided per call, not here.
fn exposure(entry: &CenterEntry, id: &str) -> Option<Exposure> {
    match entry.policy.cap_setting(id, None) {
        Some(CapSetting::Hidden) => None,
        Some(CapSetting::Off) => Some(Exposure::Off),
        Some(CapSetting::On) | None => Some(Exposure::On),
    }
}

/// The descriptor `entry` sees now; `rev` is derived from its content, so it
/// changes exactly when the view changes.
pub fn for_center(cfg: &NodeConfig, entry: &CenterEntry, now_ms: u64) -> Descriptor {
    let mut caps = vec![node_cap()];
    if let Some(e) = exposure(entry, "fs") {
        caps.push(fs_cap(e));
    }
    if let Some(e) = exposure(entry, "exec") {
        caps.push(exec_cap(e));
    }
    if entry.settings == SettingsGrant::Write {
        caps.push(settings_cap());
    }
    caps.push(audit_cap());
    // Actions set to hidden are left out; off ones stay and fail `disabled`.
    for c in &mut caps {
        let id = c.id.clone();
        c.actions.retain(|a, _| {
            entry.policy.caps.get(&format!("{id}.{a}")) != Some(&CapSetting::Hidden)
        });
    }
    let name = node_name(cfg);
    let platform = std::env::consts::OS.to_string();
    let mut d = Descriptor {
        nerve: nerve_proto::PROTOCOL_VERSION.into(),
        node: NodeInfo {
            id: entry.node_id.clone(),
            name: name.clone(),
            platform: platform.clone(),
            arch: std::env::consts::ARCH.into(),
            software: Software {
                name: SOFTWARE.into(),
                version: VERSION.into(),
            },
        },
        rev: 0,
        summary: format!(
            "{platform} machine {name}: files and shell commands, under its owner's policy (mode {}).",
            entry.policy.mode_at(now_ms).as_str()
        ),
        capabilities: caps,
    };
    d.rev = rev_of(&d);
    d
}

/// A content hash of the descriptor, kept below 2^53 so every JSON reader
/// holds it exactly.
fn rev_of(d: &Descriptor) -> u64 {
    let bytes = serde_json::to_vec(d).unwrap_or_default();
    let h = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_ref()[..8]);
    (u64::from_be_bytes(b) & ((1 << 53) - 1)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_policy::config::CenterPolicy;

    fn entry() -> CenterEntry {
        CenterEntry {
            name: "home".into(),
            url: "https://center.example".into(),
            pin: None,
            center_id: "c1".into(),
            node_id: "n1".into(),
            settings: SettingsGrant::Off,
            paused: false,
            revoked: false,
            unknown: false,
            policy: CenterPolicy::default(),
        }
    }

    #[test]
    fn filtered_per_center() {
        let cfg = NodeConfig::default();
        let mut e = entry();
        let d = for_center(&cfg, &e, 0);
        let ids: Vec<&str> = d.capabilities.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["node", "fs", "exec", "audit"]);
        assert!(nerve_proto::descriptor::summary_words(&d.summary) < 60);
        assert_eq!(d.capability("fs").unwrap().exposure, Exposure::On);

        e.policy.caps.insert("fs".into(), CapSetting::Off);
        assert_eq!(
            for_center(&cfg, &e, 0).capability("fs").unwrap().exposure,
            Exposure::Off
        );

        e.policy.caps.insert("exec".into(), CapSetting::Hidden);
        e.policy.caps.insert("fs.write".into(), CapSetting::Hidden);
        e.settings = SettingsGrant::Write;
        let d2 = for_center(&cfg, &e, 0);
        assert!(d2.capability("exec").is_none());
        assert!(d2.capability("settings").is_some());
        assert!(!d2.capability("fs").unwrap().actions.contains_key("write"));
        assert_ne!(d.rev, d2.rev);
        assert_eq!(d2.rev, for_center(&cfg, &e, 0).rev);
    }
}
