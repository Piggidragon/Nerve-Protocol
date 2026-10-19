//! What the pages show, made from the CLI's JSON answers
//! (docs/user/commands.md): the words, their tones, and the arguments of the
//! commands the buttons run. Nothing here decides anything about the node;
//! it only says what the node said, for people.

use serde_json::Value;
use slint::{ModelRc, SharedString, VecModel};

use crate::{AuditRow, CenterRow, NodeStatus, Tone};

/// The most audit entries the page shows (crate::app asks for as many).
pub const AUDIT_SHOWN: usize = 200;

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn text_model(items: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        items
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    ))
}

/// The node's status and its centers, from `status --json`.
pub fn status(v: &Value, now_ms: u64) -> (NodeStatus, Vec<CenterRow>) {
    let running = v["daemon"] == "running";
    let locked = v["locked"] == true;
    let centers: Vec<CenterRow> = v["centers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| center(c, running, now_ms))
        .collect();
    let connected = v["centers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"] == "connected")
        .count();
    let (state, title, detail, tone) = match (locked, running) {
        (true, _) => (
            "locked",
            "Locked: nothing runs",
            "A panic ended every link. No center reaches this machine and no command runs until you unlock it.",
            Tone::Danger,
        ),
        (false, true) => (
            "running",
            "The node is running",
            "It links this machine to its centers and decides each of their calls by your rules.",
            Tone::Ok,
        ),
        (false, false) => (
            "stopped",
            "The node is not running",
            "No center reaches this machine. Start the node as a service or with nerve-node run; what you change here counts from its next start.",
            Tone::Warn,
        ),
    };
    let limits = &v["command_limits"];
    let mut warnings = Vec::new();
    if running {
        if let Some(why) = v["folder_commands_off"].as_str() {
            warnings.push(format!("Folder mode runs no command: {why}."));
        }
        let lost: Vec<&str> = limits["lost"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !lost.is_empty() {
            warnings.push(format!(
                "No command runs: {} turned off in the cgroup since the node started. Start the node again.",
                lost.join(", ")
            ));
        } else if let Some(why) = limits["off"].as_str() {
            warnings.push(format!("Commands run without their limits: {why}."));
        }
        if v["keyring_failed"] == true {
            warnings.push(
                "The node found no system keyring when it started, and keys kept there cannot be read. Start it again once the keyring runs.".into(),
            );
        }
    }
    let n = |k: &str| limits[k].as_u64().unwrap_or_default();
    let status = NodeStatus {
        state: state.into(),
        title: title.into(),
        detail: detail.into(),
        tone,
        confinement: s(&v["confinement"]).into(),
        centers: centers.len() as i32,
        connected: connected as i32,
        sudo_on: v["sudo"] == "on",
        limits: format!(
            "{} MiB · {} % · {}",
            n("memory_mb"),
            n("cpu_percent"),
            n("processes")
        )
        .into(),
        warnings: text_model(warnings),
    };
    (status, centers)
}

/// The first letter in upper case.
fn sentence(t: &str) -> String {
    let mut c = t.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// One center of `status --json`: its link in words, its mode, its grant.
fn center(c: &Value, running: bool, now_ms: u64) -> CenterRow {
    let link = s(&c["status"]);
    let (label, tone, note, note_tone) = if c["revoked"] == true {
        (
            "Revoked".to_string(),
            Tone::Danger,
            "The center revoked this machine. Unpair it here; to use the center again, pair again."
                .to_string(),
            Tone::Danger,
        )
    } else if c["unknown"] == true {
        (
            "Not known".to_string(),
            Tone::Danger,
            "The center does not know this machine any more, so the node stopped dialling it. Unpair it and pair again.".to_string(),
            Tone::Danger,
        )
    } else if c["paused"] == true || link == "paused" {
        (
            "Paused".to_string(),
            Tone::Neutral,
            String::new(),
            Tone::Neutral,
        )
    } else if !running {
        (
            "Node not running".to_string(),
            Tone::Neutral,
            String::new(),
            Tone::Neutral,
        )
    } else {
        match link {
            "connected" => (
                "Connected".to_string(),
                Tone::Ok,
                String::new(),
                Tone::Neutral,
            ),
            "connecting" => (
                "Connecting".to_string(),
                Tone::Warn,
                String::new(),
                Tone::Neutral,
            ),
            "stopped" => (
                "Stopped".to_string(),
                Tone::Neutral,
                String::new(),
                Tone::Neutral,
            ),
            l if l.starts_with("link lost") => (
                "Reconnecting".to_string(),
                Tone::Warn,
                String::new(),
                Tone::Neutral,
            ),
            "not connected" | "" => (
                "Not connected".to_string(),
                Tone::Warn,
                String::new(),
                Tone::Neutral,
            ),
            // An error: its kind on the pill, the whole of it below.
            l => {
                let head = l.split(':').next().unwrap_or(l);
                let head = head.split(" (").next().unwrap_or(head);
                (sentence(head), Tone::Danger, sentence(l), Tone::Warn)
            }
        }
    };
    let mode = s(&c["mode"]);
    let mut detail = match mode {
        "allowlist" => "Only what an allow rule names may run.".to_string(),
        "folder" => "What each folder's rights allow.".to_string(),
        "user" => "Anything you could do yourself, protected files aside.".to_string(),
        _ => String::new(),
    };
    if mode != "allowlist"
        && let Some(until) = c["until"].as_u64()
        && until > now_ms
    {
        detail.push_str(&format!(" Back to allowlist {}.", ahead(until - now_ms)));
    }
    CenterRow {
        name: s(&c["name"]).into(),
        url: s(&c["url"]).into(),
        link: label.into(),
        link_tone: tone,
        mode: format!("{} mode", sentence(mode)).into(),
        mode_detail: detail.into(),
        settings_write: c["settings"] == "write",
        paused: c["paused"] == true,
        note: note.into(),
        note_tone,
    }
}

/// A time ahead, in words.
fn ahead(ms: u64) -> String {
    let min = ms / 60_000;
    match min {
        0 => "in less than a minute".into(),
        1..=59 => format!("in {min} min"),
        60..=2879 => format!("in {} h", min / 60),
        _ => format!("in {} days", min / 1440),
    }
}

/// A time gone, in words.
pub fn ago(ts_ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(ts_ms) / 1000;
    match secs {
        0..=44 => "just now".into(),
        45..=3599 => format!("{} min ago", (secs / 60).max(1)),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        86_400..=172_799 => "yesterday".into(),
        _ => format!("{} days ago", secs / 86_400),
    }
}

/// A time as a date and the time of day, in UTC.
pub fn exact(ts_ms: u64) -> String {
    let secs = ts_ms / 1000;
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// A setting's value as one short piece of text.
fn shown(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "nothing".into(),
        other => other.to_string(),
    }
}

/// The most changed settings one entry names; the rest are counted.
const CHANGES_SHOWN: usize = 6;

/// The settings that differ between `old` and `new` under `key`, each as
/// `key.of.it: old → new`. The log keeps a changed table or list whole
/// (the centers, a policy), so it is followed down to what changed in it;
/// a list of named entries (the centers) by their names.
fn changed(key: &str, old: &Value, new: &Value, out: &mut Vec<String>) {
    if old == new {
        return;
    }
    let join = |k: &str| {
        if key.is_empty() {
            k.to_string()
        } else {
            format!("{key}.{k}")
        }
    };
    if let (Some(a), Some(b)) = (old.as_object(), new.as_object()) {
        let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
        keys.sort();
        keys.dedup();
        for k in keys {
            let none = Value::Null;
            changed(
                &join(k),
                a.get(k).unwrap_or(&none),
                b.get(k).unwrap_or(&none),
                out,
            );
        }
        return;
    }
    if let (Some(a), Some(b)) = (named(old), named(new))
        && !(a.is_empty() && b.is_empty())
    {
        let mut names: Vec<&String> = Vec::new();
        for (n, _) in a.iter().chain(b.iter()) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        fn find<'a>(l: &'a [(String, Value)], n: &str) -> Option<&'a Value> {
            l.iter().find(|(m, _)| m == n).map(|(_, v)| v)
        }
        for n in names {
            match (find(&a, n), find(&b, n)) {
                (Some(x), Some(y)) => changed(&join(n), x, y, out),
                (None, Some(_)) => out.push(format!("{} added", join(n))),
                (Some(_), None) => out.push(format!("{} removed", join(n))),
                (None, None) => {}
            }
        }
        return;
    }
    out.push(format!("{key}: {} → {}", short(old), short(new)));
}

/// A list whose entries all have a name (the centers), by name; nothing
/// for no list.
fn named(v: &Value) -> Option<Vec<(String, Value)>> {
    if v.is_null() {
        return Some(Vec::new());
    }
    v.as_array()?
        .iter()
        .map(|e| Some((e["name"].as_str()?.to_string(), e.clone())))
        .collect()
}

/// A value in a line of its own: cut when long.
fn short(v: &Value) -> String {
    let t = shown(v);
    match t.char_indices().nth(60) {
        Some((at, _)) => format!("{}…", &t[..at]),
        None => t,
    }
}

/// The audit entries to show, newest first, at most [`AUDIT_SHOWN`], from
/// the entries `audit --json` gave (oldest first). `centers` are the paired
/// ones, whose entries take rule buttons.
pub fn audit(entries: &[Value], centers: &[String], now_ms: u64) -> Vec<AuditRow> {
    entries
        .iter()
        .rev()
        .take(AUDIT_SHOWN)
        .enumerate()
        .map(|(i, e)| audit_row(e, i, centers, now_ms))
        .collect()
}

fn audit_row(e: &Value, index: usize, centers: &[String], now_ms: u64) -> AuditRow {
    let ts = e["ts"].as_u64().unwrap_or_default();
    let mut row = AuditRow {
        kind: "call".into(),
        tone: Tone::Neutral,
        title: SharedString::new(),
        badge: SharedString::new(),
        center: s(&e["center"]).into(),
        target: SharedString::new(),
        detail: SharedString::new(),
        when: ago(ts, now_ms).into(),
        when_exact: exact(ts).into(),
        rules: false,
        rules_why: SharedString::new(),
        index: index as i32,
    };
    if e.get("changes").is_some() {
        let mut changes = Vec::new();
        for c in e["changes"].as_array().into_iter().flatten() {
            changed(s(&c["key"]), &c["old"], &c["new"], &mut changes);
        }
        let more = changes.len().saturating_sub(CHANGES_SHOWN);
        changes.truncate(CHANGES_SHOWN);
        if more > 0 {
            changes.push(format!("{more} more"));
        }
        row.kind = "settings".into();
        row.tone = Tone::Accent;
        row.title = "Settings changed".into();
        row.badge = format!("version {}", shown(&e["version"])).into();
        row.center = SharedString::new();
        row.detail = format!("By {}. {}", shown(&e["by"]), changes.join("; ")).into();
        return row;
    }
    match s(&e["kind"]) {
        "node" => {
            let steps: Vec<&str> = e["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            row.kind = "node".into();
            row.title = format!("Node {}", s(&e["event"])).into();
            let mut detail = steps.join("; ");
            if let Some(err) = e["error"].as_str() {
                row.tone = Tone::Danger;
                row.badge = "Failed".into();
                detail = format!("{detail} Stopped: {err}");
            }
            row.detail = detail.trim().to_string().into();
        }
        "relay" => {
            let span = e["end"]
                .as_u64()
                .unwrap_or(0)
                .saturating_sub(e["start"].as_u64().unwrap_or(0));
            row.kind = "relay".into();
            row.title = "Relay tunnel".into();
            row.detail = format!(
                "{} from {} to center {}: {} after {} s ({} bytes up, {} down)",
                shown(&e["node"]),
                shown(&e["from"]),
                shown(&e["center"]),
                shown(&e["reason"]),
                span / 1000,
                shown(&e["up"]),
                shown(&e["down"]),
            )
            .into();
        }
        "config" => {
            row.kind = "config".into();
            row.title = format!("Config {}", s(&e["event"])).into();
            if e["event"] == "refused" {
                row.tone = Tone::Warn;
                row.badge = "Refused".into();
            }
            row.target = s(&e["file"]).into();
            row.detail = sentence(s(&e["reason"])).into();
        }
        "key" => {
            row.kind = "key".into();
            row.title = format!("Key {}", s(&e["event"])).into();
            row.detail = s(&e["detail"]).into();
        }
        _ => {
            let refused = e["decision"] == "forbidden";
            row.title = format!("{}.{}", s(&e["cap"]), s(&e["action"])).into();
            row.tone = if refused { Tone::Danger } else { Tone::Ok };
            row.badge = if refused { "Refused" } else { "Allowed" }.into();
            row.target = s(&e["target"]).into();
            row.detail = e["reason"]
                .as_str()
                .map(sentence)
                .unwrap_or_default()
                .into();
            let (rules, why) = rules_for(e, centers);
            row.rules = rules;
            row.rules_why = why.into();
        }
    }
    row
}

/// Whether the four buttons can make a rule for an entry, and why not: a
/// rule needs its action and target, a target cut to its start names no
/// call, and the center must still be paired.
fn rules_for(e: &Value, centers: &[String]) -> (bool, String) {
    let (cap, action, target) = (s(&e["cap"]), s(&e["action"]), s(&e["target"]));
    if cap.is_empty() || action.is_empty() || (target.is_empty() && matches!(cap, "exec" | "fs")) {
        return (false, String::new());
    }
    if nerve_policy::audit::is_cut_target(target) {
        return (
            false,
            "The target was cut to its start, so no rule can name it.".into(),
        );
    }
    if !centers.iter().any(|c| c == s(&e["center"])) {
        return (false, "The center is no longer paired here.".into());
    }
    (true, String::new())
}

/// The list a button puts an entry on: `allow` or `deny`, and the sudo
/// list in place of `allow` for a sudo command, as on the center's audit
/// page.
pub fn rule_list(e: &Value, list: &str) -> &'static str {
    let sudo = e["cap"] == "exec"
        && e["action"] == "run"
        && nerve_policy::sudo_command(s(&e["target"])).is_some();
    match list {
        "deny" => "deny",
        _ if sudo => "sudo",
        _ => "allow",
    }
}

/// The command a button runs: `rule add` with the entry's action, target
/// and center ([`rule_list`] picks the list).
pub fn rule_args(e: &Value, list: &str, wildcard: bool) -> Vec<String> {
    let mut args = vec![
        "rule".to_string(),
        "add".into(),
        rule_list(e, list).into(),
        s(&e["target"]).into(),
        "--action".into(),
        format!("{}.{}", s(&e["cap"]), s(&e["action"])),
        "--center".into(),
        s(&e["center"]).into(),
    ];
    if wildcard {
        args.push("--wildcard".into());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use slint::Model;

    const NOW: u64 = 1_760_800_000_000;

    #[test]
    fn a_running_node_and_its_links() {
        let v = json!({
            "daemon": "running", "locked": false, "sudo": "off",
            "confinement": "landlock abi 6",
            "command_limits": {"memory_mb": 2048, "cpu_percent": 100, "processes": 256},
            "centers": [
                {"name": "home", "url": "https://c.example", "status": "connected", "mode": "folder", "settings": "write", "paused": false},
                {"name": "lab", "url": "http://10.0.0.2:7443", "status": "cannot connect: connection refused (os error 111)", "mode": "user", "until": NOW + 3 * 3_600_000, "settings": "off", "paused": false},
                {"name": "old", "url": "x", "status": "connecting", "mode": "allowlist", "revoked": true},
            ],
        });
        let (st, centers) = status(&v, NOW);
        assert_eq!(st.state, "running");
        assert_eq!(st.tone, Tone::Ok);
        assert_eq!((st.centers, st.connected), (3, 1));
        assert_eq!(st.limits, "2048 MiB · 100 % · 256");
        assert_eq!(st.warnings.row_count(), 0);
        assert_eq!(
            (centers[0].link.as_str(), centers[0].link_tone),
            ("Connected", Tone::Ok)
        );
        assert!(centers[0].settings_write);
        assert_eq!(centers[0].mode, "Folder mode");
        assert_eq!(
            (centers[1].link.as_str(), centers[1].link_tone),
            ("Cannot connect", Tone::Danger)
        );
        assert!(
            centers[1].note.contains("connection refused"),
            "{}",
            centers[1].note
        );
        assert!(
            centers[1]
                .mode_detail
                .ends_with("Back to allowlist in 3 h."),
            "{}",
            centers[1].mode_detail
        );
        assert_eq!(centers[2].link, "Revoked");
    }

    #[test]
    fn a_stopped_or_locked_node() {
        let v = json!({"daemon": "not running", "locked": false, "sudo": "off",
            "command_limits": {"off": "the node does not run"},
            "centers": [{"name": "home", "url": "u", "status": null, "mode": "allowlist", "paused": true}]});
        let (st, centers) = status(&v, NOW);
        assert_eq!((st.state.as_str(), st.tone), ("stopped", Tone::Warn));
        // Not running is said once, not as a missing limit too.
        assert_eq!(st.warnings.row_count(), 0);
        assert_eq!(centers[0].link, "Paused");
        let v = json!({"daemon": "running", "locked": true, "centers": [],
            "folder_commands_off": "commands cannot be confined on this machine"});
        let (st, _) = status(&v, NOW);
        assert_eq!(st.state, "locked");
        assert_eq!(st.warnings.row_count(), 1);
    }

    fn call(target: &str, decision: &str, center: &str) -> Value {
        json!({"ts": NOW - 120_000, "center": center, "cap": "exec", "action": "run", "target": target, "decision": decision})
    }

    #[test]
    fn the_audit_newest_first_with_buttons_where_a_rule_fits() {
        let centers = vec!["home".to_string()];
        let cut = format!(
            "{}… [cut at {n} of 600 characters]",
            "a".repeat(nerve_policy::audit::TARGET_MAX_CHARS),
            n = nerve_policy::audit::TARGET_MAX_CHARS
        );
        let entries = vec![
            call("git status", "allowed", "home"),
            json!({"ts": NOW, "kind": "settings", "by": "local", "version": 4,
                "changes": [{"key": "center.home.policy.mode", "old": "allowlist", "new": "user"}]}),
            call("ls", "forbidden", "gone"),
            call(&cut, "forbidden", "home"),
            json!({"ts": NOW, "center": "home", "cap": "fs", "action": "read", "target": "/etc/shadow", "decision": "forbidden", "reason": "protected path"}),
        ];
        let rows = audit(&entries, &centers, NOW);
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].title, "fs.read");
        assert_eq!(
            (rows[0].badge.as_str(), rows[0].tone),
            ("Refused", Tone::Danger)
        );
        assert_eq!(rows[0].detail, "Protected path");
        assert!(rows[0].rules);
        assert!(!rows[1].rules && rows[1].rules_why.contains("cut"));
        assert!(!rows[2].rules && rows[2].rules_why.contains("no longer paired"));
        assert_eq!(rows[3].kind, "settings");
        assert!(
            rows[3]
                .detail
                .contains("center.home.policy.mode: allowlist → user"),
            "{}",
            rows[3].detail
        );
        // A table the log keeps whole is followed down to what changed.
        let whole = json!({"ts": NOW, "kind": "settings", "by": "local", "version": 5, "changes": [{"key": "center",
            "old": [{"name": "home", "policy": {"mode": "folder"}}, {"name": "lab", "paused": false}],
            "new": [{"name": "home", "policy": {"mode": "folder", "allow": ["exec.run:cargo *"]}}, {"name": "lab", "paused": true}, {"name": "new"}]}]});
        let whole = audit(&[whole], &centers, NOW);
        assert_eq!(
            whole[0].detail,
            "By local. center.home.policy.allow: nothing → [\"exec.run:cargo *\"]; center.lab.paused: false → true; center.new added"
        );
        assert!(!rows[3].rules);
        assert_eq!(rows[4].when, "2 min ago");
        assert_eq!(rows[4].index, 4);
    }

    #[test]
    fn a_button_runs_rule_add_with_the_entrys_action() {
        let e = call("git status", "forbidden", "home");
        assert_eq!(
            rule_args(&e, "allow", true),
            [
                "rule",
                "add",
                "allow",
                "git status",
                "--action",
                "exec.run",
                "--center",
                "home",
                "--wildcard"
            ]
        );
        // A sudo command goes on the sudo list; a deny on the deny list.
        let e = call("sudo apt update", "forbidden", "home");
        assert_eq!(rule_args(&e, "allow", false)[2], "sudo");
        assert_eq!(rule_args(&e, "deny", false)[2], "deny");
        let e = json!({"center": "home", "cap": "fs", "action": "write", "target": "/srv/a"});
        assert_eq!(
            rule_args(&e, "deny", false)[3..6],
            ["/srv/a", "--action", "fs.write"]
        );
    }

    #[test]
    fn times_in_words() {
        assert_eq!(ago(NOW - 10_000, NOW), "just now");
        assert_eq!(ago(NOW - 5 * 3_600_000, NOW), "5 h ago");
        assert_eq!(ago(NOW - 3 * 86_400_000, NOW), "3 days ago");
        assert_eq!(exact(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(exact(1_760_800_000_000), "2025-10-18 15:06:40 UTC");
    }
}
