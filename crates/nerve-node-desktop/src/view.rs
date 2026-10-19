//! What the pages show, made from the CLI's JSON answers
//! (docs/user/commands.md): the words, their tones, and the arguments of the
//! commands the buttons run. Nothing here decides anything about the node;
//! it only says what the node said, for people.

use serde_json::Value;
use slint::{ModelRc, SharedString, VecModel};

use crate::{
    AuditRow, CapRow, CenterRow, FolderRow, HelpArg, HelpCard, HelpSection, HelpVerb, LogRow,
    NodeStatus, RelayNodeRow, Tone,
};

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
            "No center reaches this machine. What you change here counts from the node's next start.",
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

/// When a center's folder or user mode ends, in words; nothing without an
/// end.
pub fn mode_until(c: &Value, now_ms: u64) -> String {
    match c["until"].as_u64() {
        Some(until) if until > now_ms && c["mode"] != "allowlist" => {
            format!("Back to allowlist mode {}.", ahead(until - now_ms))
        }
        _ => String::new(),
    }
}

/// The folders of `folder ls --json`.
pub fn folders(v: &Value) -> Vec<FolderRow> {
    v["folders"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| FolderRow {
            path: s(&f["path"]).into(),
            read: f["read"] == true,
            write: f["write"] == true,
            execute: f["execute"] == true,
        })
        .collect()
}

/// The rights `folder set` takes for a folder: `=rwx`, the letters that
/// are on.
pub fn rights(read: bool, write: bool, execute: bool) -> String {
    let mut r = String::from("=");
    for (on, c) in [(read, 'r'), (write, 'w'), (execute, 'x')] {
        if on {
            r.push(c);
        }
    }
    r
}

/// One list of `rule ls --json`.
pub fn rule_list_of(v: &Value, list: &str) -> Vec<SharedString> {
    v[list]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(SharedString::from)
        .collect()
}

/// Why the keys cannot go into the system keyring here, by the `reason` of
/// `config get machine.secret_storage --json`.
pub fn no_keyring(reason: &str) -> &'static str {
    match reason {
        "windows-service" => {
            "Not on Windows: the service runs as its own account, and a keyring belongs to one account, so the service would not find its keys there."
        }
        "old-landlock" => {
            "Not on this Linux: below version 7.1 it cannot keep commands away from the keyring."
        }
        _ => {
            "No keyring answers for the account the node runs as. It has no desktop session of its own, so its keys stay in files."
        }
    }
}

/// What the app says after `center rotate-key` gave the center `name` a new
/// key (`said`): the key as the CLI showed it, and, in the app's words
/// instead of the CLI's command line, whether the center still takes the
/// old one, after `--end-grace` (`ended`) or without it.
pub fn new_key(name: &str, said: &Value, ended: Option<Result<Value, String>>) -> String {
    let key: Vec<&str> = said["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(2)
        .collect();
    let then = match ended {
        None => format!("The old key is deleted here. {name} takes it for 7 more days."),
        Some(Ok(_)) => format!("The old key is deleted here, and {name} no longer takes it."),
        Some(Err(e)) => {
            format!("The old key is deleted here, but {name} still takes it for 7 more days: {e}")
        }
    };
    format!("{}\n{then}", key.join("\n"))
}

/// The token of `relay add` or `relay token` (`said["token"]`), in the
/// app's words: what the other node may do and where it enters the token,
/// and what to copy to it (the proxy with the token, the pin, and the
/// command for a node without the app).
pub fn relay_token(said: &Value) -> (String, String) {
    let t = &said["token"];
    let (node, proxy, pin) = (s(&t["node"]), s(&t["proxy"]), s(&t["pin"]));
    let mut text = format!(
        "{node} may use this relay now; it may reach {}. On {node}, enter the proxy and its pin below in the Nerve app, under Settings, Proxy; on a node without the app, run the command below there.",
        s(&t["reach"])
    );
    if proxy.contains("<address of this machine>") {
        text.push_str(
            " Put the address under which it reaches this machine in place of <address of this machine>.",
        );
    }
    if t["new_pin"] == true {
        text.push_str(
            " The relay has a new certificate: the other nodes behind it need its new pin too.",
        );
    }
    if t["relay_off"] == true {
        text.push_str(" The relay is off: turn it on here under Settings, Relay.");
    }
    let copy = format!("Proxy: {proxy}\nPin: {pin}\n\nnerve-node proxy set '{proxy}' --pin {pin}");
    (text, copy)
}

/// What `restore` did (`said["restored"]`), in the app's words: the
/// centers, what to pair again, and what to set again and where. `started`
/// says what became of the node: the app started it again, or it waits.
pub fn restored(said: &Value, started: &str) -> String {
    let r = &said["restored"];
    let names = |k: &str| -> Vec<&str> {
        r[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    let centers = names("centers");
    let mut lines = vec![if centers.is_empty() {
        "The node's settings and keys are restored; it is paired with no center.".to_string()
    } else {
        format!(
            "The node's settings and keys are restored, with the pairing of {}.",
            centers.join(", ")
        )
    }];
    for c in names("no_key") {
        lines.push(format!(
            "{c}: its key was not in the backup. Unpair {c} on the Centers page and pair it again."
        ));
    }
    let mut said = Vec::new();
    for n in r["notes"].as_array().into_iter().flatten() {
        let center = s(&n["center"]);
        let line = match s(&n["fix"]) {
            "proxy" => "The proxy is not restored whole: set it again under Settings, Proxy.".into(),
            "sudo" => "Sudo is off: its password is in no backup. Turn it on again on the Permissions page.".into(),
            "sudo-file" => "Sudo is off, but the administrator's password it kept could not be deleted: turn sudo on and off again on the Permissions page.".into(),
            "pin" => format!("The pin of {center} here differed from the backup's, and the restore took the backup's. If the node does not link to {center}, set center.{center}.pin under Settings, Any setting."),
            "relay" => "The relay's TLS key was not in the backup: turn the relay on again under Settings, Relay; the nodes behind it need its new pin.".into(),
            _ => full_sentence(s(&n["text"])),
        };
        // Several notes can ask for the same: it is said once.
        if !said.contains(&line) {
            said.push(line);
        }
    }
    lines.extend(said);
    // What it did, what to do, and the node, each a paragraph.
    let mut text = lines[0].clone();
    if lines.len() > 1 {
        text.push_str("\n\n");
        text.push_str(&lines[1..].join("\n"));
    }
    format!("{text}\n\n{started}")
}

/// `text` as a sentence: its first letter up, a full stop at its end.
fn full_sentence(text: &str) -> String {
    let mut out = sentence(text);
    if !out.ends_with('.') {
        out.push('.');
    }
    out
}

/// Whether a rule typed for the allow or deny list is in the pattern form
/// for files and other actions (`fs.read:~/notes/*`, `fs:~/private/*`),
/// which `rule add` refuses as a command and `config add` takes: the test of
/// nerve-node's `rule add` (`List::entry`). A single letter before the `:`
/// is a drive (`C:\tools\x.exe`), not a capability.
pub fn pattern_rule(text: &str) -> bool {
    text.trim().split_once(':').is_some_and(|(scope, _)| {
        (scope.contains('.') || scope.len() > 1) && nerve_policy::rules::valid_scope(scope)
    })
}

/// The capability switches of `cap ls --json`: each capability the node
/// knows, then its actions, with what is set (on when nothing is).
pub fn caps(v: &Value) -> Vec<CapRow> {
    let setting = |name: &str| match v["caps"][name].as_str() {
        Some("off") => (1, true),
        Some("hidden") => (2, true),
        Some(_) => (0, true),
        None => (0, false),
    };
    let mut rows = Vec::new();
    for (cap, actions) in v["known"].as_object().into_iter().flatten() {
        let (s, set) = setting(cap);
        rows.push(CapRow {
            name: cap.as_str().into(),
            action: false,
            setting: s,
            set,
        });
        for a in actions
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let name = format!("{cap}.{a}");
            let (s, set) = setting(&name);
            rows.push(CapRow {
                name: name.into(),
                action: true,
                setting: s,
                set,
            });
        }
    }
    rows
}

/// The word `cap set` takes for a switch.
pub fn cap_word(setting: i32) -> &'static str {
    match setting {
        1 => "off",
        2 => "hidden",
        _ => "on",
    }
}

/// The lines of the log to show, from `newest` first: all of them, or the
/// errors and warnings only.
pub fn log_rows(newest: &[Value], problems_only: bool, now_ms: u64) -> Vec<LogRow> {
    newest
        .iter()
        .filter(|e| !problems_only || matches!(s(&e["level"]), "error" | "warn"))
        .map(|e| {
            let ts = e["ts"].as_u64().unwrap_or_default();
            let level = s(&e["level"]);
            let mut msg = s(&e["msg"]).to_string();
            if let Some(n) = e["node"].as_str() {
                msg = format!("{msg} ({n})");
            }
            LogRow {
                tone: match level {
                    "error" => Tone::Danger,
                    "warn" => Tone::Warn,
                    "info" => Tone::Accent,
                    _ => Tone::Neutral,
                },
                level: match level {
                    "error" => "Error",
                    "warn" => "Warning",
                    "info" => "Info",
                    "debug" => "Debug",
                    other => other,
                }
                .into(),
                msg: msg.into(),
                when: ago(ts, now_ms).into(),
                when_exact: exact(ts).into(),
            }
        })
        .collect()
}

/// The command list of `nerve-node --help`, read from the CLI's own
/// definition, as the Help page shows it.
pub fn help(h: &nerve_node::cli::Help) -> Vec<HelpSection> {
    fn model<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
        ModelRc::new(VecModel::from(v))
    }
    h.sections
        .iter()
        .map(|s| HelpSection {
            name: s.name.as_str().into(),
            about: s.about.as_str().into(),
            cards: model(
                s.cards
                    .iter()
                    .map(|c| HelpCard {
                        name: c.name.as_str().into(),
                        about: c.about.as_str().into(),
                        verbs: model(
                            c.verbs
                                .iter()
                                .map(|v| HelpVerb {
                                    usage: v.usage.as_str().into(),
                                    about: v.about.as_str().into(),
                                    args: model(
                                        v.args
                                            .iter()
                                            .map(|a| HelpArg {
                                                name: a.name.as_str().into(),
                                                about: a.about.as_str().into(),
                                            })
                                            .collect(),
                                    ),
                                })
                                .collect(),
                        ),
                    })
                    .collect(),
            ),
        })
        .collect()
}

/// The nodes of `relay ls --json` that may use the relay.
pub fn relay_nodes(v: &Value) -> Vec<RelayNodeRow> {
    v["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|n| {
            let centers: Vec<&str> = n["centers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            RelayNodeRow {
                centers: ModelRc::new(VecModel::from(
                    centers
                        .iter()
                        .map(|c| SharedString::from(*c))
                        .collect::<Vec<_>>(),
                )),
                own_limits: n["own_limits"] == true,
                max_links: n["max_links"].as_i64().unwrap_or_default() as i32,
                max_opens: n["max_opens_per_minute"].as_i64().unwrap_or_default() as i32,
                name: s(&n["name"]).into(),
                reach: if centers.is_empty() {
                    "may reach every https center of this node".to_string()
                } else {
                    format!("may reach {}", centers.join(", "))
                }
                .into(),
                limits: if n["own_limits"] == true {
                    format!(
                        "its own limits: {} tunnels at once, {} opened a minute",
                        n["max_links"], n["max_opens_per_minute"]
                    )
                } else {
                    String::new()
                }
                .into(),
            }
        })
        .collect()
}

/// A setting's value as `config get --json` gave it, for people: a text as
/// it is, anything else as JSON.
pub fn setting(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    }
}

/// A proxy URL and the password the owner typed, as `proxy set` takes them
/// with `--password-stdin`: a password in the URL (`user:password@`) moves
/// out of it, unless one was typed. `None`: no password.
pub fn proxy_login(url: &str, typed: &str) -> (String, Option<String>) {
    let mut url = url.to_string();
    let mut password = (!typed.is_empty()).then(|| typed.to_string());
    if let Some(scheme) = url.find("://")
        && let Some(at) = url.rfind('@')
        && at > scheme
        && let Some(colon) = url[scheme + 3..at].find(':').map(|c| c + scheme + 3)
    {
        let given = url[colon + 1..at].to_string();
        url.replace_range(colon..at, "");
        // A password in a URL is %-escaped; on stdin it is taken as it is.
        if password.is_none() {
            password = Some(pct_decode(&given));
        }
    }
    (url, password)
}

/// `%XX` escapes undone; a broken one stays as it is.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| std::str::from_utf8(b.get(i + 1..i + 3)?).ok())
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(x) => {
                out.push(x);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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
    // A list of words, such as rules: what came and what went.
    let words = |v: &Value| -> Option<Vec<String>> {
        if v.is_null() {
            return Some(Vec::new());
        }
        v.as_array()?
            .iter()
            .map(|e| e.as_str().map(str::to_string))
            .collect()
    };
    if (old.is_array() || new.is_array())
        && let (Some(a), Some(b)) = (words(old), words(new))
    {
        let added: Vec<&str> = b
            .iter()
            .filter(|w| !a.contains(w))
            .map(String::as_str)
            .collect();
        let removed: Vec<&str> = a
            .iter()
            .filter(|w| !b.contains(w))
            .map(String::as_str)
            .collect();
        if !added.is_empty() {
            out.push(format!("{key} + {}", added.join(", ")));
        }
        if !removed.is_empty() {
            out.push(format!("{key} − {}", removed.join(", ")));
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

/// The audit entries to show, from the `newest` first (crate::app asks for
/// as many as the page shows). `centers` are the paired ones, whose entries take rule buttons.
pub fn audit(newest: &[Value], centers: &[String], now_ms: u64) -> Vec<AuditRow> {
    newest
        .iter()
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
    /// The relay's token in the app's words: no line sends the owner of
    /// this machine to a terminal; the command is there for the other node,
    /// which may have no app.
    #[test]
    fn a_relay_token_says_where_the_other_node_enters_it() {
        let v = json!({"messages": ["on lab-pc, run:"], "token": {
            "node": "lab-pc", "token": "t0k", "pin": "p1n",
            "proxy": "https://lab-pc:t0k@<address of this machine>:7491",
            "reach": "every https center of this node", "new_pin": false, "relay_off": true,
        }});
        let (text, copy) = relay_token(&v);
        assert!(copy.starts_with("Proxy: https://lab-pc:t0k@"), "{copy}");
        assert!(copy.contains("Pin: p1n"), "{copy}");
        assert!(
            text.contains("in place of <address of this machine>"),
            "{text}"
        );
        assert!(text.contains("under Settings, Proxy"), "{text}");
        assert!(text.contains("under Settings, Relay"), "{text}");
        assert!(!text.contains('`') && !copy.contains('`'), "{text}");
    }

    /// A restore in the app's words: the CLI's commands become the places
    /// in the app, and a note without one is kept as a sentence.
    #[test]
    fn a_restore_says_what_to_do_in_the_app() {
        let v = json!({"messages": ["Start the node. … (docs/user/backup.md)"], "restored": {
            "centers": ["home", "lab"], "kept": [], "no_key": ["lab"],
            "notes": [
                {"text": "the sudo switch is off: `nerve-node sudo on` turns it on", "fix": "sudo", "center": null},
                {"text": "the pin of center home here …: `nerve-node config set center.home.pin <pin>`", "fix": "pin", "center": "home"},
                {"text": "run `nerve-node proxy set` again", "fix": "proxy", "center": null},
                {"text": "run `nerve-node proxy set` again", "fix": "proxy", "center": null},
                {"text": "the node key for home was rotated after the backup was made", "fix": null, "center": null},
            ],
        }});
        let text = restored(&v, "The node started again.");
        assert!(text.contains("pairing of home, lab"), "{text}");
        assert!(text.contains("Unpair lab on the Centers page"), "{text}");
        assert!(text.contains("on the Permissions page"), "{text}");
        assert!(
            text.contains("set center.home.pin under Settings, Any setting"),
            "{text}"
        );
        assert_eq!(text.matches("Settings, Proxy").count(), 1, "{text}");
        assert!(
            text.contains("The node key for home was rotated after the backup was made."),
            "{text}"
        );
        assert!(text.ends_with("The node started again."), "{text}");
        assert!(!text.contains('`') && !text.contains("docs/user"), "{text}");
    }

    use super::*;
    use serde_json::json;
    use slint::Model;

    const NOW: u64 = 1_760_800_000_000;

    #[test]
    fn a_new_key_is_said_without_the_command_line() {
        // What `center rotate-key --json` says (cli.rs, rotate_key).
        let said = json!({"messages": [
            "center lab took this machine's new key:",
            "  ed25519:AAAA",
            "The old key is deleted here. The center takes it for 7 more days, unless you end that now with `nerve-node center rotate-key --end-grace --center lab`.",
        ]});
        let text = new_key("lab", &said, None);
        assert!(text.starts_with("center lab took this machine's new key:\n  ed25519:AAAA\n"));
        assert!(text.ends_with("lab takes it for 7 more days."), "{text}");
        assert!(!text.contains("nerve-node"), "{text}");
        let ended = new_key("lab", &said, Some(Ok(json!({}))));
        assert!(ended.ends_with("lab no longer takes it."), "{ended}");
        let failed = new_key("lab", &said, Some(Err("the link dropped".into())));
        assert!(failed.contains("still takes it") && failed.contains("the link dropped"));
    }

    #[test]
    fn a_pattern_for_files_is_told_from_a_command() {
        for p in ["fs.read:~/notes/*", "fs:~/private/*", "exec.run:make *"] {
            assert!(pattern_rule(p), "{p}");
        }
        for c in [
            "cargo build",
            "C:\\tools\\x.exe",
            "git commit -m a:b",
            "echo x:y",
        ] {
            assert!(!pattern_rule(c), "{c}");
        }
    }

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
        let entries = [
            call("git status", "allowed", "home"),
            json!({"ts": NOW, "kind": "settings", "by": "local", "version": 4,
                "changes": [{"key": "center.home.policy.mode", "old": "allowlist", "new": "user"}]}),
            call("ls", "forbidden", "gone"),
            call(&cut, "forbidden", "home"),
            json!({"ts": NOW, "center": "home", "cap": "fs", "action": "read", "target": "/etc/shadow", "decision": "forbidden", "reason": "protected path"}),
        ];
        let newest: Vec<Value> = entries.iter().rev().cloned().collect();
        let rows = audit(&newest, &centers, NOW);
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
            "By local. center.home.policy.allow + exec.run:cargo *; center.lab.paused: false → true; center.new added"
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
    fn the_permissions_of_a_center() {
        let f = folders(
            &json!({"folders": [{"path": "/srv/a", "read": true, "write": false, "execute": true}]}),
        );
        assert_eq!(
            (f[0].path.as_str(), f[0].read, f[0].write, f[0].execute),
            ("/srv/a", true, false, true)
        );
        assert_eq!(rights(true, false, true), "=rx");
        assert_eq!(rights(false, false, false), "=");
        let rows = caps(&json!({"caps": {"exec.run": "off", "fs": "hidden"},
            "known": {"exec": ["run", "signal"], "fs": ["read"]}}));
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["exec", "exec.run", "exec.signal", "fs", "fs.read"]);
        assert_eq!((rows[0].setting, rows[0].set), (0, false));
        assert_eq!(
            (rows[1].setting, rows[1].set, rows[1].action),
            (1, true, true)
        );
        assert_eq!(rows[3].setting, 2);
        assert_eq!(cap_word(2), "hidden");
        let c = json!({"mode": "user", "until": NOW + 90 * 60_000});
        assert_eq!(mode_until(&c, NOW), "Back to allowlist mode in 1 h.");
        assert_eq!(mode_until(&json!({"mode": "user"}), NOW), "");
        let login = |u: &str, t: &str| proxy_login(u, t);
        assert_eq!(
            login("http://p.example:3128", ""),
            ("http://p.example:3128".into(), None)
        );
        assert_eq!(
            login("http://alice:s%40cret@p.example:3128", ""),
            ("http://alice@p.example:3128".into(), Some("s@cret".into()))
        );
        assert_eq!(
            login("http://alice@p.example:3128", "typed"),
            ("http://alice@p.example:3128".into(), Some("typed".into()))
        );
        assert_eq!(
            login("http://alice:old@p.example:3128", "typed"),
            ("http://alice@p.example:3128".into(), Some("typed".into()))
        );
    }

    #[test]
    fn the_log_newest_first_or_its_problems() {
        let lines = [
            json!({"ts": NOW, "level": "error", "msg": "cannot connect"}),
            json!({"ts": NOW, "level": "info", "msg": "node started"}),
            json!({"ts": NOW, "level": "warn", "msg": "link dropped", "node": "web-1"}),
        ];
        let rows = log_rows(&lines, false, NOW);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            (rows[0].level.as_str(), rows[0].tone),
            ("Error", Tone::Danger)
        );
        let rows = log_rows(&lines, true, NOW);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].msg, "link dropped (web-1)");
    }

    #[test]
    fn help_is_the_clis_own() {
        let sections = help(&nerve_node::cli::help());
        let names: Vec<String> = sections.iter().map(|s| s.name.to_string()).collect();
        assert!(names.contains(&"Pair and connect".to_string()), "{names:?}");
        let all: Vec<String> = sections
            .iter()
            .flat_map(|s| s.cards.iter().collect::<Vec<_>>())
            .flat_map(|c| {
                c.verbs
                    .iter()
                    .map(|v| v.usage.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(all.iter().any(|u| u.contains("audit")), "{all:?}");
        assert!(all.iter().any(|u| u.contains("log")), "{all:?}");
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
