//! The decision engine: whether one call of one center may run (architecture
//! §5.1, spec §7).
//!
//! The order is fixed and only ever narrows: an `off` capability is disabled;
//! a denied path or command is forbidden; then the mode decides, and protected
//! paths, `always_ask` commands, sense and actuate effects and tainted calls
//! turn an allow into an ask. A grant from an earlier approval turns an ask
//! back into an allow, except for asks only a one-off answer may settle.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobMatcher};
use nerve_proto::Effect;

use crate::config::{Access, CapSetting, CenterPolicy, Folder, Mode};
use crate::paths::within;
use crate::protected::{Protected, expand};

/// An answer the owner (or the center) may give to an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Choice {
    Once,
    Session,
    Time,
    Deny,
}

impl Choice {
    pub fn as_str(self) -> &'static str {
        match self {
            Choice::Once => "once",
            Choice::Session => "session",
            Choice::Time => "time",
            Choice::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Choice> {
        match s {
            "once" => Some(Choice::Once),
            "session" => Some(Choice::Session),
            "time" => Some(Choice::Time),
            "deny" => Some(Choice::Deny),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask {
        reasons: Vec<String>,
        choices: Vec<Choice>,
    },
    /// Policy refuses and no approval can change it.
    Forbidden(String),
    /// The capability or action is off.
    Disabled(String),
}

/// One path a call touches, already resolved (`paths::resolve`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub path: PathBuf,
    pub write: bool,
}

/// One call to decide on.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    pub cap: &'a str,
    pub action: &'a str,
    pub effect: Effect,
    pub targets: &'a [Target],
    /// For `exec.run`: the command line and its working directory (also in
    /// `targets`).
    pub command: Option<&'a str>,
    pub cwd: Option<&'a Path>,
    pub session: Option<&'a str>,
    pub tainted: bool,
    pub now_ms: u64,
}

/// What the node knows besides the center's policy.
#[derive(Debug, Clone)]
pub struct Env<'a> {
    pub home: &'a Path,
    pub protected: &'a Protected,
    /// Whether commands run in `folders` mode can be confined (Landlock). When
    /// they cannot, a command in an execute folder asks instead.
    pub confined: bool,
}

/// Every choice.
const ALL: [Choice; 4] = [Choice::Once, Choice::Session, Choice::Time, Choice::Deny];
/// Commands, protected paths and tainted calls: only this one time, or no
/// (architecture §5.4).
const STRICT: [Choice; 2] = [Choice::Once, Choice::Deny];

fn matcher(globs: &[String]) -> Vec<GlobMatcher> {
    globs
        .iter()
        .filter_map(|g| Glob::new(g).ok())
        .map(|g| g.compile_matcher())
        .collect()
}

fn matches(globs: &[String], command: &str) -> bool {
    let command = command.trim();
    matcher(globs).iter().any(|m| m.is_match(command))
}

fn inside_folder<'f>(folders: &'f [Folder], path: &Path) -> Option<&'f Folder> {
    // The deepest folder wins, so an ro folder inside an rw one stays ro.
    folders
        .iter()
        .filter(|f| within(path, Path::new(&f.path)))
        .max_by_key(|f| f.path.len())
}

/// Decides `call` under `policy`; `grants` may turn an ask into an allow.
pub fn decide(policy: &CenterPolicy, env: &Env, call: &Call, grants: &Grants) -> Decision {
    match policy.cap_setting(call.cap, Some(call.action)) {
        Some(CapSetting::Off | CapSetting::Hidden) => {
            return Decision::Disabled(format!("{}.{} is off", call.cap, call.action));
        }
        Some(CapSetting::Ask) | Some(CapSetting::On) | None => {}
    }
    let cap_ask = policy.cap_setting(call.cap, Some(call.action)) == Some(CapSetting::Ask);

    // Denied paths and commands: forbidden in every mode.
    let deny: Vec<PathBuf> = policy
        .deny
        .iter()
        .filter_map(|d| expand(env.home, d))
        .collect();
    for t in call.targets {
        if let Some(d) = deny.iter().find(|d| within(&t.path, d)) {
            return Decision::Forbidden(format!(
                "{} is denied ({})",
                t.path.display(),
                d.display()
            ));
        }
    }
    let rules = &policy.commands;
    if let Some(cmd) = call.command {
        if matches(&rules.deny, cmd) {
            return Decision::Forbidden(format!("the command {cmd:?} is denied"));
        }
        if !rules.allow.is_empty() && !matches(&rules.allow, cmd) {
            return Decision::Forbidden(format!("the command {cmd:?} is not on the allow list"));
        }
    }

    let mode = policy.mode_at(call.now_ms);
    let mut reasons = Vec::new();
    let mut strict = false;

    // What the mode says.
    let mut allowed = match call.effect {
        Effect::Sense | Effect::Actuate => {
            reasons.push(format!("{} asks in every mode", call.effect.as_str()));
            false
        }
        Effect::Read | Effect::Write => match mode {
            Mode::Ask => false,
            Mode::Full => true,
            Mode::Folders => call.targets.iter().all(|t| {
                inside_folder(&policy.folders, &t.path)
                    .is_some_and(|f| !t.write || f.access == Access::Rw)
            }),
        },
        Effect::Execute => match mode {
            Mode::Ask => false,
            Mode::Full => true,
            Mode::Folders => {
                let in_exec = call
                    .cwd
                    .and_then(|c| inside_folder(&policy.folders, c))
                    .is_some_and(|f| f.execute);
                if in_exec && !env.confined {
                    reasons.push("commands cannot be confined on this machine".into());
                }
                in_exec && env.confined
            }
        },
    };
    if !allowed && reasons.is_empty() {
        reasons.push(match (mode, call.effect) {
            (Mode::Ask, _) => format!("mode ask: {} asks", call.effect.as_str()),
            (_, Effect::Execute) => "the working directory is not in an execute folder".into(),
            (_, Effect::Write) => "outside the read-write folders".into(),
            _ => "outside the folders".into(),
        });
    }
    if call.effect == Effect::Execute {
        // Commands are only ever approved one at a time.
        strict = true;
        if let Some(cmd) = call.command {
            if matches(&rules.always_ask, cmd) {
                allowed = false;
                reasons.push("the command is on the always-ask list".into());
            } else if matches(&rules.never_ask, cmd) && !call.tainted {
                allowed = true;
                reasons.clear();
            }
        }
    }
    if cap_ask && allowed {
        allowed = false;
        reasons.push(format!("{}.{} is set to ask", call.cap, call.action));
    }

    // Narrowing that holds in every mode.
    for t in call.targets {
        if let Some(entry) = env.protected.check(&t.path, t.write, &policy.folders) {
            allowed = false;
            strict = true;
            reasons.push(format!(
                "{} is protected ({})",
                t.path.display(),
                entry.display()
            ));
        } else if t.write
            && let Some(tc) = env.protected.tool_config(&t.path)
        {
            allowed = false;
            strict = true;
            reasons.push(format!("writes to {tc} run code later"));
        }
    }
    if call.tainted && matches!(call.effect, Effect::Write | Effect::Execute) && allowed {
        allowed = false;
        strict = true;
        reasons.push("the call is tainted".into());
    }

    if allowed {
        return Decision::Allow;
    }
    if !strict && grants.covers(call) {
        return Decision::Allow;
    }
    Decision::Ask {
        reasons,
        choices: if strict {
            STRICT.to_vec()
        } else {
            ALL.to_vec()
        },
    }
}

/// The scope a grant covers: the action, and for paths the folder the call
/// touched (the parent of a file, the folder itself for listings).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scope {
    pub cap: String,
    pub action: String,
    pub dirs: BTreeSet<PathBuf>,
}

impl Scope {
    pub fn of(call: &Call) -> Scope {
        let dirs = call
            .targets
            .iter()
            .map(|t| {
                if t.path.is_dir() {
                    t.path.clone()
                } else {
                    t.path.parent().unwrap_or(&t.path).to_path_buf()
                }
            })
            .collect();
        Scope {
            cap: call.cap.into(),
            action: call.action.into(),
            dirs,
        }
    }

    fn covers(&self, call: &Call) -> bool {
        self.cap == call.cap
            && self.action == call.action
            && call
                .targets
                .iter()
                .all(|t| self.dirs.iter().any(|d| within(&t.path, d)))
    }
}

#[derive(Debug, Clone)]
struct Grant {
    scope: Scope,
    /// `Some` for a session grant.
    session: Option<String>,
    until_ms: u64,
}

/// What approvals answered with `session` or `time` allow from then on, for
/// one center.
#[derive(Debug, Clone, Default)]
pub struct Grants {
    list: Vec<Grant>,
    now_ms: u64,
}

impl Grants {
    /// Remembers a `session` answer (until the session ends, at most
    /// `until_ms`) or a `time` answer (every session, until `until_ms`).
    pub fn add(&mut self, scope: Scope, session: Option<String>, until_ms: u64) {
        self.list.push(Grant {
            scope,
            session,
            until_ms,
        });
    }

    /// Drops what expired; the engine sees the grants as of `now_ms`.
    pub fn at(&mut self, now_ms: u64) -> &Grants {
        self.list.retain(|g| g.until_ms > now_ms);
        self.now_ms = now_ms;
        self
    }

    pub fn end_session(&mut self, session: &str) {
        self.list.retain(|g| g.session.as_deref() != Some(session));
    }

    pub fn clear(&mut self) {
        self.list.clear();
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    fn covers(&self, call: &Call) -> bool {
        self.list.iter().any(|g| {
            g.until_ms > call.now_ms
                && match &g.session {
                    Some(s) => call.session == Some(s.as_str()),
                    None => true,
                }
                && g.scope.covers(call)
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::{CommandRules, ProtectedOptions};

    const NOW: u64 = 1_000_000;

    fn policy(mode: Mode) -> CenterPolicy {
        CenterPolicy {
            mode,
            full_until: (mode == Mode::Full).then_some(NOW + 1000),
            folders: vec![
                Folder {
                    path: "/w/ro".into(),
                    access: Access::Ro,
                    execute: false,
                },
                Folder {
                    path: "/w/rw".into(),
                    access: Access::Rw,
                    execute: true,
                },
            ],
            deny: vec!["/w/rw/secret".into()],
            commands: CommandRules {
                deny: vec!["rm -rf /*".into()],
                always_ask: vec!["git push*".into()],
                never_ask: vec!["ls*".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    struct T {
        prot: Protected,
    }

    impl T {
        fn new() -> T {
            T {
                prot: Protected::new(Path::new("/h"), &[], &ProtectedOptions::default()),
            }
        }

        fn env(&self, confined: bool) -> Env<'_> {
            Env {
                home: Path::new("/h"),
                protected: &self.prot,
                confined,
            }
        }
    }

    fn call<'a>(effect: Effect, targets: &'a [Target], command: Option<&'a str>) -> Call<'a> {
        Call {
            cap: if effect == Effect::Execute {
                "exec"
            } else {
                "fs"
            },
            action: match effect {
                Effect::Execute => "run",
                Effect::Write => "write",
                _ => "read",
            },
            effect,
            targets,
            command,
            cwd: command.and(targets.first().map(|t| t.path.as_path())),
            session: Some("s1"),
            tainted: false,
            now_ms: NOW,
        }
    }

    fn t(p: &str, write: bool) -> Vec<Target> {
        vec![Target {
            path: p.into(),
            write,
        }]
    }

    fn short(d: &Decision) -> &'static str {
        match d {
            Decision::Allow => "allow",
            Decision::Ask { choices, .. } if choices.len() == 2 => "ask1",
            Decision::Ask { .. } => "ask",
            Decision::Forbidden(_) => "forbidden",
            Decision::Disabled(_) => "disabled",
        }
    }

    #[test]
    fn mode_matrix() {
        let x = T::new();
        let env = x.env(true);
        let g = Grants::default();
        let inside_ro = t("/w/ro/a", false);
        let inside_rw_w = t("/w/rw/a", true);
        let ro_w = t("/w/ro/a", true);
        let outside = t("/elsewhere/a", false);
        let exec_in = t("/w/rw", false);
        let exec_ro = t("/w/ro", false);
        let denied = t("/w/rw/secret/k", false);
        let key = t("/h/.ssh/id_rsa", false);
        let hook = t("/w/rw/.git/hooks/x", true);
        // (mode, effect, targets, command, expected)
        type Case<'a> = (Mode, Effect, &'a [Target], Option<&'a str>, &'a str);
        let cases: Vec<Case> = vec![
            (Mode::Ask, Effect::Read, &inside_ro, None, "ask"),
            (Mode::Ask, Effect::Write, &inside_rw_w, None, "ask"),
            (Mode::Ask, Effect::Execute, &exec_in, Some("make"), "ask1"),
            (Mode::Ask, Effect::Sense, &[], None, "ask"),
            (Mode::Ask, Effect::Actuate, &[], None, "ask"),
            (Mode::Folders, Effect::Read, &inside_ro, None, "allow"),
            (Mode::Folders, Effect::Read, &outside, None, "ask"),
            (Mode::Folders, Effect::Write, &inside_rw_w, None, "allow"),
            (Mode::Folders, Effect::Write, &ro_w, None, "ask"),
            (
                Mode::Folders,
                Effect::Execute,
                &exec_in,
                Some("make"),
                "allow",
            ),
            (
                Mode::Folders,
                Effect::Execute,
                &exec_ro,
                Some("make"),
                "ask1",
            ),
            (Mode::Folders, Effect::Sense, &[], None, "ask"),
            (Mode::Folders, Effect::Actuate, &[], None, "ask"),
            (Mode::Full, Effect::Read, &outside, None, "allow"),
            (Mode::Full, Effect::Write, &ro_w, None, "allow"),
            (Mode::Full, Effect::Execute, &exec_ro, Some("make"), "allow"),
            (Mode::Full, Effect::Sense, &[], None, "ask"),
            (Mode::Full, Effect::Actuate, &[], None, "ask"),
            // Command rules.
            (
                Mode::Full,
                Effect::Execute,
                &exec_in,
                Some("git push origin"),
                "ask1",
            ),
            (
                Mode::Ask,
                Effect::Execute,
                &exec_ro,
                Some("ls -la"),
                "allow",
            ),
            (
                Mode::Full,
                Effect::Execute,
                &exec_in,
                Some("rm -rf /home"),
                "forbidden",
            ),
            // Denied paths, in every mode.
            (Mode::Full, Effect::Read, &denied, None, "forbidden"),
            // Protected paths ask once, also in full.
            (Mode::Full, Effect::Read, &key, None, "ask1"),
            (Mode::Full, Effect::Write, &hook, None, "ask1"),
        ];
        for (mode, effect, targets, cmd, want) in cases {
            let p = policy(mode);
            let d = decide(&p, &env, &call(effect, targets, cmd), &g);
            assert_eq!(
                short(&d),
                want,
                "{mode:?} {effect:?} {targets:?} {cmd:?}: {d:?}"
            );
        }
        // Folders mode without confinement asks for commands.
        let d = decide(
            &policy(Mode::Folders),
            &x.env(false),
            &call(Effect::Execute, &exec_in, Some("make")),
            &g,
        );
        assert_eq!(short(&d), "ask1");
        // Expired full is folders.
        let mut p = policy(Mode::Full);
        p.full_until = Some(NOW);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &outside, None), &g)),
            "ask"
        );
    }

    #[test]
    fn caps_settings() {
        let x = T::new();
        let env = x.env(true);
        let g = Grants::default();
        let inside = t("/w/ro/a", false);
        let mut p = policy(Mode::Folders);
        p.caps.insert("fs".into(), CapSetting::Off);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &inside, None), &g)),
            "disabled"
        );
        p.caps.insert("fs.read".into(), CapSetting::Ask);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &inside, None), &g)),
            "ask"
        );
    }

    #[test]
    fn taint_narrows() {
        let x = T::new();
        let env = x.env(true);
        let g = Grants::default();
        let p = policy(Mode::Full);
        let w = t("/w/rw/a", true);
        let mut c = call(Effect::Write, &w, None);
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c, &g)), "ask1");
        let e = t("/w/rw", false);
        let mut c = call(Effect::Execute, &e, Some("ls"));
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c, &g)), "ask1");
        // Reads are not narrowed by taint.
        let r = t("/x/a", false);
        let mut c = call(Effect::Read, &r, None);
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c, &g)), "allow");
    }

    #[test]
    fn grants_by_session_and_time() {
        let x = T::new();
        let env = x.env(true);
        let p = policy(Mode::Ask);
        let a = t("/x/d/a", false);
        let c = call(Effect::Read, &a, None);
        let mut g = Grants::default();
        g.add(Scope::of(&c), Some("s1".into()), NOW + 10);
        assert_eq!(short(&decide(&p, &env, &c, g.at(NOW))), "allow");
        // Another file in the same folder, same session.
        let b = t("/x/d/b", false);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &b, None), g.at(NOW))),
            "allow"
        );
        // Another session, another folder, another action: ask.
        let mut other = call(Effect::Read, &a, None);
        other.session = Some("s2");
        assert_eq!(short(&decide(&p, &env, &other, g.at(NOW))), "ask");
        let elsewhere = t("/y/a", false);
        assert_eq!(
            short(&decide(
                &p,
                &env,
                &call(Effect::Read, &elsewhere, None),
                g.at(NOW)
            )),
            "ask"
        );
        g.end_session("s1");
        assert_eq!(short(&decide(&p, &env, &c, g.at(NOW))), "ask");
        // A time grant holds in every session until it expires.
        g.add(Scope::of(&c), None, NOW + 10);
        assert_eq!(short(&decide(&p, &env, &other, g.at(NOW))), "allow");
        let mut late = other.clone();
        late.now_ms = NOW + 10;
        assert_eq!(short(&decide(&p, &env, &late, g.at(NOW + 10))), "ask");
        assert!(g.is_empty());
        // Grants never settle a protected path.
        let k = t("/h/.ssh/k", false);
        let ck = call(Effect::Read, &k, None);
        g.add(Scope::of(&ck), None, NOW + 10);
        assert_eq!(short(&decide(&p, &env, &ck, g.at(NOW))), "ask1");
    }
}
