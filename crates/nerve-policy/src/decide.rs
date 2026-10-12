//! The decision engine: whether one call of one center may run (architecture
//! §5.1, spec node-local §3).
//!
//! There are two outcomes, allowed and refused; nothing waits for an answer.
//! The order only ever narrows: a call that touches the node's own folders
//! (config, keys, state) is forbidden before anything else is looked at, and
//! nothing lifts that; an `off` capability is disabled; a sudo
//! command with the sudo switch off, and anything a deny rule matches, is
//! forbidden whatever else says; then a sudo command needs the sudo allow
//! list, and any other call the mode: allow rules in `allowlist` mode, the
//! folders in `folder` mode, the user's own reach in `user` mode. A call no
//! mode and no rule allows is refused at once, and so is one that touches a
//! protected path, whatever allowed it.

use std::path::{Path, PathBuf};

use nerve_proto::Effect;

use crate::config::{Access, CapSetting, CenterPolicy, Folder, Mode};
use crate::paths::{to_wire, within};
use crate::protected::Protected;
use crate::rules::{RuleSet, command_matches};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Policy refuses the call.
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
    pub now_ms: u64,
}

/// What the node knows besides the center's policy.
#[derive(Debug, Clone)]
pub struct Env<'a> {
    pub home: &'a Path,
    pub protected: &'a Protected,
    /// Whether commands run in `folder` mode can be confined (Landlock). When
    /// they cannot, a command in an execute folder is refused.
    pub confined: bool,
    /// The node's sudo switch: on only while the node holds a sudo password
    /// it has checked.
    pub sudo: bool,
}

/// The arguments of a command that runs through `sudo`: its first word is
/// `sudo` (or a path ending in `/sudo`). Anything else (`env sudo`, `ls;
/// sudo x`) is not a sudo command here; the node runs those so that sudo
/// cannot gain privileges at all.
pub fn sudo_command(command: &str) -> Option<&str> {
    let command = command.trim_start();
    let end = command
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(command.len());
    let (first, rest) = command.split_at(end);
    (first == "sudo" || first.ends_with("/sudo")).then_some(rest.trim_start())
}

/// Characters that chain, substitute or redirect in a shell.
const SHELL_CONTROL: &[char] = &[';', '&', '|', '$', '`', '(', ')', '<', '>', '\n', '\r'];

fn inside_folder<'f>(folders: &'f [Folder], path: &Path) -> Option<&'f Folder> {
    // The deepest folder wins, so an ro folder inside an rw one stays ro.
    folders
        .iter()
        .filter(|f| within(path, Path::new(&f.path)))
        .max_by_key(|f| f.path.len())
}

/// The strings rules are tried on (`rules`): the command line of `exec.run`,
/// the paths of an `fs` call, else the action itself.
fn rule_targets(call: &Call) -> Vec<String> {
    if let Some(cmd) = call.command {
        vec![cmd.trim().to_string()]
    } else if call.targets.is_empty() {
        vec![format!("{}.{}", call.cap, call.action)]
    } else {
        call.targets.iter().map(|t| to_wire(&t.path)).collect()
    }
}

/// How a refusal names a rule target.
fn name(call: &Call, target: &str) -> String {
    if call.command.is_some() {
        format!("the command {target:?}")
    } else {
        target.to_string()
    }
}

/// The node's own folder `call` touches: one of its paths, its working
/// directory, or a path its command line names plainly.
fn own_folder<'p>(env: &'p Env, call: &Call) -> Option<&'p Path> {
    call.targets
        .iter()
        .map(|t| t.path.as_path())
        .chain(call.cwd)
        .find_map(|p| env.protected.own(p))
        .or_else(|| call.command.and_then(|c| env.protected.own_in_command(c)))
}

/// Decides `call` under `policy`.
pub fn decide(policy: &CenterPolicy, env: &Env, call: &Call) -> Decision {
    // The node's own folders hold the policy itself and the keys that sign
    // it: no rule, mode or release reaches them, so they come first.
    if let Some(own) = own_folder(env, call) {
        return Decision::Forbidden(format!(
            "{} belongs to the node itself; no rule or mode reaches it",
            own.display()
        ));
    }

    let setting = policy.cap_setting(call.cap, Some(call.action));
    if matches!(setting, Some(CapSetting::Off | CapSetting::Hidden)) {
        return Decision::Disabled(format!("{}.{} is off", call.cap, call.action));
    }

    // The switch is checked before any rule: off, no sudo allow entry makes a
    // sudo command run, because the node has no password to give it.
    let sudo = call.command.is_some_and(|c| sudo_command(c).is_some());
    if sudo && !env.sudo {
        return Decision::Forbidden("sudo is off on this node".into());
    }

    // Deny rules: forbidden in every mode, and they win over any allow.
    let targets = rule_targets(call);
    let deny = RuleSet::new(&policy.deny, env.home);
    for t in &targets {
        if let Some(rule) = deny.find(call.cap, call.action, t) {
            return Decision::Forbidden(format!("{} is denied ({rule})", name(call, t)));
        }
    }

    let mode = policy.mode_at(call.now_ms);
    let mut reasons = Vec::new();
    let mut allowed = if sudo {
        by_sudo_list(policy, call, &mut reasons)
    } else if mode == Mode::Allowlist {
        by_allow_rules(policy, env, call, &targets, &mut reasons)
    } else {
        by_mode(policy, env, call, mode, &mut reasons)
    };
    if !allowed && reasons.is_empty() {
        reasons.push("not allowed".into());
    }

    // Narrowing that holds in every mode.
    for t in call.targets {
        if let Some(entry) = env.protected.check(&t.path, t.write, &policy.folders) {
            allowed = false;
            reasons.push(format!(
                "{} is protected ({})",
                t.path.display(),
                entry.display()
            ));
        } else if t.write
            && let Some(tc) = env.protected.tool_config(&t.path)
        {
            allowed = false;
            reasons.push(format!("writes to {tc} run code later"));
        }
    }

    if allowed {
        Decision::Allow
    } else {
        Decision::Forbidden(reasons.join("; "))
    }
}

/// A sudo command runs only when the sudo allow list names it, in every mode.
fn by_sudo_list(policy: &CenterPolicy, call: &Call, reasons: &mut Vec<String>) -> bool {
    let cmd = call.command.unwrap_or_default();
    // An entry names one command; `sudo apt update; rm -rf /` must not slip
    // through a `sudo apt *` entry with a second command.
    if cmd.trim().contains(SHELL_CONTROL) {
        reasons.push(
            "a sudo command is one simple command (no ; & | $ ` ( ) < > or line breaks)".into(),
        );
        return false;
    }
    let ok = command_matches(&policy.sudo_allow, cmd);
    if !ok {
        reasons.push("a sudo command runs only when the sudo allow list names it".into());
    }
    ok
}

/// `allowlist` mode: every target needs an allow rule.
fn by_allow_rules(
    policy: &CenterPolicy,
    env: &Env,
    call: &Call,
    targets: &[String],
    reasons: &mut Vec<String>,
) -> bool {
    let allow = RuleSet::new(&policy.allow, env.home);
    for t in targets {
        // Commands run unconfined here, so a wildcard must not cover a second
        // command chained on: only a rule that names the line exactly does.
        let chained = call.command.is_some() && t.contains(SHELL_CONTROL);
        let found = if chained {
            allow.find_exact(call.cap, call.action, t)
        } else {
            allow.find(call.cap, call.action, t)
        };
        if found.is_none() {
            reasons.push(if chained && allow.find(call.cap, call.action, t).is_some() {
                format!(
                    "{} chains commands (; & | $ ` ( ) < > or a line break); only an allow rule that names it exactly covers that",
                    name(call, t)
                )
            } else {
                format!("no allow rule matches {}", name(call, t))
            });
            return false;
        }
    }
    true
}

/// `folder` and `user` mode: what the mode itself allows. Allow rules are not
/// looked at.
fn by_mode(
    policy: &CenterPolicy,
    env: &Env,
    call: &Call,
    mode: Mode,
    reasons: &mut Vec<String>,
) -> bool {
    match call.effect {
        // No mode allows these; only the owner's `on` does.
        Effect::Sense | Effect::Actuate => {
            let on = policy.cap_setting(call.cap, Some(call.action)) == Some(CapSetting::On);
            if !on {
                reasons.push(format!(
                    "{} is allowed only where {}.{} is set to on",
                    call.effect.as_str(),
                    call.cap,
                    call.action
                ));
            }
            on
        }
        Effect::Read | Effect::Write => {
            let ok = match mode {
                Mode::User => true,
                Mode::Folder => call.targets.iter().all(|t| {
                    inside_folder(&policy.folders, &t.path)
                        .is_some_and(|f| !t.write || f.access == Access::Rw)
                }),
                // The allow rules decide there (`by_allow_rules`).
                Mode::Allowlist => false,
            };
            if !ok {
                reasons.push(match call.effect {
                    Effect::Write => "outside the read-write folders".into(),
                    _ => "outside the folders".into(),
                });
            }
            ok
        }
        Effect::Execute => match mode {
            Mode::User => true,
            Mode::Allowlist => false,
            Mode::Folder => {
                let in_exec = call
                    .cwd
                    .and_then(|c| inside_folder(&policy.folders, c))
                    .is_some_and(|f| f.execute);
                if in_exec && !env.confined {
                    reasons.push("commands cannot be confined on this machine".into());
                } else if !in_exec {
                    reasons.push("the working directory is not in an execute folder".into());
                }
                in_exec && env.confined
            }
        },
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::ProtectedOptions;

    const NOW: u64 = 1_000_000;

    /// `mode` with two folders, a denied path and two denied commands.
    fn policy(mode: Mode) -> CenterPolicy {
        CenterPolicy {
            mode,
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
            deny: vec![
                "fs:/w/rw/secret/*".into(),
                "exec.run:rm -rf /*".into(),
                "exec.run:git push*".into(),
            ],
            ..Default::default()
        }
    }

    const MODES: [Mode; 3] = [Mode::Allowlist, Mode::Folder, Mode::User];

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
                sudo: false,
            }
        }

        fn sudo_on(&self) -> Env<'_> {
            Env {
                sudo: true,
                ..self.env(true)
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
            now_ms: NOW,
        }
    }

    /// A call of another capability, with no path and no command.
    fn action<'a>(effect: Effect, cap: &'a str, action: &'a str) -> Call<'a> {
        Call {
            cap,
            action,
            effect,
            targets: &[],
            command: None,
            cwd: None,
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
            Decision::Forbidden(_) => "refused",
            Decision::Disabled(_) => "disabled",
        }
    }

    fn run(p: &CenterPolicy, env: &Env, c: &Call) -> &'static str {
        short(&decide(p, env, c))
    }

    fn rules(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn folder_and_user_mode_matrix() {
        let x = T::new();
        let env = x.env(true);
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
            (Mode::Folder, Effect::Read, &inside_ro, None, "allow"),
            (Mode::Folder, Effect::Read, &outside, None, "refused"),
            (Mode::Folder, Effect::Write, &inside_rw_w, None, "allow"),
            (Mode::Folder, Effect::Write, &ro_w, None, "refused"),
            (
                Mode::Folder,
                Effect::Execute,
                &exec_in,
                Some("make"),
                "allow",
            ),
            (
                Mode::Folder,
                Effect::Execute,
                &exec_ro,
                Some("make"),
                "refused",
            ),
            (Mode::Folder, Effect::Sense, &[], None, "refused"),
            (Mode::Folder, Effect::Actuate, &[], None, "refused"),
            (Mode::User, Effect::Read, &outside, None, "allow"),
            (Mode::User, Effect::Write, &ro_w, None, "allow"),
            (Mode::User, Effect::Execute, &exec_ro, Some("make"), "allow"),
            (Mode::User, Effect::Sense, &[], None, "refused"),
            (Mode::User, Effect::Actuate, &[], None, "refused"),
            // Deny rules on commands.
            (
                Mode::User,
                Effect::Execute,
                &exec_in,
                Some("git push origin"),
                "refused",
            ),
            (
                Mode::Folder,
                Effect::Execute,
                &exec_in,
                Some("git push origin"),
                "refused",
            ),
            (
                Mode::User,
                Effect::Execute,
                &exec_in,
                Some("rm -rf /home"),
                "refused",
            ),
            // Denied paths, in every mode.
            (Mode::User, Effect::Read, &denied, None, "refused"),
            (Mode::Folder, Effect::Read, &denied, None, "refused"),
            // Protected paths are refused, also in user mode.
            (Mode::User, Effect::Read, &key, None, "refused"),
            (Mode::User, Effect::Write, &hook, None, "refused"),
        ];
        for (mode, effect, targets, cmd, want) in cases {
            let p = policy(mode);
            let d = decide(&p, &env, &call(effect, targets, cmd));
            assert_eq!(
                short(&d),
                want,
                "{mode:?} {effect:?} {targets:?} {cmd:?}: {d:?}"
            );
        }
        // Folder mode without confinement refuses commands.
        let d = decide(
            &policy(Mode::Folder),
            &x.env(false),
            &call(Effect::Execute, &exec_in, Some("make")),
        );
        assert_eq!(short(&d), "refused");
        // A limit that is still running changes nothing; one that has run out
        // leaves default deny, so a read in a folder needs a rule again.
        for mode in [Mode::Folder, Mode::User] {
            let mut p = policy(mode);
            p.until = Some(NOW + 1);
            let read = call(Effect::Read, &inside_ro, None);
            assert_eq!(run(&p, &env, &read), "allow", "{mode:?}");
            p.until = Some(NOW);
            assert_eq!(run(&p, &env, &read), "refused", "{mode:?}");
            p.allow = vec!["fs:/w/ro/*".into()];
            assert_eq!(run(&p, &env, &read), "allow", "{mode:?}");
        }
    }

    #[test]
    fn default_deny_refuses_without_a_rule() {
        let x = T::new();
        let env = x.env(true);
        // A new center: allowlist mode, no folder, no rule.
        let p = CenterPolicy::default();
        assert_eq!(p.mode, Mode::Allowlist);
        let r = t("/w/rw/a", false);
        let w = t("/w/rw/a", true);
        let e = t("/w/rw", false);
        for c in [
            call(Effect::Read, &r, None),
            call(Effect::Write, &w, None),
            call(Effect::Execute, &e, Some("make")),
            action(Effect::Sense, "camera", "snap"),
            action(Effect::Actuate, "lamp", "on"),
            action(Effect::Read, "notes", "list"),
        ] {
            let d = decide(&p, &env, &c);
            assert!(
                matches!(&d, Decision::Forbidden(why) if !why.is_empty()),
                "{:?}: {d:?}",
                c.effect
            );
        }
        // Folders do not count in allowlist mode, and neither does `on`.
        let mut p = policy(Mode::Allowlist);
        p.caps.insert("camera".into(), CapSetting::On);
        assert_eq!(run(&p, &env, &call(Effect::Read, &r, None)), "refused");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("make"))),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
    }

    #[test]
    fn an_allow_rule_lets_a_matching_call_through_in_allowlist_mode() {
        let x = T::new();
        let env = x.env(true);
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:make", "fs.read:/elsewhere/a", "fs.write:/w/rw/*"]);
        let e = t("/w/ro", false);
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        assert_eq!(run(&p, &env, &c("make")), "allow");
        // The rule names one command.
        assert_eq!(run(&p, &env, &c("make all")), "refused");
        assert_eq!(run(&p, &env, &c("cargo build")), "refused");
        let read = t("/elsewhere/a", false);
        assert_eq!(run(&p, &env, &call(Effect::Read, &read, None)), "allow");
        let other = t("/elsewhere/b", false);
        assert_eq!(run(&p, &env, &call(Effect::Read, &other, None)), "refused");
        // A rule of one action does not cover its sibling.
        let write = t("/w/rw/a/b", true);
        assert_eq!(run(&p, &env, &call(Effect::Write, &write, None)), "allow");
        let read_there = t("/w/rw/a/b", false);
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &read_there, None)),
            "refused"
        );
        // A path rule is no command rule and the other way round.
        let mut q = policy(Mode::Allowlist);
        q.allow = rules(&["fs:/w/*"]);
        assert_eq!(
            run(&q, &env, &call(Effect::Execute, &e, Some("/w/tool"))),
            "refused"
        );
        q.allow = rules(&["exec.run:/w/*"]);
        assert_eq!(
            run(&q, &env, &call(Effect::Read, &t("/w/a", false), None)),
            "refused"
        );
        // Other capabilities: by action, or with a wildcard by capability.
        let mut q = policy(Mode::Allowlist);
        q.allow = rules(&["camera.snap"]);
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "snap")),
            "allow"
        );
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "record")),
            "refused"
        );
        assert_eq!(
            run(&q, &env, &action(Effect::Actuate, "lamp", "on")),
            "refused"
        );
        q.allow = rules(&["camera"]);
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "record")),
            "allow"
        );
        // A capability that is off stays off.
        q.caps.insert("camera".into(), CapSetting::Off);
        assert_eq!(
            run(&q, &env, &action(Effect::Sense, "camera", "snap")),
            "disabled"
        );
        // Protected paths are refused whatever allowed them.
        let mut q = policy(Mode::Allowlist);
        q.allow = rules(&["fs:/h/*"]);
        let key = t("/h/.ssh/id_rsa", false);
        assert_eq!(run(&q, &env, &call(Effect::Read, &key, None)), "refused");
        let ok = t("/h/notes", false);
        assert_eq!(run(&q, &env, &call(Effect::Read, &ok, None)), "allow");
    }

    #[test]
    fn wildcard_rules_match() {
        let x = T::new();
        let env = x.env(true);
        let e = t("/w/ro", false);
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:git *", "fs.read:/notes/*"]);
        for cmd in ["git status", "git log -n 3", "git", "  git status  "] {
            assert_eq!(run(&p, &env, &c(cmd)), "allow", "{cmd}");
        }
        for cmd in ["gitk", "echo git status", "cat git"] {
            assert_eq!(run(&p, &env, &c(cmd)), "refused", "{cmd}");
        }
        for path in ["/notes/a", "/notes/a/b/c", "/notes"] {
            let r = t(path, false);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &r, None)),
                "allow",
                "{path}"
            );
        }
        for path in ["/notes2/a", "/other"] {
            let r = t(path, false);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &r, None)),
                "refused",
                "{path}"
            );
        }
        // The same forms deny, in a mode that otherwise allows.
        let mut u = policy(Mode::User);
        u.deny = rules(&["exec.run:docker *", "fs:/notes/*"]);
        assert_eq!(run(&u, &env, &c("docker run x")), "refused");
        assert_eq!(run(&u, &env, &c("dockerd")), "allow");
        let r = t("/notes/a/b", false);
        assert_eq!(run(&u, &env, &call(Effect::Read, &r, None)), "refused");
        // The refusal names the rule.
        assert!(matches!(
            decide(&u, &env, &c("docker run x")),
            Decision::Forbidden(m) if m.contains("docker *")
        ));
    }

    #[test]
    fn a_deny_rule_wins_over_an_allow_rule() {
        let x = T::new();
        let env = x.env(true);
        let e = t("/w/ro", false);
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:git *", "fs:/w/*", "camera"]);
        p.deny = rules(&["exec.run:git push*", "fs.write:/w/secret/*", "camera.snap"]);
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("git status"))),
            "allow"
        );
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("git push -f"))),
            "refused"
        );
        let r = t("/w/secret/k", false);
        let w = t("/w/secret/k", true);
        assert_eq!(run(&p, &env, &call(Effect::Read, &r, None)), "allow");
        assert_eq!(run(&p, &env, &call(Effect::Write, &w, None)), "refused");
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "record")),
            "allow"
        );
        // The exact same rule on both lists: deny.
        p.allow = rules(&["exec.run:make"]);
        p.deny = rules(&["exec.run:make"]);
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &e, Some("make"))),
            "refused"
        );
    }

    #[test]
    fn allow_rules_change_nothing_in_folder_and_user_mode() {
        let x = T::new();
        let env = x.env(true);
        let outside = t("/elsewhere/a", false);
        let ro_w = t("/w/ro/a", true);
        let exec_ro = t("/w/ro", false);
        let everything = rules(&["fs", "exec", "camera", "lamp.on"]);
        // What folder mode refuses stays refused, rule or not.
        let mut p = policy(Mode::Folder);
        p.allow = everything.clone();
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &outside, None)),
            "refused"
        );
        assert_eq!(run(&p, &env, &call(Effect::Write, &ro_w, None)), "refused");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &exec_ro, Some("make"))),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
        assert_eq!(
            run(&p, &env, &action(Effect::Actuate, "lamp", "on")),
            "refused"
        );
        // What user mode allows is allowed without one.
        let mut p = policy(Mode::User);
        assert_eq!(run(&p, &env, &call(Effect::Read, &outside, None)), "allow");
        assert_eq!(
            run(&p, &env, &call(Effect::Execute, &exec_ro, Some("make"))),
            "allow"
        );
        p.allow = everything;
        assert_eq!(run(&p, &env, &call(Effect::Read, &outside, None)), "allow");
        // ... and sense and actuate still need `on`, not an allow rule.
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "refused"
        );
        p.caps.insert("camera".into(), CapSetting::On);
        assert_eq!(
            run(&p, &env, &action(Effect::Sense, "camera", "snap")),
            "allow"
        );
    }

    #[test]
    fn a_deny_rule_refuses_in_every_mode() {
        let x = T::new();
        let env = x.env(true);
        let secret = t("/w/rw/secret/k", false);
        let fine = t("/w/rw/a", false);
        let exec = t("/w/rw", false);
        for mode in MODES {
            let mut p = policy(mode);
            p.allow = rules(&["fs:/w/*", "exec.run:*"]);
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &secret, None)),
                "refused",
                "{mode:?}"
            );
            assert_eq!(
                run(&p, &env, &call(Effect::Execute, &exec, Some("git push"))),
                "refused",
                "{mode:?}"
            );
            let d = decide(&p, &env, &call(Effect::Read, &secret, None));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("denied")),
                "{d:?}"
            );
            // The same call outside the denied path is allowed in all three.
            assert_eq!(
                run(&p, &env, &call(Effect::Read, &fine, None)),
                "allow",
                "{mode:?}"
            );
        }
    }

    #[test]
    fn caps_settings() {
        let x = T::new();
        let env = x.env(true);
        let inside = t("/w/ro/a", false);
        let mut p = policy(Mode::Folder);
        p.caps.insert("fs".into(), CapSetting::Off);
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &inside, None)),
            "disabled"
        );
        // An action's own setting wins over its capability's.
        p.caps.insert("fs.read".into(), CapSetting::On);
        assert_eq!(run(&p, &env, &call(Effect::Read, &inside, None)), "allow");
        // `on` does not widen what the mode refuses.
        let outside = t("/elsewhere/a", false);
        assert_eq!(
            run(&p, &env, &call(Effect::Read, &outside, None)),
            "refused"
        );
    }

    #[test]
    fn sense_and_actuate_need_an_explicit_on_in_folder_and_user_mode() {
        let x = T::new();
        let env = x.env(true);
        for effect in [Effect::Sense, Effect::Actuate] {
            for mode in [Mode::Folder, Mode::User] {
                let mut p = policy(mode);
                let c = action(effect, "camera", "snap");
                assert_eq!(run(&p, &env, &c), "refused");
                p.caps.insert("camera".into(), CapSetting::On);
                assert_eq!(run(&p, &env, &c), "allow");
            }
        }
    }

    #[test]
    fn sudo_needs_the_switch_and_a_sudo_allow_entry_in_every_mode() {
        let x = T::new();
        let off = x.env(true);
        let on = x.sudo_on();
        let e = t("/w/rw", false);
        let sudo = |cmd| call(Effect::Execute, &e, Some(cmd));
        for mode in MODES {
            let mut p = policy(mode);
            // No entry: refused in every mode, and no normal allow rule helps.
            p.allow = rules(&["exec.run:sudo *", "exec"]);
            let d = decide(&p, &on, &sudo("sudo apt update"));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("sudo allow list")),
                "{mode:?}: {d:?}"
            );
            // An entry, the switch on: it runs, in every mode.
            p.sudo_allow.push("sudo apt update".into());
            assert_eq!(run(&p, &on, &sudo("sudo apt update")), "allow", "{mode:?}");
            // Off, even an entry does not run it.
            assert_eq!(
                decide(&p, &off, &sudo("sudo apt update")),
                Decision::Forbidden("sudo is off on this node".into()),
                "{mode:?}"
            );
            // Only what the list names.
            for other in ["sudo rm -rf /", "/usr/bin/sudo apt upgrade", "  sudo -i"] {
                assert_eq!(run(&p, &on, &sudo(other)), "refused", "{mode:?} {other}");
            }
            // An entry never covers a second command.
            p.sudo_allow.push("sudo apt *".into());
            for chained in [
                "sudo apt x; id",
                "sudo apt $(id)",
                "sudo apt x > /etc/y",
                "sudo apt x\nid",
            ] {
                assert_eq!(run(&p, &on, &sudo(chained)), "refused", "{chained}");
            }
            assert_eq!(run(&p, &on, &sudo("sudo apt upgrade -y")), "allow");
            // Deny rules still apply to a sudo command.
            p.deny.push("exec.run:sudo apt*".into());
            assert_eq!(
                run(&p, &on, &sudo("sudo apt update")),
                "refused",
                "{mode:?}"
            );
        }
        // The sudo list is for sudo commands: without `sudo`, it allows nothing.
        let mut p = policy(Mode::Allowlist);
        p.sudo_allow = rules(&["apt *", "sudo apt *"]);
        assert_eq!(run(&p, &on, &sudo("apt update")), "refused");
        // A sudo command in a protected working directory is refused as well.
        p.sudo_allow = rules(&["sudo id"]);
        let key = t("/h/.ssh", false);
        let c = call(Effect::Execute, &key, Some("sudo id"));
        assert_eq!(run(&p, &on, &c), "refused");
    }

    #[test]
    fn a_wildcard_allow_does_not_cover_a_chained_command() {
        let x = T::new();
        let env = x.env(true);
        let e = t("/w/ro", false);
        let c = |cmd| call(Effect::Execute, &e, Some(cmd));
        let mut p = policy(Mode::Allowlist);
        p.allow = rules(&["exec.run:git *"]);
        for chained in [
            "git status; rm -rf ~",
            "git status && id",
            "git log | sh",
            "git $(id)",
            "git status\nid",
        ] {
            let d = decide(&p, &env, &c(chained));
            assert!(
                matches!(&d, Decision::Forbidden(m) if m.contains("chains")),
                "{chained}: {d:?}"
            );
        }
        // A rule that names the whole line covers it.
        p.allow
            .push(crate::rules::rule_for("exec", "run", "git log | head", false).unwrap());
        assert_eq!(run(&p, &env, &c("git log | head")), "allow");
        assert_eq!(run(&p, &env, &c("git log | sh")), "refused");
        // A literal `*` in the line is not a wildcard.
        p.allow = vec![crate::rules::rule_for("exec", "run", "rm *", false).unwrap()];
        assert_eq!(run(&p, &env, &c("rm *")), "allow");
        assert_eq!(run(&p, &env, &c("rm -rf /")), "refused");
    }

    #[test]
    fn what_counts_as_a_sudo_command() {
        assert_eq!(sudo_command("sudo apt update"), Some("apt update"));
        assert_eq!(sudo_command("  /usr/bin/sudo -n true"), Some("-n true"));
        assert_eq!(sudo_command("sudo"), Some(""));
        for not in ["sudoedit x", "ls; sudo x", "env sudo x", "echo sudo"] {
            assert_eq!(sudo_command(not), None, "{not}");
        }
    }
}
