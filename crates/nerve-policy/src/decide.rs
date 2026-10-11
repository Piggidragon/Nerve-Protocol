//! The decision engine: whether one call of one center may run (architecture
//! §5.1, spec §7).
//!
//! There are two outcomes, allowed and refused; nothing waits for an answer.
//! The order only ever narrows: an `off` capability is disabled; a denied path
//! or command is forbidden; then the mode and the rules allow or not. A call
//! no mode and no rule allows is refused at once, and so is one that touches a
//! protected path or is tainted, whatever allowed it.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobMatcher};
use nerve_proto::Effect;

use crate::config::{Access, CapSetting, CenterPolicy, Folder, Mode};
use crate::paths::within;
use crate::protected::{Protected, expand};

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
    pub tainted: bool,
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
}

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

/// Decides `call` under `policy`.
pub fn decide(policy: &CenterPolicy, env: &Env, call: &Call) -> Decision {
    let setting = policy.cap_setting(call.cap, Some(call.action));
    if matches!(setting, Some(CapSetting::Off | CapSetting::Hidden)) {
        return Decision::Disabled(format!("{}.{} is off", call.cap, call.action));
    }

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

    // What the mode, or an explicit `on`, allows.
    let mut allowed = match call.effect {
        // No mode allows these; only the owner's `on` does.
        Effect::Sense | Effect::Actuate => {
            if setting != Some(CapSetting::On) {
                reasons.push(format!(
                    "{} is allowed only where {}.{} is set to on",
                    call.effect.as_str(),
                    call.cap,
                    call.action
                ));
            }
            setting == Some(CapSetting::On)
        }
        Effect::Read | Effect::Write => match mode {
            Mode::User => true,
            Mode::Folder => call.targets.iter().all(|t| {
                inside_folder(&policy.folders, &t.path)
                    .is_some_and(|f| !t.write || f.access == Access::Rw)
            }),
        },
        Effect::Execute => match mode {
            Mode::User => true,
            Mode::Folder => {
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
        reasons.push(match call.effect {
            Effect::Execute => "the working directory is not in an execute folder".into(),
            Effect::Write => "outside the read-write folders".into(),
            _ => "outside the folders".into(),
        });
    }
    if call.effect == Effect::Execute
        && !call.tainted
        && call.command.is_some_and(|cmd| matches(&rules.permit, cmd))
    {
        allowed = true;
        reasons.clear();
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
    if call.tainted && matches!(call.effect, Effect::Write | Effect::Execute) && allowed {
        allowed = false;
        reasons.push("the call is tainted".into());
    }

    if allowed {
        Decision::Allow
    } else {
        Decision::Forbidden(reasons.join("; "))
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
            user_until: (mode == Mode::User).then_some(NOW + 1000),
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
                deny: vec!["rm -rf /*".into(), "git push*".into()],
                permit: vec!["ls*".into()],
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
            Decision::Forbidden(_) => "refused",
            Decision::Disabled(_) => "disabled",
        }
    }

    #[test]
    fn mode_matrix() {
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
            // Command rules.
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
                &exec_ro,
                Some("ls -la"),
                "allow",
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
        // Expired user mode is folder mode.
        let mut p = policy(Mode::User);
        p.user_until = Some(NOW);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &outside, None))),
            "refused"
        );
    }

    #[test]
    fn a_call_no_rule_allows_is_refused_at_once() {
        let x = T::new();
        let env = x.env(true);
        // The default policy has no folder and no rule: nothing is allowed.
        let p = CenterPolicy::default();
        assert_eq!(p.mode, Mode::Folder);
        let r = t("/w/rw/a", false);
        let w = t("/w/rw/a", true);
        let e = t("/w/rw", false);
        for c in [
            call(Effect::Read, &r, None),
            call(Effect::Write, &w, None),
            call(Effect::Execute, &e, Some("make")),
            call(Effect::Sense, &[], None),
            call(Effect::Actuate, &[], None),
        ] {
            let d = decide(&p, &env, &c);
            assert!(
                matches!(&d, Decision::Forbidden(why) if !why.is_empty()),
                "{:?}: {d:?}",
                c.effect
            );
        }
        // One explicit allow changes only what it names.
        let mut p = CenterPolicy::default();
        p.commands.permit = vec!["make".into()];
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Execute, &e, Some("make")))),
            "allow"
        );
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Execute, &e, Some("cargo")))),
            "refused"
        );
    }

    #[test]
    fn caps_settings() {
        let x = T::new();
        let env = x.env(true);
        let inside = t("/w/ro/a", false);
        let mut p = policy(Mode::Folder);
        p.caps.insert("fs".into(), CapSetting::Off);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &inside, None))),
            "disabled"
        );
        // An action's own setting wins over its capability's.
        p.caps.insert("fs.read".into(), CapSetting::On);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &inside, None))),
            "allow"
        );
        // `on` does not widen what the mode refuses.
        let outside = t("/elsewhere/a", false);
        assert_eq!(
            short(&decide(&p, &env, &call(Effect::Read, &outside, None))),
            "refused"
        );
    }

    #[test]
    fn sense_and_actuate_need_an_explicit_on() {
        let x = T::new();
        let env = x.env(true);
        for effect in [Effect::Sense, Effect::Actuate] {
            for mode in [Mode::Folder, Mode::User] {
                let mut p = policy(mode);
                let mut c = call(effect, &[], None);
                c.cap = "camera";
                c.action = "snap";
                assert_eq!(short(&decide(&p, &env, &c)), "refused");
                p.caps.insert("camera".into(), CapSetting::On);
                assert_eq!(short(&decide(&p, &env, &c)), "allow");
                // Taint does not narrow reads or senses, only writes and commands.
                c.tainted = true;
                assert_eq!(short(&decide(&p, &env, &c)), "allow");
            }
        }
    }

    #[test]
    fn taint_narrows() {
        let x = T::new();
        let env = x.env(true);
        let p = policy(Mode::User);
        let w = t("/w/rw/a", true);
        let mut c = call(Effect::Write, &w, None);
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c)), "refused");
        let e = t("/w/rw", false);
        let mut c = call(Effect::Execute, &e, Some("make"));
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c)), "refused");
        // A permitted command is no exception.
        let mut c = call(Effect::Execute, &e, Some("ls"));
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c)), "refused");
        // Reads are not narrowed by taint.
        let r = t("/x/a", false);
        let mut c = call(Effect::Read, &r, None);
        c.tainted = true;
        assert_eq!(short(&decide(&p, &env, &c)), "allow");
    }
}
