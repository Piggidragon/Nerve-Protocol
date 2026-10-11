//! The node's own folders (config, keys, state) are refused before any rule
//! or mode, and nothing the owner or a center writes into a policy lifts that
//! (issue #20).

#![cfg(unix)]

use std::path::{Path, PathBuf};

use nerve_policy::config::{Access, Folder};
use nerve_policy::protected::Protected;
use nerve_policy::{Call, CenterPolicy, Decision, Env, Mode, Target, decide};
use nerve_proto::Effect;

const NOW: u64 = 1_000_000;
const CONFIG: &str = "/h/.config/nerve";
const STATE: &str = "/h/.local/state/nerve";

/// A policy that would allow everything: folders naming the node's folders,
/// the protected list released, allow rules for every path and command, and
/// a sudo allow entry for any command.
fn wide_open(mode: Mode) -> CenterPolicy {
    let mut p = CenterPolicy {
        mode,
        user_until: (mode == Mode::User).then_some(NOW + 1000),
        ..Default::default()
    };
    for path in ["/h", CONFIG, STATE] {
        p.folders.push(Folder {
            path: path.into(),
            access: Access::Rw,
            execute: true,
        });
    }
    p.protected.allow = vec!["~/.config/nerve".into(), "~/.local/state/nerve".into()];
    p.allow = vec!["fs:/*".into(), "exec.run:*".into()];
    p.sudo_allow = vec!["sudo *".into()];
    p
}

fn protected(p: &CenterPolicy) -> Protected {
    Protected::new(
        Path::new("/h"),
        &[PathBuf::from(CONFIG), PathBuf::from(STATE)],
        &p.protected,
    )
}

fn fs(effect: Effect, targets: &[Target]) -> Call<'_> {
    Call {
        cap: "fs",
        action: if effect == Effect::Write {
            "write"
        } else {
            "read"
        },
        effect,
        targets,
        command: None,
        cwd: None,
        now_ms: NOW,
    }
}

fn run<'a>(command: &'a str, cwd: &'a [Target]) -> Call<'a> {
    Call {
        cap: "exec",
        action: "run",
        effect: Effect::Execute,
        targets: cwd,
        command: Some(command),
        cwd: Some(cwd[0].path.as_path()),
        now_ms: NOW,
    }
}

fn at(p: &str, write: bool) -> Vec<Target> {
    vec![Target {
        path: p.into(),
        write,
    }]
}

fn own_refusal(d: &Decision) -> bool {
    matches!(d, Decision::Forbidden(why) if why.contains("belongs to the node"))
}

#[test]
fn nothing_reaches_the_nodes_own_folders() {
    for mode in [Mode::Allowlist, Mode::Folder, Mode::User] {
        let p = wide_open(mode);
        let prot = protected(&p);
        let env = Env {
            home: Path::new("/h"),
            protected: &prot,
            confined: true,
            sudo: true,
        };
        let check = |c: &Call| {
            let d = decide(&p, &env, c);
            assert!(own_refusal(&d), "{mode:?} {c:?}: {d:?}");
        };
        check(&fs(Effect::Read, &at("/h/.config/nerve/node.toml", false)));
        check(&fs(Effect::Write, &at("/h/.config/nerve/node.toml", true)));
        check(&fs(Effect::Write, &at("/h/.config/nerve", true)));
        check(&fs(
            Effect::Read,
            &at("/h/.local/state/nerve/config.key", false),
        ));
        check(&fs(Effect::Write, &at("/h/.CONFIG/Nerve/node.toml", true)));
        let home = at("/h", false);
        let inside = at("/h/.config/nerve", false);
        check(&run("ls", &inside));
        for named in [
            "cat ~/.config/nerve/node.toml",
            "echo x >> $HOME/.config/nerve/node.toml",
            "cp evil ${HOME}/.local/state/nerve/config.key",
            "cat /h/.config/nerve",
            "sudo tee /h/.config/nerve/node.toml",
        ] {
            check(&run(named, &home));
        }
        // A name that only starts like one is not one.
        let d = decide(&p, &env, &run("cat ~/.config/nerve-notes/a", &home));
        assert!(!own_refusal(&d), "{mode:?}: {d:?}");
    }
    // The same policy still allows what lies beside them.
    let p = wide_open(Mode::User);
    let prot = protected(&p);
    let env = Env {
        home: Path::new("/h"),
        protected: &prot,
        confined: true,
        sudo: false,
    };
    let notes = at("/h/notes/a", true);
    assert_eq!(
        decide(&p, &env, &fs(Effect::Write, &notes)),
        Decision::Allow
    );
}
