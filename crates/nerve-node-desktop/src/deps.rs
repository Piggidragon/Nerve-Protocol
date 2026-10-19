//! What the app needs of the desktop, and what it says when that is missing
//! (docs/user/desktop.md, "What the app needs"): a display, a renderer that
//! draws on it, polkit's `pkexec` with an authentication agent that asks the
//! owner, and a desktop portal whose file chooser opens files and folders.
//! GNOME and KDE Plasma bring all of it; another desktop may not. Each check
//! takes what it looks at as arguments, so the tests can leave each part out.

use std::path::{Path, PathBuf};

/// The variable that chooses Slint's backend and renderer.
pub const BACKEND_VAR: &str = "SLINT_BACKEND";
/// Slint's winit backend drawing in software, without OpenGL.
pub const SOFTWARE: &str = "winit-software";

/// Why no window can open in this session, or `None` when one can:
/// neither Wayland nor X11 is there. `var` reads the session's variables,
/// `exists` whether a path is there.
pub fn no_display(
    var: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&Path) -> bool,
) -> Option<String> {
    if cfg!(windows) {
        return None;
    }
    let set = |k: &str| var(k).filter(|v| !v.is_empty());
    // Wayland's socket: an absolute path, or a name in the runtime folder.
    let wayland = set("WAYLAND_SOCKET").is_some()
        || set("WAYLAND_DISPLAY").is_some_and(|name| {
            let p = Path::new(&name);
            if p.is_absolute() {
                exists(p)
            } else {
                set("XDG_RUNTIME_DIR").is_some_and(|dir| exists(&Path::new(&dir).join(p)))
            }
        });
    // An X11 display may be on another host, so its name alone counts.
    if wayland || set("DISPLAY").is_some() {
        return None;
    }
    Some(
        "no display: the app's window needs a desktop session, Wayland (WAYLAND_DISPLAY) or X11 (DISPLAY), and neither is there. Open Nerve from the desktop's application menu; in a terminal without a desktop, run its commands instead (nerve-node-desktop --help).".into(),
    )
}

/// [`no_display`] for this process.
pub fn no_display_here() -> Option<String> {
    no_display(|k| std::env::var(k).ok(), Path::exists)
}

/// What to do when the window did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Start again, drawing in software.
    Software,
    /// Say this and end.
    Fail(String),
}

/// After the window failed with `error`: the GPU renderer (OpenGL, EGL)
/// may be what is missing, so the app starts once more in software, unless
/// the renderer was chosen already (`chosen`, [`BACKEND_VAR`]).
pub fn after_window_error(error: &str, chosen: Option<&str>) -> Next {
    match chosen.filter(|c| !c.is_empty()) {
        None => Next::Software,
        Some(c) => Next::Fail(format!(
            "the window did not open ({error}), drawing with {BACKEND_VAR}={c}. If neither OpenGL nor software drawing works here, the display is not reachable or its graphics libraries are missing: install Mesa's libEGL and libGL (libegl1 and libgl1 on Debian and Ubuntu, mesa-libEGL on Fedora)."
        )),
    }
}

/// Runs this program again with the same arguments, drawing in software;
/// its exit code.
pub fn rerun_in_software() -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(BACKEND_VAR, SOFTWARE)
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(1)
}

/// Shows `text` as a desktop notification where one can be shown; a
/// program started from the menu has no terminal to print to.
pub fn notify(title: &str, text: &str) {
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("notify-send")
        .args(["--app-name=Nerve", "--icon=nerve-node-desktop", title, text])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    #[cfg(not(target_os = "linux"))]
    let _ = (title, text);
}

/// Whether pkexec can ask for root here: `pkexec` is the program found, if
/// any; `agent` whether an authentication agent of the desktop runs, which
/// shows pkexec's question. Without one pkexec fails at once.
pub fn polkit(pkexec: Option<&Path>, agent: bool) -> Result<(), String> {
    if pkexec.is_none() {
        return Err("There is no pkexec on this machine, so the app cannot ask for administrator rights. Install polkit (the package polkit, or policykit-1 on older Debian and Ubuntu), then try again.".into());
    }
    if !agent {
        return Err("No polkit authentication agent is running, so nobody can be asked for the administrator password. Install and start one for your desktop, for example polkit-gnome or polkit-kde-agent-1 (GNOME and KDE Plasma bring theirs), then try again.".into());
    }
    Ok(())
}

/// `program` in the folders of `path` (`PATH`), or in `/usr/bin`.
pub fn find_program(program: &str, path: Option<&str>) -> Option<PathBuf> {
    path.unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
        .chain(["/usr/bin"])
        .map(|d| Path::new(d).join(program))
        .find(|p| p.is_file())
}

/// Whether one of `programs` (the names this user's processes were started
/// as) is a polkit authentication agent: one of polkit's own (polkit-gnome,
/// polkit-kde-agent, lxpolkit, polkit-mate, hyprpolkitagent, lxqt-policykit
/// …), or a desktop shell that has one built in.
pub fn agent_among<S: AsRef<str>>(programs: impl IntoIterator<Item = S>) -> bool {
    const SHELLS: [&str; 4] = ["gnome-shell", "gnome-flashback", "cinnamon", "phosh"];
    programs.into_iter().any(|p| {
        let name = Path::new(p.as_ref())
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        // polkit's daemon and pkexec's helper are no agent.
        let polkit = (name.contains("polkit") || name.contains("policykit"))
            && !matches!(
                name.as_str(),
                "polkitd" | "pkexec" | "polkit-agent-helper-1"
            );
        polkit || SHELLS.contains(&name.as_str())
    })
}

/// The names this user's processes were started as (Linux, from /proc).
#[cfg(target_os = "linux")]
fn own_programs() -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    procs
        .flatten()
        .filter(|e| e.metadata().is_ok_and(|m| m.uid() == me))
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .filter_map(|c| {
            let first = c.split(|b| *b == 0).next()?;
            (!first.is_empty()).then(|| String::from_utf8_lossy(first).into_owned())
        })
        .collect()
}

/// [`polkit`] on this machine, before the app asks.
#[cfg(target_os = "linux")]
pub fn polkit_here() -> Result<(), String> {
    let path = std::env::var("PATH").ok();
    let pkexec = find_program("pkexec", path.as_deref());
    polkit(pkexec.as_deref(), agent_among(own_programs()))
}

/// The interface of the portal that opens the file dialogs.
const FILE_CHOOSER: &str = "org.freedesktop.portal.FileChooser";

/// Whether the desktop portal's file chooser answers on the session bus,
/// from what `busctl --user introspect org.freedesktop.portal.Desktop
/// /org/freedesktop/portal/desktop` did: `None` when busctl is not there
/// to ask (the dialog then tries), else whether it succeeded and what it
/// printed.
pub fn portal(asked: Option<(bool, &str)>) -> Result<(), String> {
    match asked {
        None => Ok(()),
        Some((true, out)) if out.contains(FILE_CHOOSER) => Ok(()),
        Some(_) => Err("No file dialog: the app opens files and folders through the desktop portal (org.freedesktop.portal.Desktop with a FileChooser), and none answers here. Install xdg-desktop-portal and the backend for your desktop: xdg-desktop-portal-gnome, -kde, -gtk or -wlr, then log out and in.".into()),
    }
}

/// [`portal`] on this session.
#[cfg(target_os = "linux")]
pub fn portal_here() -> Result<(), String> {
    let out = std::process::Command::new("busctl")
        .args([
            "--user",
            "--no-pager",
            "--timeout=5",
            "introspect",
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok();
    let text = out
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    portal(
        out.as_ref()
            .zip(text.as_deref())
            .map(|(o, t)| (o.status.success(), t)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn no_display_is_said_and_either_display_will_do() {
        let vars = |set: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                set.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let none = |_: &Path| false;
        let e = no_display(vars(&[]), none).unwrap();
        assert!(e.contains("Wayland") && e.contains("X11"), "{e}");
        // A Wayland name without its socket is no display.
        assert!(
            no_display(
                vars(&[
                    ("WAYLAND_DISPLAY", "wayland-0"),
                    ("XDG_RUNTIME_DIR", "/run/user/1000")
                ]),
                none
            )
            .is_some()
        );
        assert!(no_display(vars(&[("DISPLAY", "")]), none).is_some());
        let socket = |p: &Path| p == Path::new("/run/user/1000/wayland-0");
        assert_eq!(
            no_display(
                vars(&[
                    ("WAYLAND_DISPLAY", "wayland-0"),
                    ("XDG_RUNTIME_DIR", "/run/user/1000")
                ]),
                socket
            ),
            None
        );
        assert_eq!(no_display(vars(&[("DISPLAY", ":0")]), none), None);
    }

    #[test]
    fn a_window_that_fails_tries_software_once() {
        assert_eq!(after_window_error("no EGL", None), Next::Software);
        assert_eq!(after_window_error("no EGL", Some("")), Next::Software);
        let Next::Fail(e) = after_window_error("no EGL", Some(SOFTWARE)) else {
            panic!("software failed too");
        };
        assert!(e.contains("no EGL") && e.contains("libEGL"), "{e}");
        // A renderer the owner chose is not changed behind them.
        assert!(matches!(
            after_window_error("x", Some("winit-femtovg")),
            Next::Fail(_)
        ));
    }

    #[test]
    fn pkexec_needs_the_program_and_an_agent() {
        let pk = Path::new("/usr/bin/pkexec");
        assert_eq!(polkit(Some(pk), true), Ok(()));
        assert!(polkit(None, true).unwrap_err().contains("Install polkit"));
        let e = polkit(Some(pk), false).unwrap_err();
        assert!(e.contains("No polkit authentication agent"), "{e}");
        assert!(
            e.contains("polkit-gnome") && e.contains("polkit-kde-agent"),
            "{e}"
        );

        assert!(agent_among(["/usr/bin/gnome-shell"]));
        assert!(agent_among([
            "/usr/lib/x86_64-linux-gnu/libexec/polkit-kde-authentication-agent-1"
        ]));
        assert!(agent_among([
            "/usr/libexec/polkit-gnome-authentication-agent-1"
        ]));
        assert!(agent_among(["lxqt-policykit-agent"]));
        assert!(!agent_among([
            "/usr/bin/bash",
            "/usr/lib/polkit-1/polkitd",
            "pkexec"
        ]));
        assert!(!agent_among(Vec::<String>::new()));

        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("pkexec-test"), "").unwrap();
        let path = format!("/nowhere:{}", d.path().display());
        assert_eq!(
            find_program("pkexec-test", Some(&path)),
            Some(d.path().join("pkexec-test"))
        );
        assert_eq!(find_program("pkexec-test", Some("/nowhere")), None);
    }

    #[test]
    fn the_file_dialogs_need_the_portals_file_chooser() {
        let found = "NAME TYPE SIGNATURE\norg.freedesktop.portal.FileChooser interface - - -\n.OpenFile method ssa{sv} o -\n";
        assert_eq!(portal(Some((true, found))), Ok(()));
        // Not there to ask: the dialog tries itself.
        assert_eq!(portal(None), Ok(()));
        for asked in [
            (false, ""),
            (true, "org.freedesktop.portal.Settings interface - - -\n"),
        ] {
            let e = portal(Some(asked)).unwrap_err();
            assert!(e.contains("xdg-desktop-portal-gnome"), "{e}");
        }
    }
}
