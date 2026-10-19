//! Installing, updating and removing Nerve: the installer, which a program
//! that is not the installed one shows (the file just downloaded), and the
//! update and uninstall of Settings. Each runs this program's `install`,
//! `update` or `uninstall` (the node's, with the app's parts,
//! crate::parts) with the rights the system gives, through the broker.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Exec, Launcher};
use crate::Install;
use crate::broker::{self, Launch};
use crate::runner::Runner;

/// Starts `bin` without arguments, as the menu entry does, apart from this
/// program: it opens the installed app.
pub(super) fn system_launcher() -> Launcher {
    std::sync::Arc::new(|bin: &Path| {
        std::process::Command::new(bin)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("cannot start {}: {e}", bin.display()))
    })
}

/// Whether version `a` is newer than `b` (both `x.y.z`).
pub fn newer(a: &str, b: &str) -> bool {
    let parse =
        |v: &str| -> Option<Vec<u64>> { v.trim().split('.').map(|p| p.parse().ok()).collect() };
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// What a service command said, as the steps it did and what it warned
/// about. Its advice for a terminal (`Next: …`) is the app's to give.
pub fn steps(v: &Value) -> (Vec<String>, Vec<String>) {
    let (mut did, mut warn) = (Vec::new(), Vec::new());
    for line in v["messages"].as_array().into_iter().flatten() {
        let Some(line) = line.as_str() else { continue };
        if line.starts_with("Next:") {
            continue;
        }
        if line.starts_with("Warning:") || line.starts_with("no account for commands") {
            warn.push(line.to_string());
        } else {
            did.push(line.to_string());
        }
    }
    (did, warn)
}

fn shared(lines: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        lines
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    ))
}

impl Ctl {
    /// Makes the window the installer for the app at `bin`: what will be
    /// installed, or, when Nerve is installed, what it can do with it. `how`
    /// starts the broker once the owner goes on.
    pub fn installer(self: &Rc<Self>, how: Launch, bin: &Path) {
        self.elevate.set(Some(how));
        *self.program.borrow_mut() = bin.to_path_buf();
        // The service's commands work on the installed node's folders only.
        let plain = Runner::new(self.runner().exe().clone(), None, None);
        *self.runner.borrow_mut() = plain;
        self.with_install(|i| {
            i.set_shown(true);
            i.set_program(bin.display().to_string().into());
            i.set_windows(cfg!(windows));
            i.set_account(
                std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_default()
                    .into(),
            );
            i.set_step("working".into());
        });
        // The service's state needs no rights.
        self.command(
            vec!["service".into(), "status".into()],
            None,
            |c, answer| {
                let v = answer.unwrap_or_default();
                let app = v["present"] == true;
                let installed = v["installed"] == true;
                let version = v["version"].as_str().unwrap_or_default().to_string();
                c.with_install(|i| {
                    i.set_installed_version(version.as_str().into());
                    i.set_newer(app && newer(&i.get_version(), &version));
                    i.set_node_only(installed && !app);
                    i.set_step(if app { "installed" } else { "welcome" }.into());
                });
            },
        );
    }

    /// The app at its installed place: its service's state is asked for
    /// when `service` (the node is the service's), and Settings updates and
    /// removes `bin`.
    pub fn watch_service(&self, service: bool, bin: &Path) {
        self.service.set(service);
        *self.program.borrow_mut() = bin.to_path_buf();
        self.with_install(|i| i.set_program(bin.display().to_string().into()));
    }

    /// Opens the installed app with `launcher` instead of starting it.
    pub fn set_launcher(&self, launcher: Launcher) {
        *self.launcher.borrow_mut() = launcher;
    }

    /// Runs `then` once the commands have the rights: at once when they
    /// have them or need none, else after the system's question.
    fn with_rights(self: &Rc<Self>, then: impl FnOnce(&Rc<Ctl>) + Send + 'static) {
        let how = match self.elevate.get() {
            Some(how) if !self.runner.borrow().elevated() => how,
            _ => return then(self),
        };
        let exe = self.runner().exe().clone();
        self.with_install(|i| {
            i.set_asking(true);
            i.set_step("working".into());
        });
        self.job(
            move |_| broker::launch(&exe, how),
            move |c, launched| {
                c.with_install(|i| i.set_asking(false));
                match launched {
                    Ok(b) => {
                        let r = c.runner().through(b);
                        *c.runner.borrow_mut() = r;
                        c.with_store(|s| {
                            s.set_elevate_needed(false);
                            s.set_elevate_open(false);
                        });
                        then(c);
                    }
                    Err(e) => c.failed(e),
                }
            },
        );
    }

    /// A step that did not finish: back where the owner was, with why.
    fn failed(&self, e: String) {
        self.with_install(|i| {
            let back = match i.get_action().as_str() {
                "uninstall" => "choose",
                "update" if !i.get_shown() => "choose",
                "update" => "installed",
                _ => "welcome",
            };
            i.set_error(e.into());
            i.set_error_title(SharedString::new());
            i.set_step(back.into());
        });
    }

    /// Runs a service command with the rights, then shows what it did; the
    /// installed version comes after it.
    fn run_service_command(
        self: &Rc<Self>,
        action: &str,
        args: Vec<String>,
        input: Option<String>,
    ) {
        self.with_install(|i| {
            i.set_action(action.into());
            i.set_error(SharedString::new());
            i.set_error_title(SharedString::new());
            i.set_did(ModelRc::default());
            i.set_warnings(ModelRc::default());
        });
        self.with_rights(move |c| {
            c.with_install(|i| i.set_step("working".into()));
            c.command(args, input, |c, answer| match answer {
                Ok(v) => {
                    let (did, warn) = steps(&v);
                    c.with_install(|i| {
                        i.set_password(SharedString::new());
                        i.set_did(shared(did));
                        i.set_warnings(shared(warn));
                    });
                    c.command(vec!["service".into(), "status".into()], None, |c, v| {
                        let version = v
                            .ok()
                            .and_then(|v| v["version"].as_str().map(str::to_string))
                            .unwrap_or_default();
                        c.with_install(|i| {
                            if i.get_action() != "uninstall" {
                                i.set_installed_version(version.into());
                            }
                            i.set_step("done".into());
                        });
                    });
                }
                Err(e) => c.failed(e),
            });
        });
    }

    fn install_go(self: &Rc<Self>) {
        // Windows asks for the password of the account commands run as;
        // it goes on stdin, never as an argument.
        let input = self
            .with_install(|i| i.get_password().to_string())
            .filter(|p| !p.is_empty());
        self.run_service_command("install", vec!["install".into()], input);
    }

    /// The update: the installer's from this program, Settings' from the
    /// latest release or the file chosen.
    fn update_go(self: &Rc<Self>) {
        let Some((shown, source, file)) =
            self.with_install(|i| (i.get_shown(), i.get_source(), i.get_file().to_string()))
        else {
            return;
        };
        let mut args = vec!["update".to_string()];
        // The installer updates with itself: the program its commands run.
        let from = if shown {
            Some(self.runner().exe().display().to_string())
        } else {
            (source == 1).then_some(file)
        };
        if let Some(from) = from {
            args.push("--from".into());
            args.push(from);
        }
        self.run_service_command("update", args, None);
    }

    fn uninstall_go(self: &Rc<Self>) {
        let purge = self.with_install(|i| i.get_purge()).unwrap_or(false);
        let mut args = vec!["uninstall".to_string()];
        if purge {
            args.push("--purge".into());
        }
        self.run_service_command("uninstall", args, None);
    }

    /// Opens the uninstall: keep or delete the node's data, then go.
    pub fn ask_uninstall(&self) {
        self.with_install(|i| {
            i.set_action("uninstall".into());
            i.set_purge(false);
            i.set_error(SharedString::new());
            i.set_step("choose".into());
            if !i.get_shown() {
                i.set_uninstall_open(true);
            }
        });
    }

    fn ask_update(&self) {
        self.with_install(|i| {
            i.set_action("update".into());
            i.set_source(0);
            i.set_file(SharedString::new());
            i.set_error(SharedString::new());
            i.set_error_title(SharedString::new());
            i.set_step("choose".into());
            i.set_update_open(true);
        });
    }

    fn choose_file(self: &Rc<Self>) {
        let chooser = self.chooser.borrow().clone();
        self.job(
            move |_| chooser(Choose::Program),
            |c, picked: Result<Option<PathBuf>, String>| match picked {
                // The update dialog is open: it says why, under its own
                // heading, since the update did not start.
                Err(e) => {
                    c.with_install(|i| {
                        i.set_error(e.into());
                        i.set_error_title("No file dialog".into());
                    });
                }
                Ok(None) => {}
                Ok(Some(p)) => {
                    c.with_install(|i| {
                        i.set_source(1);
                        i.set_file(p.display().to_string().into());
                        i.set_error(SharedString::new());
                        i.set_error_title(SharedString::new());
                    });
                }
            },
        );
    }

    /// Opens the installed app and closes this window: the installer's
    /// end, and the app's start again after an update.
    fn open_app(self: &Rc<Self>) {
        let bin = self.program.borrow().clone();
        let launcher = self.launcher.borrow().clone();
        // The new window is the user's one window from its start; this one
        // lets go first.
        self.instance.borrow_mut().take();
        match launcher(&bin) {
            Ok(()) => self.close_app(),
            Err(e) => {
                self.with_install(|i| i.set_error(e.into()));
            }
        }
    }

    fn close_app(&self) {
        self.with_install(|i| i.set_closed(true));
        self.end();
        if self.exec == Exec::Threads {
            let _ = slint::quit_event_loop();
        }
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let i = window.global::<Install>();
    let c = ctl.clone();
    i.on_install(move || c.install_go());
    let c = ctl.clone();
    i.on_update(move || c.update_go());
    let c = ctl.clone();
    i.on_uninstall(move || c.uninstall_go());
    let c = ctl.clone();
    i.on_ask_uninstall(move || c.ask_uninstall());
    let c = ctl.clone();
    i.on_ask_update(move || c.ask_update());
    let c = ctl.clone();
    i.on_choose_file(move || c.choose_file());
    let c = ctl.clone();
    i.on_open_app(move || c.open_app());
    let c = ctl.clone();
    i.on_close(move || c.close_app());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newer_version_and_the_steps_of_an_install() {
        assert!(newer("0.0.6", "0.0.5"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(!newer("0.0.5", "0.0.5"));
        assert!(!newer("0.0.5", ""));
        let v = serde_json::json!({"messages": [
            "made the user nerve (uid 991)",
            "Warning: alice is the account that ran sudo.",
            "no account for commands: the password of alice is wrong; `nerve-node install` asks again",
            "the service nerve-node.service runs as nerve and starts with the machine",
            "Next: `sudo nerve-node setup` names the node and pairs it with its first center.",
        ]});
        let (did, warn) = steps(&v);
        assert_eq!(did.len(), 2);
        assert_eq!(warn.len(), 2);
        assert!(warn[1].starts_with("no account"));
    }
}
