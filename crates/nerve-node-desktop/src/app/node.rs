//! The node itself: starting and stopping one the app runs, the rights the
//! app asks for when the node is installed as a service, and the first-run
//! steps.
//!
//! A node the app starts (`nerve-node run`, on a node not installed as a
//! service) ends with the app, as a desktop user expects of what a window
//! started; the overview says so, and the service keeps one running.

use std::io::BufRead;
use std::process::Child;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slint::{ComponentHandle, SharedString};

use super::Ctl;
use crate::broker;
use crate::{Store, Tone};

/// A node the app started: its process, and the last line it said, which
/// is why it ended when it did.
pub(super) struct NodeProcess {
    child: Child,
    said: Arc<Mutex<String>>,
}

impl NodeProcess {
    /// Asks the node to end, as Ctrl+C would, so it says goodbye to its
    /// centers; ends it when it does not within a few seconds.
    fn end(mut self) {
        #[cfg(unix)]
        {
            // SAFETY: a signal to the process this app started and holds.
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
            for _ in 0..50 {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        // Windows has no signal for a process without a console.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Ctl {
    fn node_start(self: &Rc<Self>) {
        if self.node.borrow().is_some() {
            return;
        }
        let mut child = match self.runner().start_node() {
            Ok(c) => c,
            Err(e) => {
                self.toast(e, Tone::Danger);
                return;
            }
        };
        let said = Arc::new(Mutex::new(String::new()));
        if let Some(err) = child.stderr.take() {
            let said = said.clone();
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                    if !line.trim().is_empty() {
                        *said.lock().unwrap_or_else(|p| p.into_inner()) = line;
                    }
                }
            });
        }
        *self.node.borrow_mut() = Some(NodeProcess { child, said });
        self.with_store(|s| {
            s.set_started_here(true);
            s.set_busy("run".into());
        });
        // It answers once its control socket is up.
        let c = Rc::downgrade(self);
        slint::Timer::single_shot(Duration::from_millis(1200), move || {
            if let Some(c) = c.upgrade() {
                c.with_store(|s| s.set_busy(SharedString::new()));
                c.check_node();
                c.refresh_status();
            }
        });
    }

    /// Whether the node the app started still runs; one that ended says why.
    pub(super) fn check_node(&self) {
        let ended = {
            let mut n = self.node.borrow_mut();
            match n.as_mut().map(|p| p.child.try_wait()) {
                Some(Ok(Some(status))) => {
                    let said = n
                        .take()
                        .map(|p| p.said.lock().map(|s| s.clone()).unwrap_or_default());
                    Some((status, said.unwrap_or_default()))
                }
                _ => None,
            }
        };
        if let Some((status, said)) = ended {
            self.with_store(|s| s.set_started_here(false));
            if !status.success() {
                let why = said
                    .strip_prefix("nerve-node: ")
                    .unwrap_or(&said)
                    .to_string();
                self.toast(
                    if why.is_empty() {
                        "The node ended.".to_string()
                    } else {
                        format!("The node ended: {why}")
                    },
                    Tone::Danger,
                );
            }
        }
    }

    fn node_stop(self: &Rc<Self>) {
        let Some(p) = self.node.borrow_mut().take() else {
            return;
        };
        self.with_store(|s| s.set_busy("run".into()));
        self.job(
            move |_| p.end(),
            |c, ()| {
                c.with_store(|s| {
                    s.set_busy(SharedString::new());
                    s.set_started_here(false);
                });
                c.toast("The node stopped.", Tone::Ok);
                c.refresh_status();
            },
        );
    }

    /// The app ends: so do the node it started and what follows the log.
    pub fn end(&self) {
        self.stop_follow();
        if let Some(p) = self.node.borrow_mut().take() {
            p.end();
        }
    }

    /// Starts the broker with the rights the owner gives, after the app said
    /// why it needs them.
    fn elevate_allow(self: &Rc<Self>) {
        let Some(how) = self.elevate.get() else {
            return;
        };
        let exe = self.runner().exe().clone();
        self.with_store(|s| {
            s.set_elevate_busy(true);
            s.set_elevate_error(SharedString::new());
        });
        self.job(
            move |_| broker::launch(&exe, how),
            |c, launched| {
                c.with_store(|s| s.set_elevate_busy(false));
                match launched {
                    Ok(b) => {
                        let r = c.runner().through(b);
                        *c.runner.borrow_mut() = r;
                        c.with_store(|s| {
                            s.set_elevate_needed(false);
                            s.set_elevate_open(false);
                        });
                        c.refresh_status();
                        c.take_link();
                    }
                    Err(e) => {
                        c.with_store(|s| s.set_elevate_error(e.into()));
                    }
                }
            },
        );
    }

    /// The broker ended (the owner's session, a crash): the app asks again.
    pub(super) fn rights_gone(&self) {
        if self.elevate.get().is_none() {
            return;
        }
        let plain = self.runner().direct();
        *self.runner.borrow_mut() = plain;
        self.with_store(|s| s.set_elevate_needed(true));
    }

    pub(super) fn setup_start(self: &Rc<Self>) {
        let host = nerve_node::descriptor::node_name(&nerve_policy::NodeConfig::default());
        self.with_store(|s| {
            s.set_setup_step(0);
            s.set_setup_name(host.as_str().into());
            s.set_setup_storage(0);
            s.set_setup_mode("allowlist".into());
            s.set_setup_error(SharedString::new());
            s.set_setup_busy(false);
            s.set_pair_step(0);
            s.set_pair_link(SharedString::new());
            s.set_pair_name(SharedString::new());
            s.set_pair_error(SharedString::new());
            s.set_setup_open(true);
        });
        // What is set already.
        self.command(
            vec!["config".into(), "get".into(), "node.name".into()],
            None,
            |c, v| {
                if let Some(n) = v.ok().and_then(|v| v["value"].as_str().map(str::to_string)) {
                    c.with_store(|s| s.set_setup_name(n.into()));
                }
            },
        );
        self.command(
            vec![
                "config".into(),
                "get".into(),
                "machine.secret_storage".into(),
            ],
            None,
            |c, v| {
                if v.is_ok_and(|v| v["value"] == "keyring") {
                    c.with_store(|s| s.set_setup_storage(1));
                }
            },
        );
    }

    fn setup_go(&self, step: i32) {
        self.with_store(|s| {
            s.set_setup_busy(false);
            s.set_setup_error(SharedString::new());
            s.set_setup_step(step);
        });
    }

    /// Runs a step's command, then goes to `next`.
    fn setup_run(self: &Rc<Self>, args: Vec<String>, next: i32) {
        self.with_store(|s| s.set_setup_busy(true));
        self.command(args, None, move |c, answer| match answer {
            Ok(_) => c.setup_go(next),
            Err(e) => {
                c.with_store(|s| {
                    s.set_setup_busy(false);
                    s.set_setup_error(e.into());
                });
            }
        });
    }

    fn setup_next(self: &Rc<Self>) {
        let Some((step, name, storage, mode, center, pair_step, link, pair_name)) = self
            .with_store(|s| {
                (
                    s.get_setup_step(),
                    s.get_setup_name().to_string(),
                    s.get_setup_storage(),
                    s.get_setup_mode().to_string(),
                    s.get_setup_center().to_string(),
                    s.get_pair_step(),
                    s.get_pair_link().to_string(),
                    s.get_pair_name().to_string(),
                )
            })
        else {
            return;
        };
        match step {
            0 => {
                let host = nerve_node::descriptor::node_name(&nerve_policy::NodeConfig::default());
                let name = name.trim();
                if name.is_empty() || name == host {
                    self.setup_go(1);
                } else {
                    let args = vec![
                        "config".into(),
                        "set".into(),
                        "node.name".into(),
                        name.into(),
                    ];
                    self.setup_run(args, 1);
                }
            }
            1 => {
                let to = if storage == 1 { "keyring" } else { "file" };
                let args = vec![
                    "config".into(),
                    "set".into(),
                    "machine.secret_storage".into(),
                    to.into(),
                ];
                self.setup_run(args, 2);
            }
            2 => self.pair(&link, &pair_name, pair_step == 1),
            3 => {
                let args = vec!["mode".into(), "set".into(), mode, "--center".into(), center];
                self.setup_run(args, 4);
            }
            _ => {
                let stopped = self
                    .with_store(|s| !s.get_installed() && s.get_status().state == "stopped")
                    .unwrap_or(false);
                self.with_store(|s| s.set_setup_open(false));
                if stopped {
                    self.node_start();
                }
            }
        }
    }

    /// The first-run steps paired `name`: its mode is next.
    pub(super) fn setup_paired(&self, name: &str) {
        self.with_store(|s| s.set_setup_center(name.into()));
        self.setup_go(3);
    }

    fn setup_skip(&self) {
        let step = self.with_store(|s| s.get_setup_step()).unwrap_or(0);
        // Without a center there is no mode to choose.
        self.setup_go(if step >= 2 { 4 } else { step + 1 });
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let store = window.global::<Store>();
    let c = ctl.clone();
    store.on_node_start(move || c.node_start());
    let c = ctl.clone();
    store.on_node_stop(move || c.node_stop());
    let c = ctl.clone();
    store.on_elevate_allow(move || c.elevate_allow());
    let c = ctl.clone();
    store.on_setup_start(move || c.setup_start());
    let c = ctl.clone();
    store.on_setup_next(move || c.setup_next());
    let c = ctl.clone();
    store.on_setup_skip(move || c.setup_skip());
}
