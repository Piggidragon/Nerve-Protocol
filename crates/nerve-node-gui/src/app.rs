//! The app's actions: each one runs a `nerve-node` command ([`Runner`]) off
//! the window's thread and shows its answer ([`crate::view`]). A change is
//! shown once the node made it, never before.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::runner::Runner;
use crate::{AppWindow, Load, Page, PairPreview, Store, Tone, Type, view};

/// Where the commands run: on threads of their own, answering on the
/// window's event loop; or at once, for tests and the screenshots, which
/// have no event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exec {
    Threads,
    Inline,
}

/// The change that waits for the owner's yes in the confirm dialog.
enum Pending {
    Unpair(String),
}

pub struct Ctl {
    runner: Runner,
    exec: Exec,
    window: slint::Weak<AppWindow>,
    /// The audit entries shown, newest first: what a button's index names.
    audit: RefCell<Vec<Value>>,
    /// The names of the paired centers, as the last status said.
    centers: RefCell<Vec<String>>,
    pending: RefCell<Option<Pending>>,
    asking_status: Cell<bool>,
    timer: slint::Timer,
}

thread_local! {
    // The controller of the window on this thread, for answers that come
    // back from a command's thread.
    static CURRENT: RefCell<Option<Rc<Ctl>>> = const { RefCell::new(None) };
}

/// The system's monospace font. Slint takes one family by its name, and
/// does not resolve a generic one; fontconfig knows which one Linux uses.
fn mono_font() -> String {
    if cfg!(windows) {
        return "Consolas".into();
    }
    std::process::Command::new("fc-match")
        .args(["-f", "%{family[0]}", "monospace"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| "DejaVu Sans Mono".into())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

impl Ctl {
    /// Wires `window`'s actions to the CLI that `runner` starts.
    pub fn attach(window: &AppWindow, runner: Runner, exec: Exec) -> Rc<Ctl> {
        let ctl = Rc::new(Ctl {
            runner,
            exec,
            window: window.as_weak(),
            audit: RefCell::new(Vec::new()),
            centers: RefCell::new(Vec::new()),
            pending: RefCell::new(None),
            asking_status: Cell::new(false),
            timer: slint::Timer::default(),
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(ctl.clone()));
        window.global::<Type>().set_mono(mono_font().into());
        let store = window.global::<Store>();
        store.set_version(env!("CARGO_PKG_VERSION").into());

        let c = ctl.clone();
        store.on_show(move |page| c.show(page));
        let c = ctl.clone();
        store.on_refresh(move || c.refresh_status());
        let c = ctl.clone();
        store.on_refresh_audit(move || c.refresh_audit());
        let c = ctl.clone();
        store.on_audit_filter(move |refused| {
            c.with_store(|s| s.set_audit_refused_only(refused));
            c.refresh_audit();
        });
        let c = ctl.clone();
        store.on_audit_rule(move |i, list, wildcard| c.audit_rule(i as usize, &list, wildcard));
        let c = ctl.clone();
        store.on_pair_start(move || c.pair_start());
        let c = ctl.clone();
        store.on_pair_check(move |link, name| c.pair(&link, &name, false));
        let c = ctl.clone();
        store.on_pair_confirm(move || {
            let (link, name) = c
                .with_store(|s| (s.get_pair_link(), s.get_pair_name()))
                .unwrap_or_default();
            c.pair(&link, &name, true)
        });
        let c = ctl.clone();
        store.on_center_pause(move |name, pause| c.center_pause(&name, pause));
        let c = ctl.clone();
        store.on_center_grant(move |name, on| c.center_grant(&name, on));
        let c = ctl.clone();
        store.on_center_unpair(move |name| c.ask_unpair(&name));
        let c = ctl.clone();
        store.on_confirm_accepted(move || c.confirmed());
        let c = ctl.clone();
        store.on_panic(move || c.lock(true));
        let c = ctl.clone();
        store.on_unlock(move || c.lock(false));
        let c = ctl.clone();
        store.on_set_appearance(move |i| c.set_appearance(i));
        ctl
    }

    /// Asks for the status now and then every few seconds, so the window
    /// follows the node while it is open.
    pub fn watch(self: &Rc<Self>) {
        self.refresh_status();
        let c = Rc::downgrade(self);
        self.timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(3),
            move || {
                if let Some(c) = c.upgrade() {
                    c.refresh_status();
                }
            },
        );
    }

    fn with_store<R>(&self, f: impl FnOnce(&Store<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let store = w.global::<Store>();
        Some(f(&store))
    }

    /// Runs `work` with the runner, then `done` with its result on the
    /// window's thread.
    fn job<R: Send + 'static>(
        self: &Rc<Self>,
        work: impl FnOnce(&Runner) -> R + Send + 'static,
        done: impl FnOnce(&Rc<Ctl>, R) + Send + 'static,
    ) {
        match self.exec {
            Exec::Inline => {
                let r = work(&self.runner);
                done(self, r);
            }
            Exec::Threads => {
                let runner = self.runner.clone();
                std::thread::spawn(move || {
                    let r = work(&runner);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(c) = CURRENT.with(|c| c.borrow().clone()) {
                            done(&c, r);
                        }
                    });
                });
            }
        }
    }

    fn toast(&self, text: impl Into<SharedString>, tone: Tone) {
        let text = text.into();
        self.with_store(|s| {
            // Hidden first, so the timer that hides it starts again.
            s.set_toast_shown(false);
            s.set_toast(text);
            s.set_toast_tone(tone);
            s.set_toast_shown(true);
        });
    }

    fn show(self: &Rc<Self>, page: Page) {
        self.with_store(|s| s.set_page(page));
        match page {
            Page::Audit => self.refresh_audit(),
            _ => self.refresh_status(),
        }
    }

    pub fn refresh_status(self: &Rc<Self>) {
        // One question at a time: a slow node is not asked again meanwhile.
        if self.asking_status.replace(true) {
            return;
        }
        self.job(
            |r| r.run(&["status"]),
            |c, answer| {
                c.asking_status.set(false);
                c.show_status(answer);
            },
        );
    }

    fn show_status(&self, answer: Result<Value, String>) {
        match answer {
            Ok(v) => {
                let (status, centers) = view::status(&v, now_ms());
                *self.centers.borrow_mut() = centers.iter().map(|c| c.name.to_string()).collect();
                self.with_store(|s| {
                    s.set_status(status);
                    s.set_centers(ModelRc::new(VecModel::from(centers)));
                    s.set_status_load(Load::Ready);
                    s.set_status_error(SharedString::new());
                });
            }
            Err(e) => {
                self.with_store(|s| {
                    s.set_status_load(Load::Failed);
                    s.set_status_error(e.into());
                });
            }
        }
    }

    pub fn refresh_audit(self: &Rc<Self>) {
        let refused = self
            .with_store(|s| {
                s.set_audit_load(Load::Loading);
                s.get_audit_refused_only()
            })
            .unwrap_or(false);
        // The rule buttons need the centers that are paired now.
        self.job(
            move |r| {
                let status = r.run(&["status"]);
                let args: &[&str] = if refused {
                    &["audit", "--denied"]
                } else {
                    &["audit"]
                };
                (status, r.run(args))
            },
            |c, (status, audit)| {
                c.show_status(status);
                c.show_audit(audit);
            },
        );
    }

    fn show_audit(&self, answer: Result<Value, String>) {
        match answer {
            Ok(v) => {
                let entries = v["entries"].as_array().cloned().unwrap_or_default();
                let rows = view::audit(&entries, &self.centers.borrow(), now_ms());
                *self.audit.borrow_mut() = entries
                    .iter()
                    .rev()
                    .take(view::AUDIT_SHOWN)
                    .cloned()
                    .collect();
                self.with_store(|s| {
                    s.set_audit_total(entries.len() as i32);
                    s.set_audit(ModelRc::new(VecModel::from(rows)));
                    s.set_audit_load(Load::Ready);
                    s.set_audit_error(SharedString::new());
                });
            }
            Err(e) => {
                self.with_store(|s| {
                    s.set_audit_load(Load::Failed);
                    s.set_audit_error(e.into());
                });
            }
        }
    }

    /// One of the four buttons on an audit entry.
    fn audit_rule(self: &Rc<Self>, index: usize, list: &str, wildcard: bool) {
        let Some(entry) = self.audit.borrow().get(index).cloned() else {
            return;
        };
        let args = view::rule_args(&entry, list, wildcard);
        let list = view::rule_list(&entry, list);
        let center = entry["center"].as_str().unwrap_or_default().to_string();
        self.with_store(|s| s.set_busy(format!("audit-{index}").into()));
        self.job(
            move |r| r.run(&args.iter().map(String::as_str).collect::<Vec<_>>()),
            move |c, answer| {
                c.with_store(|s| s.set_busy(SharedString::new()));
                match answer {
                    Ok(_) => {
                        let list = match list {
                            "sudo" => "sudo allow list",
                            "deny" => "deny list",
                            _ => "allow list",
                        };
                        c.toast(format!("Added to the {list} of {center}."), Tone::Ok);
                        c.refresh_audit();
                    }
                    Err(e) => c.toast(e, Tone::Danger),
                }
            },
        );
    }

    fn pair_start(&self) {
        self.with_store(|s| {
            s.set_pair_step(0);
            s.set_pair_link(SharedString::new());
            s.set_pair_name(SharedString::new());
            s.set_pair_error(SharedString::new());
            s.set_pair_busy(false);
            s.set_pair_open(true);
        });
    }

    /// `center add`: without `yes` the preview the owner confirms, with it
    /// the pairing.
    fn pair(self: &Rc<Self>, link: &str, name: &str, yes: bool) {
        let mut args = vec!["center".to_string(), "add".into(), link.trim().to_string()];
        if !name.trim().is_empty() {
            args.push("--name".into());
            args.push(name.trim().into());
        }
        if yes {
            args.push("--yes".into());
        }
        self.with_store(|s| {
            s.set_pair_busy(true);
            s.set_pair_error(SharedString::new());
        });
        self.job(
            move |r| r.run(&args.iter().map(String::as_str).collect::<Vec<_>>()),
            move |c, answer| {
                c.with_store(|s| s.set_pair_busy(false));
                match answer {
                    Ok(v) if !yes => {
                        let p = &v["preview"];
                        let preview = PairPreview {
                            center: p["center"].as_str().unwrap_or_default().into(),
                            tls: p["tls"] == true,
                            pin: p["pin"].as_str().unwrap_or_default().into(),
                            name: p["name"].as_str().unwrap_or_default().into(),
                        };
                        c.with_store(|s| {
                            s.set_pair_preview(preview);
                            s.set_pair_step(1);
                        });
                    }
                    Ok(v) => {
                        c.with_store(|s| s.set_pair_open(false));
                        let name = v["name"].as_str().unwrap_or_default();
                        c.toast(
                            format!("Paired with {name}. It may do nothing until you allow it."),
                            Tone::Ok,
                        );
                        c.refresh_status();
                    }
                    Err(e) => {
                        c.with_store(|s| s.set_pair_error(e.into()));
                    }
                }
            },
        );
    }

    /// Runs a change about `key` (a center's name, "node"), whose buttons
    /// wait meanwhile, and says `said` once the node made it.
    fn change(self: &Rc<Self>, key: &str, args: Vec<String>, said: String) {
        self.with_store(|s| s.set_busy(key.into()));
        self.job(
            move |r| r.run(&args.iter().map(String::as_str).collect::<Vec<_>>()),
            move |c, answer| {
                c.with_store(|s| s.set_busy(SharedString::new()));
                match answer {
                    Ok(_) => c.toast(said, Tone::Ok),
                    Err(e) => c.toast(e, Tone::Danger),
                }
                c.refresh_status();
            },
        );
    }

    fn center_pause(self: &Rc<Self>, name: &str, pause: bool) {
        let verb = if pause { "pause" } else { "resume" };
        let said = if pause {
            format!("{name} is paused: its link ends until you resume it.")
        } else {
            format!("{name} is resumed.")
        };
        let args = vec!["center".into(), verb.into(), "--center".into(), name.into()];
        self.change(name, args, said);
    }

    fn center_grant(self: &Rc<Self>, name: &str, on: bool) {
        let said = if on {
            format!("{name} may change this machine's settings now.")
        } else {
            format!("{name} can no longer change this machine's settings.")
        };
        let value = if on { "write" } else { "off" };
        let args = vec![
            "center".into(),
            "grant".into(),
            "settings".into(),
            value.into(),
            "--center".into(),
            name.into(),
        ];
        self.change(name, args, said);
    }

    fn ask_unpair(&self, name: &str) {
        *self.pending.borrow_mut() = Some(Pending::Unpair(name.to_string()));
        self.with_store(|s| {
            s.set_confirm_title(format!("Unpair {name}?").into());
            s.set_confirm_text(
                format!("{name} loses its link to this machine, and its key here is deleted. Its rules go too. To use it again, pair again.").into(),
            );
            s.set_confirm_button("Unpair".into());
            s.set_confirm_open(true);
        });
    }

    fn confirmed(self: &Rc<Self>) {
        let Some(p) = self.pending.borrow_mut().take() else {
            return;
        };
        match p {
            Pending::Unpair(name) => {
                let args = vec![
                    "center".into(),
                    "rm".into(),
                    "--center".into(),
                    name.clone(),
                ];
                self.change(&name, args, format!("Unpaired {name}."));
            }
        }
    }

    fn lock(self: &Rc<Self>, lock: bool) {
        let (args, said) = if lock {
            (
                "panic",
                "Locked: every link ended, and nothing runs until you unlock.",
            )
        } else {
            ("unlock", "Unlocked: the node links and works again.")
        };
        self.change("node", vec![args.into()], said.into());
    }

    fn set_appearance(&self, i: i32) {
        let Some(w) = self.window.upgrade() else {
            return;
        };
        w.global::<Store>().set_appearance(i);
        match i {
            1 => w.invoke_set_dark(false),
            2 => w.invoke_set_dark(true),
            _ => w.invoke_follow_system(),
        }
    }
}

/// Opens the window and runs until it is closed.
pub fn run() -> Result<(), String> {
    let runner = Runner::this_program()?;
    let window = AppWindow::new().map_err(|e| format!("cannot open the window: {e}"))?;
    let ctl = Ctl::attach(&window, runner, Exec::Threads);
    ctl.watch();
    window
        .run()
        .map_err(|e| format!("the window ended with an error: {e}"))
}
