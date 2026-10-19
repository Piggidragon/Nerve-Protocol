//! The app's actions: each one runs a `nerve-node` command ([`Runner`]) off
//! the window's thread and shows its answer ([`crate::view`]). A change is
//! shown once the node made it, never before.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::broker::Launch;
use crate::runner::{Follow, Runner};
use crate::{
    AppWindow, Install, Load, Manual, Page, PairPreview, Perm, Prefs, Store, Tone, Type, view,
};

mod install;
mod live;
mod node;
mod perm;
mod prefs;

/// Where the commands run: on threads of their own, answering on the
/// window's event loop; or at once, for tests and the screenshots, which
/// have no event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exec {
    Threads,
    Inline,
}

/// What the owner picks in one of the system's file dialogs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choose {
    /// A folder a center may use.
    Folder,
    /// Where a new backup goes.
    SaveBackup,
    /// The backup to restore.
    OpenBackup,
    /// The program an update takes.
    Program,
}

/// Shows the system's dialog for a [`Choose`]; tests answer for it.
pub type Chooser = Arc<dyn Fn(Choose) -> Option<PathBuf> + Send + Sync>;

/// Starts the installed app, as the menu entry does; tests answer for it.
pub type Launcher = Arc<dyn Fn(&std::path::Path) -> Result<(), String> + Send + Sync>;

/// The system's own dialogs: the desktop portal on Linux, so they work on
/// Wayland and look like the desktop's.
fn system_chooser() -> Chooser {
    Arc::new(|c| {
        let d = rfd::FileDialog::new();
        match c {
            Choose::Folder => d.set_title("A folder for the center").pick_folder(),
            Choose::SaveBackup => d
                .set_title("Back up the node")
                .set_file_name("nerve-node.backup")
                .save_file(),
            Choose::OpenBackup => d.set_title("Restore a backup").pick_file(),
            Choose::Program => d.set_title("The new nerve-node-desktop").pick_file(),
        }
    })
}

/// The change that waits for the owner's yes in the confirm dialog.
enum Pending {
    Unpair(String),
    RotateKey(String),
    Accept,
}

/// What a command that keeps answering gave, until the window takes it.
type Queue = Arc<Mutex<Vec<(u64, Result<Value, String>)>>>;

pub struct Ctl {
    runner: RefCell<Runner>,
    exec: Exec,
    window: slint::Weak<AppWindow>,
    chooser: RefCell<Chooser>,
    /// The audit entries shown, newest first: what a button's index names.
    audit: RefCell<Vec<Value>>,
    /// The log lines shown, newest first.
    log: RefCell<Vec<Value>>,
    /// The names of the paired centers, and the status, as the node said
    /// them last.
    centers: RefCell<Vec<String>>,
    status: RefCell<Value>,
    pending: RefCell<Option<Pending>>,
    asking_status: Cell<bool>,
    timer: slint::Timer,
    /// The page's command that keeps answering (`audit --follow`), what it
    /// gave, and which start of it that was.
    follow: RefCell<Option<Follow>>,
    queue: Queue,
    feed: Arc<AtomicU64>,
    pumping: Arc<AtomicBool>,
    settle: slint::Timer,
    /// Whether the node is the installed service's, whose state the app
    /// asks for, and whether it is asking now.
    service: Cell<bool>,
    asking_service: Cell<bool>,
    /// Starts the installed app (src/app/install.rs), which is there.
    launcher: RefCell<Launcher>,
    program: RefCell<PathBuf>,
    /// The app's own settings file (crate::settings), when it keeps one.
    settings: RefCell<Option<PathBuf>>,
    /// This window's claim as the user's one window (crate::instance).
    instance: RefCell<Option<crate::instance::Instance>>,
    /// How the broker starts when the node is installed as a service.
    elevate: Cell<Option<Launch>>,
    /// A `nerve://` link the app was opened with, paired once it can be.
    link: RefCell<Option<String>>,
    /// Open the first-run steps when nothing is paired yet.
    first_run: Cell<bool>,
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

fn strings(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// The lines a change said (`{"messages": [...]}`), as one text.
fn messages(v: &Value) -> String {
    v["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

impl Ctl {
    /// Wires `window`'s actions to the CLI that `runner` starts.
    pub fn attach(window: &AppWindow, runner: Runner, exec: Exec) -> Rc<Ctl> {
        let ctl = Rc::new(Ctl {
            runner: RefCell::new(runner),
            exec,
            window: window.as_weak(),
            chooser: RefCell::new(system_chooser()),
            audit: RefCell::new(Vec::new()),
            log: RefCell::new(Vec::new()),
            centers: RefCell::new(Vec::new()),
            status: RefCell::new(Value::Null),
            pending: RefCell::new(None),
            asking_status: Cell::new(false),
            timer: slint::Timer::default(),
            follow: RefCell::new(None),
            queue: Arc::default(),
            feed: Arc::default(),
            pumping: Arc::default(),
            settle: slint::Timer::default(),
            service: Cell::new(false),
            asking_service: Cell::new(false),
            launcher: RefCell::new(install::system_launcher()),
            program: RefCell::new(PathBuf::new()),
            settings: RefCell::new(None),
            instance: RefCell::new(None),
            elevate: Cell::new(None),
            link: RefCell::new(None),
            first_run: Cell::new(false),
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(ctl.clone()));
        window.global::<Type>().set_mono(mono_font().into());
        window
            .global::<Manual>()
            .set_sections(ModelRc::new(VecModel::from(view::help(
                &nerve_node::cli::help(),
            ))));
        let store = window.global::<Store>();
        store.set_version(env!("CARGO_PKG_VERSION").into());
        window
            .global::<Install>()
            .set_version(env!("CARGO_PKG_VERSION").into());

        let c = ctl.clone();
        store.on_show(move |page| c.show(page));
        let c = ctl.clone();
        store.on_refresh(move || c.refresh_status());
        let c = ctl.clone();
        store.on_refresh_audit(move || c.follow_audit());
        let c = ctl.clone();
        store.on_audit_filter(move |refused| {
            c.with_store(|s| s.set_audit_refused_only(refused));
            c.follow_audit();
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
        store.on_center_rotate(move |name| c.ask_rotate(&name));
        let c = ctl.clone();
        store.on_confirm_accepted(move || c.confirmed());
        let c = ctl.clone();
        store.on_panic(move || c.lock(true));
        let c = ctl.clone();
        store.on_unlock(move || c.lock(false));
        let c = ctl.clone();
        store.on_set_appearance(move |i| c.set_appearance(i));
        node::wire(&ctl, window);
        perm::wire(&ctl, window);
        prefs::wire(&ctl, window);
        live::wire(&ctl, window);
        install::wire(&ctl, window);
        ctl
    }

    /// Answers the file dialogs with `chooser` instead of the system's.
    pub fn set_chooser(&self, chooser: Chooser) {
        *self.chooser.borrow_mut() = chooser;
    }

    /// The node is installed as a service: the app needs the rights to read
    /// it, says why, and asks with `how` when the owner goes on.
    pub fn needs_rights(&self, how: Launch) {
        self.elevate.set(Some(how));
        self.with_store(|s| {
            s.set_elevate_needed(true);
            s.set_elevate_open(true);
            s.set_installed(true);
        });
    }

    /// Opens with `link`: straight to its pairing once the node answers.
    pub fn open_link(self: &Rc<Self>, link: String) {
        *self.link.borrow_mut() = Some(link);
        self.take_link();
    }

    /// Opens the first-run steps when the node turns out to have no center.
    pub fn offer_setup(&self) {
        self.first_run.set(true);
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

    fn with_perm<R>(&self, f: impl FnOnce(&Perm<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let p = w.global::<Perm>();
        Some(f(&p))
    }

    fn with_install<R>(&self, f: impl FnOnce(&Install<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let i = w.global::<Install>();
        Some(f(&i))
    }

    fn with_prefs<R>(&self, f: impl FnOnce(&Prefs<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let p = w.global::<Prefs>();
        Some(f(&p))
    }

    fn runner(&self) -> Runner {
        self.runner.borrow().clone()
    }

    /// Whether the commands cannot run yet: the node is the system's and the
    /// app has no rights for it.
    fn waiting_for_rights(&self) -> bool {
        self.elevate.get().is_some() && !self.runner.borrow().elevated()
    }

    /// Runs `work` with the runner, then `done` with its result on the
    /// window's thread.
    fn job<R: Send + 'static>(
        self: &Rc<Self>,
        work: impl FnOnce(&Runner) -> R + Send + 'static,
        done: impl FnOnce(&Rc<Ctl>, R) + Send + 'static,
    ) {
        let runner = self.runner();
        match self.exec {
            Exec::Inline => {
                let r = work(&runner);
                done(self, r);
            }
            Exec::Threads => {
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

    /// Runs one command, then `done` with its answer. An answer that says
    /// the broker is gone asks for the rights again.
    fn command(
        self: &Rc<Self>,
        args: Vec<String>,
        input: Option<String>,
        done: impl FnOnce(&Rc<Ctl>, Result<Value, String>) + Send + 'static,
    ) {
        self.job(
            move |r| r.run_with(&strings(&args), input.as_deref()),
            move |c, answer| {
                if answer.as_ref().is_err_and(|e| e == crate::broker::GONE) {
                    c.rights_gone();
                }
                done(c, answer)
            },
        );
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
        // Only the page that shows it keeps a command running.
        if !matches!(page, Page::Audit | Page::Log) {
            self.stop_follow();
        }
        match page {
            Page::Audit => self.follow_audit(),
            Page::Log => self.follow_log(),
            Page::Policy => {
                self.refresh_status();
                self.perm_load();
            }
            Page::Settings => self.prefs_load(),
            _ => self.refresh_status(),
        }
    }

    pub fn refresh_status(self: &Rc<Self>) {
        self.refresh_service();
        if self.waiting_for_rights() {
            self.with_store(|s| {
                s.set_status_load(Load::Failed);
                s.set_status_error(
                    "The node is installed as a service: the app needs administrator rights to read it."
                        .into(),
                );
            });
            return;
        }
        // One question at a time: a slow node is not asked again meanwhile.
        if self.asking_status.replace(true) {
            return;
        }
        self.command(vec!["status".into()], None, |c, answer| {
            c.asking_status.set(false);
            c.show_status(answer);
        });
    }

    fn show_status(self: &Rc<Self>, answer: Result<Value, String>) {
        match answer {
            Ok(v) => {
                let (status, centers) = view::status(&v, now_ms());
                let names: Vec<String> = centers.iter().map(|c| c.name.to_string()).collect();
                let first = self.status.borrow().is_null();
                *self.centers.borrow_mut() = names.clone();
                *self.status.borrow_mut() = v;
                self.with_store(|s| {
                    s.set_status(status);
                    s.set_centers(ModelRc::new(VecModel::from(centers)));
                    s.set_status_load(Load::Ready);
                    s.set_status_error(SharedString::new());
                });
                self.perm_centers(&names);
                if first {
                    self.after_first_status(names.is_empty());
                }
            }
            Err(e) => {
                self.with_store(|s| {
                    s.set_status_load(Load::Failed);
                    s.set_status_error(e.into());
                });
            }
        }
    }

    /// The first answer of the node: a link the app was opened with goes to
    /// its pairing now, and a node without a center gets the first-run steps.
    fn after_first_status(self: &Rc<Self>, no_center: bool) {
        if self.link.borrow().is_some() {
            self.take_link();
        } else if no_center && self.first_run.get() {
            self.setup_start();
        }
    }

    fn take_link(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        let Some(link) = self.link.borrow_mut().take() else {
            return;
        };
        self.pair_start();
        self.with_store(|s| s.set_pair_link(link.as_str().into()));
        self.pair(&link, "", false);
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
        self.command(args, None, move |c, answer| {
            c.with_store(|s| s.set_busy(SharedString::new()));
            match answer {
                Ok(_) => {
                    let list = match list {
                        "sudo" => "sudo allow list",
                        "deny" => "deny list",
                        _ => "allow list",
                    };
                    c.toast(format!("Added to the {list} of {center}."), Tone::Ok);
                }
                Err(e) => c.toast(e, Tone::Danger),
            }
        });
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
    /// the pairing. In the first-run steps the steps go on after it.
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
        self.command(args, None, move |c, answer| {
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
                    let name = v["name"].as_str().unwrap_or_default().to_string();
                    let steps = c.with_store(|s| s.get_setup_open()).unwrap_or(false);
                    c.with_store(|s| s.set_pair_open(false));
                    if steps {
                        c.setup_paired(&name);
                    } else {
                        c.toast(
                            format!("Paired with {name}. It may do nothing until you allow it."),
                            Tone::Ok,
                        );
                    }
                    c.refresh_status();
                }
                Err(e) => {
                    c.with_store(|s| s.set_pair_error(e.into()));
                }
            }
        });
    }

    /// Runs a change about `key` (a center's name, "node"), whose buttons
    /// wait meanwhile, and says `said` once the node made it.
    fn change(self: &Rc<Self>, key: &str, args: Vec<String>, said: String) {
        self.with_store(|s| s.set_busy(key.into()));
        self.command(args, None, move |c, answer| {
            c.with_store(|s| s.set_busy(SharedString::new()));
            match answer {
                Ok(_) => c.toast(said, Tone::Ok),
                Err(e) => c.toast(e, Tone::Danger),
            }
            c.refresh_status();
        });
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

    fn confirm(&self, pending: Pending, title: String, text: String, button: &str) {
        *self.pending.borrow_mut() = Some(pending);
        self.with_store(|s| {
            s.set_confirm_title(title.into());
            s.set_confirm_text(text.into());
            s.set_confirm_button(button.into());
            s.set_confirm_open(true);
        });
    }

    fn ask_unpair(&self, name: &str) {
        self.confirm(
            Pending::Unpair(name.to_string()),
            format!("Unpair {name}?"),
            format!("{name} loses its link to this machine, and its key here is deleted. Its rules go too. To use it again, pair again."),
            "Unpair",
        );
    }

    fn ask_rotate(&self, name: &str) {
        self.confirm(
            Pending::RotateKey(name.to_string()),
            format!("A new key for {name}?"),
            format!("This machine makes a new key for {name} and sends it over the link; the old one is deleted here. {name} takes the old key for 7 more days. The node must run and be linked to {name}."),
            "Make a new key",
        );
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
            Pending::RotateKey(name) => {
                let args = vec![
                    "center".into(),
                    "rotate-key".into(),
                    "--center".into(),
                    name.clone(),
                ];
                self.with_store(|s| s.set_busy(name.as_str().into()));
                self.command(args, None, move |c, answer| {
                    c.with_store(|s| s.set_busy(SharedString::new()));
                    match answer {
                        Ok(v) => c.show_once(&format!("New key for {name}"), &messages(&v)),
                        Err(e) => c.toast(e, Tone::Danger),
                    }
                });
            }
            Pending::Accept => {
                self.command(vec!["config".into(), "accept".into()], None, |c, answer| {
                    match answer {
                        Ok(v) => c.toast(messages(&v), Tone::Ok),
                        Err(e) => c.toast(e, Tone::Danger),
                    }
                    c.refresh_status();
                });
            }
        }
    }

    /// Shows what a command said once, such as a token, to copy.
    fn show_once(&self, title: &str, text: &str) {
        self.with_prefs(|p| {
            p.set_once_title(title.into());
            p.set_once_text(text.into());
            p.set_once_open(true);
        });
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

    /// Makes this window the user's one window: what a later start asks
    /// comes here.
    pub fn take_starts(&self, instance: crate::instance::Instance) {
        instance.listen(|asked| {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(c) = CURRENT.with(|c| c.borrow().clone()) {
                    c.started_again(asked);
                }
            });
        });
        *self.instance.borrow_mut() = Some(instance);
    }

    /// Another start of the app: this window comes to the front, and the
    /// app opens the link it was given, or its uninstall.
    pub fn started_again(self: &Rc<Self>, asked: crate::instance::Asked) {
        if let Some(w) = self.window.upgrade() {
            let _ = w.show();
            w.window().set_minimized(false);
        }
        let installer = self.with_install(|i| i.get_shown()).unwrap_or(false);
        if installer {
            return;
        }
        if let Some(link) = asked.link {
            self.open_link(link);
        } else if asked.uninstall {
            self.ask_uninstall();
        }
    }

    /// Keeps the app's settings in `file`, and takes the appearance saved
    /// there.
    pub fn keep_settings(&self, file: PathBuf) {
        let appearance = crate::settings::appearance(&file);
        *self.settings.borrow_mut() = Some(file);
        self.show_appearance(appearance);
    }

    fn set_appearance(&self, i: i32) {
        self.show_appearance(i);
        if let Some(file) = self.settings.borrow().as_ref()
            && let Err(e) = crate::settings::save_appearance(file, i)
        {
            self.toast(format!("The appearance is not saved: {e}"), Tone::Danger);
        }
    }

    fn show_appearance(&self, i: i32) {
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

/// Opens the window and runs until it is closed. The installed program
/// opens the app, at what `start` asks (the pairing of a `nerve://` link,
/// or the uninstall); any other copy of it, such as the file just
/// downloaded, the installer.
pub fn run(start: crate::instance::Asked) -> Result<(), String> {
    // A window of this user's is open already: it takes this start.
    let instance = match crate::instance::claim(&start) {
        crate::instance::Claimed::Forwarded => return Ok(()),
        crate::instance::Claimed::First(i) => i,
    };
    let runner = Runner::this_program()?;
    let layout = nerve_node::service::Layout::system();
    let here = std::env::current_exe().and_then(std::fs::canonicalize).ok();
    let installed = std::fs::canonicalize(&layout.bin).ok();
    // The window's name on Wayland and X11, by which the desktop finds its
    // menu entry (crate::parts).
    let _ = slint::set_xdg_app_id(crate::parts::PROGRAM);
    let window = AppWindow::new().map_err(|e| format!("cannot open the window: {e}"))?;
    let ctl = Ctl::attach(&window, runner, Exec::Threads);
    if let Some(file) = crate::settings::file() {
        ctl.keep_settings(file);
    }
    ctl.take_starts(instance);
    if here.is_none() || here != installed {
        ctl.installer(Launch::Elevated, &layout.bin);
    } else {
        // The node's default folders: the service's when it is installed.
        let paths = nerve_node::NodePaths::from_args(None, None);
        window
            .global::<Store>()
            .set_installed(layout.installed() && paths == layout.paths);
        ctl.watch_service(paths == layout.paths, &layout.bin);
        // The CLI says itself whether this user may open the node's files.
        if nerve_node::service::check_access(&paths).is_err() {
            ctl.needs_rights(Launch::Elevated);
        }
        match start.link {
            Some(link) => ctl.open_link(link),
            None if start.uninstall => ctl.ask_uninstall(),
            None => ctl.offer_setup(),
        }
        ctl.watch();
    }
    let r = window
        .run()
        .map_err(|e| format!("the window ended with an error: {e}"));
    ctl.end();
    r
}
