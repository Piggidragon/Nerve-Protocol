//! The audit and log pages follow the node as it writes: `audit --follow`
//! and `log --follow` run while their page is open, and their entries come
//! into the page in batches on the window's thread ([`Ctl::pump`]).

use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{CURRENT, Ctl, Exec, now_ms};
use crate::{Load, Logs, Page, view};

/// How many audit entries the app asks for: the newest the page shows.
pub(super) const AUDIT_LAST: &str = "200";
/// How many log lines the page shows.
const LOG_LAST: usize = 300;

impl Ctl {
    pub(super) fn stop_follow(&self) {
        // A new start; what the old one still sends is left alone.
        self.feed.fetch_add(1, Ordering::SeqCst);
        self.follow.borrow_mut().take();
    }

    /// Starts `args` (a command with `--follow`) for the page that shows it.
    fn start_follow(self: &Rc<Self>, args: Vec<&str>) {
        self.stop_follow();
        let feed = self.feed.load(Ordering::SeqCst);
        let (queue, pumping, exec) = (self.queue.clone(), self.pumping.clone(), self.exec);
        let started = self.runner().follow(&args, move |entry| {
            queue
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((feed, entry));
            // One batch at a time on the window's thread.
            if exec == Exec::Threads && !pumping.swap(true, Ordering::SeqCst) {
                let _ = slint::invoke_from_event_loop(|| {
                    if let Some(c) = CURRENT.with(|c| c.borrow().clone()) {
                        c.pump();
                    }
                });
            }
        });
        match started {
            Ok(f) => *self.follow.borrow_mut() = Some(f),
            Err(e) => self.feed_failed(e),
        }
        // A log with nothing in it says nothing: after a moment the page is
        // ready all the same.
        if self.exec == Exec::Threads {
            let c = Rc::downgrade(self);
            self.settle.start(
                slint::TimerMode::SingleShot,
                Duration::from_millis(700),
                move || {
                    if let Some(c) = c.upgrade() {
                        c.pump();
                        c.feed_ready();
                    }
                },
            );
        }
    }

    pub(super) fn follow_audit(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        self.audit.borrow_mut().clear();
        let refused = self
            .with_store(|s| {
                s.set_audit_load(Load::Loading);
                s.set_audit(ModelRc::default());
                s.get_audit_refused_only()
            })
            .unwrap_or(false);
        let mut args = vec!["audit", "--follow", "--last", AUDIT_LAST];
        if refused {
            args.push("--denied");
        }
        // The rule buttons need the centers that are paired now.
        self.refresh_status();
        self.start_follow(args);
    }

    pub(super) fn follow_log(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        self.log.borrow_mut().clear();
        if let Some(w) = self.window.upgrade() {
            let l = w.global::<Logs>();
            l.set_load(Load::Loading);
            l.set_rows(ModelRc::default());
        }
        let last = LOG_LAST.to_string();
        self.start_follow(vec!["log", "--follow", "--last", &last]);
    }

    fn page(&self) -> Option<Page> {
        self.with_store(|s| s.get_page())
    }

    fn feed_failed(&self, e: String) {
        match self.page() {
            Some(Page::Log) => {
                if let Some(w) = self.window.upgrade() {
                    let l = w.global::<Logs>();
                    l.set_load(Load::Failed);
                    l.set_error(e.into());
                }
            }
            _ => {
                self.with_store(|s| {
                    s.set_audit_load(Load::Failed);
                    s.set_audit_error(e.into());
                });
            }
        }
    }

    /// The page shows what came so far, also when that is nothing. A timer
    /// calls it a moment after the start; tests, which have none, call it
    /// themselves.
    pub fn feed_ready(&self) {
        match self.page() {
            Some(Page::Log) => {
                if let Some(w) = self.window.upgrade() {
                    let l = w.global::<Logs>();
                    if l.get_load() == Load::Loading {
                        l.set_load(Load::Ready);
                    }
                }
            }
            Some(Page::Audit) => {
                self.with_store(|s| {
                    if s.get_audit_load() == Load::Loading {
                        s.set_audit_load(Load::Ready);
                    }
                });
            }
            _ => {}
        }
    }

    /// Takes what the running command gave into its page. Tests, which have
    /// no event loop, call it themselves.
    pub fn pump(&self) {
        self.pumping.store(false, Ordering::SeqCst);
        let feed = self.feed.load(Ordering::SeqCst);
        let batch: Vec<_> =
            std::mem::take(&mut *self.queue.lock().unwrap_or_else(|p| p.into_inner()))
                .into_iter()
                .filter(|(f, _)| *f == feed)
                .map(|(_, e)| e)
                .collect();
        if batch.is_empty() {
            return;
        }
        let log = self.page() == Some(Page::Log);
        for entry in batch {
            match entry {
                Ok(v) => {
                    let (list, keep) = if log {
                        (&self.log, LOG_LAST)
                    } else {
                        (&self.audit, view::AUDIT_SHOWN)
                    };
                    let mut l = list.borrow_mut();
                    l.insert(0, v);
                    l.truncate(keep);
                }
                Err(e) => {
                    self.feed_failed(e);
                    return;
                }
            }
        }
        if log {
            let problems = self
                .window
                .upgrade()
                .map(|w| w.global::<Logs>().get_problems_only())
                .unwrap_or(false);
            let rows = view::log_rows(&self.log.borrow(), problems, now_ms());
            if let Some(w) = self.window.upgrade() {
                let l = w.global::<Logs>();
                l.set_rows(ModelRc::new(VecModel::from(rows)));
                l.set_load(Load::Ready);
                l.set_error(SharedString::new());
            }
        } else {
            let rows = view::audit(&self.audit.borrow(), &self.centers.borrow(), now_ms());
            self.with_store(|s| {
                s.set_audit_total(rows.len() as i32);
                s.set_audit(ModelRc::new(VecModel::from(rows)));
                s.set_audit_load(Load::Ready);
                s.set_audit_error(SharedString::new());
            });
        }
    }

    /// Shows the log again, all of it or its problems.
    pub(super) fn log_filter(&self, problems: bool) {
        let rows = view::log_rows(&self.log.borrow(), problems, now_ms());
        if let Some(w) = self.window.upgrade() {
            let l = w.global::<Logs>();
            l.set_problems_only(problems);
            l.set_rows(ModelRc::new(VecModel::from(rows)));
        }
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let c = ctl.clone();
    window
        .global::<Logs>()
        .on_filter(move |problems| c.log_filter(problems));
}
