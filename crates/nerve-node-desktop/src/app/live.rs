//! The audit and log pages follow the node as it writes: `audit --follow`
//! and `log --follow` run while their page is open, and their entries come
//! into the page in batches on the window's thread ([`Ctl::pump`]).

use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{CURRENT, Ctl, Exec, now_ms};
use crate::{Load, Logs, Page, view};

/// The most audit entries and log lines a page asks for once the owner
/// wants more than the newest few (`Store.audit-limit`, `Logs.limit`): the
/// page lays out every row it holds.
const MOST: i32 = 1000;

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
        let last = self
            .with_store(|s| s.get_audit_limit())
            .unwrap_or_default()
            .to_string();
        let mut args = vec!["audit", "--follow", "--last", &last];
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
        let (last, problems) = self
            .window
            .upgrade()
            .map(|w| {
                let l = w.global::<Logs>();
                (l.get_limit(), l.get_problems_only())
            })
            .unwrap_or_default();
        let last = last.to_string();
        let mut args = vec!["log", "--follow", "--last", &last];
        // The CLI picks the problems from the whole log, so that the newest
        // of them show, not those among the newest lines.
        if problems {
            args.push("--problems");
        }
        self.start_follow(args);
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
        let keep = if log {
            self.window
                .upgrade()
                .map(|w| w.global::<Logs>().get_limit())
        } else {
            self.with_store(|s| s.get_audit_limit())
        };
        let keep = keep.unwrap_or_default().max(0) as usize;
        for entry in batch {
            match entry {
                Ok(v) => {
                    let list = if log { &self.log } else { &self.audit };
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

    /// Says again how long ago each shown entry was, as of `now`: the timer
    /// that asks for the status calls it, so that "just now" does not stay
    /// on an entry of an hour ago while the node writes nothing new. Only
    /// the rows whose time reads differently change, so the list keeps its
    /// place.
    pub fn refresh_times(&self, now: u64) {
        match self.page() {
            Some(Page::Log) => {
                let Some(w) = self.window.upgrade() else {
                    return;
                };
                let l = w.global::<Logs>();
                let rows = view::log_rows(&self.log.borrow(), l.get_problems_only(), now);
                retime(&l.get_rows(), rows, |r| &r.when);
            }
            Some(Page::Audit) => {
                let rows = view::audit(&self.audit.borrow(), &self.centers.borrow(), now);
                self.with_store(|s| retime(&s.get_audit(), rows, |r| &r.when));
            }
            _ => {}
        }
    }

    /// Shows the log again, all of it or its problems.
    pub(super) fn log_filter(self: &Rc<Self>, problems: bool) {
        if let Some(w) = self.window.upgrade() {
            w.global::<Logs>().set_problems_only(problems);
        }
        self.follow_log();
    }
}

/// Puts each of `rows` whose time (`when`) differs from the shown one in
/// its place; a list that is not the shown one's length is left alone (an
/// entry came, and the next batch shows it whole).
fn retime<T: Clone + 'static>(
    shown: &ModelRc<T>,
    rows: Vec<T>,
    when: impl Fn(&T) -> &SharedString,
) {
    use slint::Model;
    if shown.row_count() != rows.len() {
        return;
    }
    for (i, row) in rows.into_iter().enumerate() {
        if shown
            .row_data(i)
            .is_some_and(|old| when(&old) != when(&row))
        {
            shown.set_row_data(i, row);
        }
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let c = ctl.clone();
    window.global::<crate::Store>().on_audit_more(move || {
        c.with_store(|s| s.set_audit_limit(MOST));
        c.follow_audit();
    });
    let c = ctl.clone();
    window.global::<Logs>().on_more(move || {
        if let Some(w) = c.window.upgrade() {
            w.global::<Logs>().set_limit(MOST);
        }
        c.follow_log();
    });
    let c = ctl.clone();
    window
        .global::<Logs>()
        .on_filter(move |problems| c.log_filter(problems));
}
