//! The job object a command runs in on Windows. The shell starts suspended,
//! is put in a job of its own before it runs anything, and only then runs;
//! every process it starts is in that job too, however deep, also when its
//! parent has exited. A cancel, a timeout, `exec.signal`, the session's end
//! and the call's end end the job, and with it every process in it. The job
//! closes with the node, so a node that dies leaves no command running.
//!
//! What the job does not hold: a process another program starts on the
//! command's request, such as the WMI provider host (`Win32_Process.Create`),
//! a service or the task scheduler. That process is that program's child and
//! in that program's job. A job does not restrict file access either: it is
//! no confinement, and folder mode still runs no command on Windows.
//!
//! When Windows makes no job, the command runs anyway and its processes are
//! ended by the walk of crate::tree, best effort. When it makes one but
//! cannot put the shell in it, the command does not run.
//!
//! The choices and their texts are plain logic, tested on every platform;
//! the job itself is crate::win::Job.

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::{Arc, Mutex};

/// What the node logs when Windows made no job for a command: it then runs
/// with the walk.
pub fn no_job_warning(err: &dyn Display) -> String {
    format!(
        "cannot make a job object for a command ({err}); its processes are ended by a walk \
         of the process table instead, which misses some"
    )
}

/// Why a command did not run when Windows did not put its shell in its job.
/// `in_job` is whether the shell is in a job already: the node's own, under
/// a service or the task scheduler, which the shell was born into. Windows 8
/// and later nest a new job in that one; a job that allows neither nesting
/// nor breakaway is reported as what it is.
pub fn assign_error(in_job: Option<bool>, err: &dyn Display) -> String {
    match in_job {
        Some(true) => format!(
            "the command was not run: the node runs inside a job of its own (set up by a \
             service or the task scheduler) that lets a command neither have a job nested in \
             it nor break away from it, so the node could not hold the command's processes \
             ({err})"
        ),
        _ => format!(
            "the command was not run: Windows did not put its shell in a job object, so the \
             node could not hold the command's processes ({err})"
        ),
    }
}

/// Something that ends every process it holds: a job object, a fake in the
/// tests.
pub trait End {
    /// Whether the processes were ended.
    fn end(&self) -> bool;
}

/// The jobs of the running commands, by their shell's pid.
pub struct Jobs<J> {
    held: Mutex<HashMap<u32, Arc<J>>>,
}

impl<J> Default for Jobs<J> {
    fn default() -> Self {
        Jobs {
            held: Mutex::default(),
        }
    }
}

impl<J: End> Jobs<J> {
    /// Holds `job` as the job of the shell `pid`, until [`Jobs::release`].
    pub fn hold(&self, pid: u32, job: J) {
        self.held.lock().unwrap().insert(pid, Arc::new(job));
    }

    /// Whether the shell `pid` has a job.
    pub fn holds(&self, pid: u32) -> bool {
        self.held.lock().unwrap().contains_key(&pid)
    }

    /// Ends the processes of the shell `pid` through its job; false when it
    /// has none or Windows did not end it, and the walk has to.
    pub fn end(&self, pid: u32) -> bool {
        let job = self.held.lock().unwrap().get(&pid).cloned();
        job.is_some_and(|j| j.end())
    }

    /// Ends the job of `pid` and lets it go.
    pub fn release(&self, pid: u32) {
        let job = self.held.lock().unwrap().remove(&pid);
        if let Some(j) = job {
            j.end();
        }
    }
}

#[cfg(windows)]
pub use sys::{SUSPENDED, adopt, end, holds, make, release};

#[cfg(windows)]
mod sys {
    use std::sync::OnceLock;

    use super::{End, Jobs, assign_error, no_job_warning};
    use crate::win::{self, Job};

    /// The creation flag that starts the shell suspended, so it runs nothing
    /// before it is in its job.
    pub const SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    impl End for Job {
        fn end(&self) -> bool {
            self.terminate()
        }
    }

    fn jobs() -> &'static Jobs<Job> {
        static J: OnceLock<Jobs<Job>> = OnceLock::new();
        J.get_or_init(Jobs::default)
    }

    /// A job for the next command; `None`, logged, when Windows makes none
    /// (the command then starts as it is and the walk ends its processes).
    pub fn make() -> Option<Job> {
        match Job::new() {
            Ok(j) => Some(j),
            Err(e) => {
                tracing::warn!("{}", no_job_warning(&e));
                None
            }
        }
    }

    /// Puts the suspended shell `child` in `job` and lets it run; the job
    /// then holds it until [`release`]. On an error the shell has run
    /// nothing and is ended.
    pub fn adopt(job: Job, child: &mut tokio::process::Child) -> Result<(), String> {
        let (Some(pid), Some(handle)) = (child.id(), child.raw_handle()) else {
            return Err("the command was not run: its shell ended before it started".into());
        };
        let handle = handle as win::Handle;
        if let Err(e) = job.assign(handle) {
            let why = assign_error(win::in_job(handle), &e);
            let _ = child.start_kill();
            return Err(why);
        }
        // The pid stays the shell's while the node holds the child's handle,
        // which it does until the call's end has released the job.
        jobs().hold(pid, job);
        if let Err(e) = win::resume(pid) {
            release(pid);
            return Err(format!(
                "the command was not run: its shell could not be resumed ({e})"
            ));
        }
        Ok(())
    }

    /// Whether the shell `pid` runs in a job.
    pub fn holds(pid: u32) -> bool {
        jobs().holds(pid)
    }

    /// Ends every process in the job of the shell `pid`; false when it has
    /// none (the walk's turn).
    pub fn end(pid: u32) -> bool {
        jobs().end(pid)
    }

    /// Ends the job of the shell `pid` and closes it.
    pub fn release(pid: u32) {
        jobs().release(pid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A job that counts its ends and ends, or not, as told.
    struct Fake {
        ends: Arc<AtomicUsize>,
        works: bool,
    }

    impl End for Fake {
        fn end(&self) -> bool {
            self.ends.fetch_add(1, Ordering::SeqCst);
            self.works
        }
    }

    fn fake(works: bool) -> (Fake, Arc<AtomicUsize>) {
        let ends = Arc::new(AtomicUsize::new(0));
        (
            Fake {
                ends: ends.clone(),
                works,
            },
            ends,
        )
    }

    /// A command with a job is ended through it; one without (Windows made
    /// none) is left to the walk, and so is one whose job Windows did not end.
    #[test]
    fn the_walk_ends_only_what_no_job_ended() {
        let jobs = Jobs::default();
        let (job, ends) = fake(true);
        jobs.hold(10, job);
        assert!(jobs.holds(10));
        assert!(jobs.end(10), "a job ends its command");
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        assert!(!jobs.holds(20));
        assert!(!jobs.end(20), "no job: the walk's turn");
        let (broken, _) = fake(false);
        jobs.hold(30, broken);
        assert!(!jobs.end(30), "a job Windows did not end: the walk's turn");
    }

    /// The call's end ends the job once more and lets it go; after that the
    /// pid is not the command's any more, also when Windows gives it to
    /// another process.
    #[test]
    fn release_ends_the_job_and_forgets_the_pid() {
        let jobs = Jobs::default();
        let (job, ends) = fake(true);
        jobs.hold(10, job);
        jobs.release(10);
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        assert!(!jobs.holds(10));
        assert!(!jobs.end(10));
        jobs.release(10);
        assert_eq!(ends.load(Ordering::SeqCst), 1);
    }

    /// The texts say what happened and that the command did not run.
    #[test]
    fn the_texts_say_why() {
        let e = "Access is denied. (os error 5)";
        let nested = assign_error(Some(true), &e);
        assert!(nested.starts_with("the command was not run: "), "{nested}");
        assert!(
            nested.contains("neither have a job nested in it nor break away"),
            "{nested}"
        );
        assert!(
            nested.ends_with("(Access is denied. (os error 5))"),
            "{nested}"
        );
        for in_job in [Some(false), None] {
            let other = assign_error(in_job, &e);
            assert!(
                other.starts_with("the command was not run: Windows did not put its shell"),
                "{other}"
            );
            assert!(!other.contains("nested"), "{other}");
        }
        let w = no_job_warning(&"Not enough quota. (os error 1816)");
        assert!(w.contains("(Not enough quota. (os error 1816))"), "{w}");
        assert!(w.contains("walk of the process table"), "{w}");
    }
}
