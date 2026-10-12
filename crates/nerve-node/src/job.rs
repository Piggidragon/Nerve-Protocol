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

use std::fmt::Display;
use std::sync::Arc;

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

/// How one command's processes are ended: through its job, or, when Windows
/// made none, by the walk below its shell (`W`, the walk's record). The job
/// goes with the call, never with the shell's pid: tokio lets go of the
/// shell's handle once the shell has exited, while the call still waits for
/// output a background process of the command may hold, and from then on
/// Windows can give that pid to another process.
pub enum Ending<J, W> {
    Job(Arc<J>),
    Walk(W),
}

impl<J, W: Clone> Clone for Ending<J, W> {
    fn clone(&self) -> Self {
        match self {
            Ending::Job(j) => Ending::Job(j.clone()),
            Ending::Walk(w) => Ending::Walk(w.clone()),
        }
    }
}

impl<J: End, W> Ending<J, W> {
    /// Whether the command has a job.
    pub fn has_job(&self) -> bool {
        matches!(self, Ending::Job(_))
    }

    /// Ends the command's processes. A command with a job is ended through
    /// that job alone, also when Windows did not end it: the walk goes by the
    /// shell's pid, which may name another process by now.
    pub fn end(&self, walk: impl FnOnce(&W)) {
        match self {
            Ending::Job(j) => {
                if !j.end() {
                    tracing::warn!("{}", END_FAILED);
                }
            }
            Ending::Walk(w) => walk(w),
        }
    }
}

/// What the node logs when Windows did not end a command's job.
const END_FAILED: &str = "Windows did not end a command's job object; its processes end when the \
     call has ended and the node closes the job";

#[cfg(windows)]
pub use sys::{SUSPENDED, adopt, make};

#[cfg(windows)]
mod sys {
    use std::sync::Arc;

    use super::{End, assign_error, no_job_warning};
    use crate::win::{self, Job};

    /// The creation flag that starts the shell suspended, so it runs nothing
    /// before it is in its job.
    pub const SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    impl End for Job {
        fn end(&self) -> bool {
            self.terminate()
        }
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

    /// Puts the suspended shell `child` in `job` and lets it run; the job is
    /// then the call's, which ends it and closes it at its end. On an error
    /// the shell has run nothing and is ended.
    pub fn adopt(job: Job, child: &mut tokio::process::Child) -> Result<Arc<Job>, String> {
        let (Some(pid), Some(handle)) = (child.id(), child.raw_handle()) else {
            return Err("the command was not run: its shell ended before it started".into());
        };
        let handle = handle as win::Handle;
        if let Err(e) = job.assign(handle) {
            let why = assign_error(win::in_job(handle), &e);
            let _ = child.start_kill();
            return Err(why);
        }
        // The shell is suspended and the node holds its handle, so the pid
        // is still the shell's here.
        if let Err(e) = win::resume(pid) {
            job.end();
            return Err(format!(
                "the command was not run: its shell could not be resumed ({e})"
            ));
        }
        Ok(Arc::new(job))
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

    /// A command with a job is ended through it, one without (Windows made
    /// none) by the walk.
    #[test]
    fn the_walk_ends_only_a_command_without_a_job() {
        let (job, ends) = fake(true);
        let with: Ending<Fake, u32> = Ending::Job(Arc::new(job));
        assert!(with.has_job());
        with.end(|_| panic!("a command with a job was walked"));
        assert_eq!(ends.load(Ordering::SeqCst), 1);
        let without: Ending<Fake, u32> = Ending::Walk(20);
        assert!(!without.has_job());
        let mut walked = None;
        without.end(|pid| walked = Some(*pid));
        assert_eq!(walked, Some(20));
    }

    /// Two commands whose shells had the same pid, the first one's long
    /// exited while a background process still held its output: each call
    /// ends its own job and nothing else, and a job Windows did not end is
    /// not walked either, since the pid may be another process's by now
    /// (code review 2 of PR #19, finding 1).
    #[test]
    fn a_call_ends_its_own_job_whatever_pid_its_shell_had() {
        let (a, a_ends) = fake(true);
        let (b, b_ends) = fake(true);
        let a: Ending<Fake, u32> = Ending::Job(Arc::new(a));
        let b: Ending<Fake, u32> = Ending::Job(Arc::new(b));
        // `exec.signal` holds a copy; it ends the same job.
        let signal = a.clone();
        a.end(|_| panic!("walked"));
        signal.end(|_| panic!("walked"));
        assert_eq!(a_ends.load(Ordering::SeqCst), 2);
        assert_eq!(b_ends.load(Ordering::SeqCst), 0, "A's end ended B's job");
        drop((a, signal));
        b.end(|_| panic!("walked"));
        assert_eq!(b_ends.load(Ordering::SeqCst), 1);
        let (broken, ends) = fake(false);
        let broken: Ending<Fake, u32> = Ending::Job(Arc::new(broken));
        broken.end(|_| panic!("a job Windows did not end was walked"));
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
