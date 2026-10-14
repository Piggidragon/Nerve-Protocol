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
//! no confinement. Folder mode adds that with an AppContainer, which the
//! shim starts in the command's job (nerve_sandbox::appcontainer).
//!
//! When Windows makes no job, the command runs anyway and its processes are
//! ended by the walk of crate::tree, best effort. When it makes one but
//! cannot put the shell in it, the command does not run.
//!
//! The choices and their texts are plain logic, tested on every platform;
//! the job itself is crate::win::Job.

use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// Something that lists the processes it holds: a job object, a fake in the
/// tests.
pub trait Members {
    /// The ids of the processes in it now, those of jobs nested in it
    /// included.
    fn pids(&self) -> std::io::Result<Vec<u32>>;
}

/// Whether `caller` (a process id; `None` when Windows did not tell it) may
/// be a process of a command the node runs: such a caller must not change
/// the node (crate::pipe). `commands` holds the job of each command running
/// now, `None` for one Windows made no job for.
///
/// It errs on the side of the refusal: a caller without an id, any command
/// without a job (its processes cannot be told apart from others) and a job
/// whose processes cannot be listed all refuse. A process stays in its job
/// for its whole life and its children are born into it, so one that is in
/// no job of a running command is no command's.
pub fn from_a_command<'a, J: Members + 'a>(
    caller: Option<u32>,
    commands: impl IntoIterator<Item = Option<&'a J>>,
) -> bool {
    let Some(caller) = caller else {
        return true;
    };
    commands.into_iter().any(|c| match c {
        Some(job) => job.pids().map_or(true, |pids| pids.contains(&caller)),
        None => true,
    })
}

/// Where the ids start in the JOBOBJECT_BASIC_PROCESS_ID_LIST Windows
/// writes: after its two counts, at a pointer's alignment (checked against
/// windows-sys in crate::win).
pub const IDS_AT: usize = 8;

/// The process ids in a JOBOBJECT_BASIC_PROCESS_ID_LIST that Windows wrote
/// into `list`: two u32 counts, the processes in the job and the ids
/// listed, then the ids, one pointer-sized word each. `None` when the job
/// holds more processes than are listed: ask again with more room. Whatever
/// does not add up is an error, so the caller refuses rather than taking an
/// id list that is shorter than the job.
pub fn listed_ids(list: &[u8]) -> Result<Option<Vec<u32>>, String> {
    let count = |at: usize| {
        list.get(at..at + 4)
            .map(|b| u32::from_ne_bytes(b.try_into().expect("four bytes")) as usize)
    };
    let (Some(in_job), Some(listed)) = (count(0), count(4)) else {
        return Err("the job's process list is cut short".into());
    };
    if in_job > listed {
        return Ok(None);
    }
    let word = std::mem::size_of::<usize>();
    let ids = list
        .get(IDS_AT..)
        .and_then(|rest| rest.get(..listed.checked_mul(word)?))
        .ok_or("the job's process list holds fewer ids than it says")?;
    ids.chunks_exact(word)
        .map(|w| {
            let id = usize::from_ne_bytes(w.try_into().expect("a word"));
            u32::try_from(id).map_err(|_| format!("{id} is no process id"))
        })
        .collect::<Result<Vec<u32>, String>>()
        .map(Some)
}

/// How many commands run now without a job of their own.
static JOBLESS: AtomicUsize = AtomicUsize::new(0);

/// Counts a command that runs without a job while it lives: the control
/// pipe cannot tell its processes from others meanwhile.
pub struct Jobless(());

impl Jobless {
    pub fn count() -> Jobless {
        JOBLESS.fetch_add(1, Ordering::SeqCst);
        Jobless(())
    }
}

impl Drop for Jobless {
    fn drop(&mut self) {
        JOBLESS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// How many commands run now without a job of their own.
pub fn jobless() -> usize {
    JOBLESS.load(Ordering::SeqCst)
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
    /// not walked either, since the pid may be another process's by now.
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

    /// A job that holds the processes it is told, or cannot list them.
    struct Holds(Option<Vec<u32>>);

    impl Members for Holds {
        fn pids(&self) -> std::io::Result<Vec<u32>> {
            self.0
                .clone()
                .ok_or_else(|| std::io::Error::other("Access is denied. (os error 5)"))
        }
    }

    /// A caller in the job of a running command is refused, one in none of
    /// them is let through; whatever the node cannot tell refuses.
    #[test]
    fn a_caller_in_a_commands_job_is_refused() {
        let (a, b, broken) = (
            Holds(Some(vec![10, 11])),
            Holds(Some(vec![20])),
            Holds(None),
        );
        let two = || [Some(&a), Some(&b)];
        assert!(from_a_command(Some(11), two()));
        assert!(from_a_command(Some(20), two()));
        assert!(!from_a_command(Some(30), two()));
        assert!(!from_a_command::<Holds>(Some(30), []));
        // Without the caller's id nothing can be told.
        assert!(from_a_command::<Holds>(None, []));
        assert!(from_a_command(None, two()));
        // A command without a job, or a job that cannot be listed.
        assert!(from_a_command(Some(30), [Some(&a), None]));
        assert!(from_a_command(Some(30), [Some(&a), Some(&broken)]));
    }

    /// The list Windows writes, as bytes.
    fn list(in_job: u32, ids: &[usize]) -> Vec<u8> {
        let mut b = in_job.to_ne_bytes().to_vec();
        b.extend((ids.len() as u32).to_ne_bytes());
        b.resize(IDS_AT, 0);
        for id in ids {
            b.extend(id.to_ne_bytes());
        }
        b
    }

    /// The ids come out as Windows listed them; a list shorter than the job
    /// asks for more room, and one that does not add up is an error, never
    /// a shorter list.
    #[test]
    fn the_jobs_process_list_is_read_as_windows_writes_it() {
        assert_eq!(listed_ids(&list(2, &[10, 4242])), Ok(Some(vec![10, 4242])));
        assert_eq!(listed_ids(&list(0, &[])), Ok(Some(vec![])));
        // More processes came than the room held.
        assert_eq!(listed_ids(&list(3, &[10, 11])), Ok(None));
        // Room to spare after the ids is not read.
        let mut spare = list(1, &[7]);
        spare.extend([0xff; 16]);
        assert_eq!(listed_ids(&spare), Ok(Some(vec![7])));
        // Counts that promise more ids than the buffer holds, a cut header,
        // an id no process has.
        let mut short = list(2, &[10, 11]);
        short.truncate(short.len() - 1);
        assert!(listed_ids(&short).is_err());
        assert!(listed_ids(&[0; 6]).is_err());
        let mut huge = list(1, &[]);
        huge[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(listed_ids(&huge).is_err());
        #[cfg(target_pointer_width = "64")]
        assert!(listed_ids(&list(1, &[1 << 40])).is_err());
    }

    /// A command without a job counts while it runs.
    #[test]
    fn a_command_without_a_job_counts_while_it_runs() {
        let before = jobless();
        let one = Jobless::count();
        let two = Jobless::count();
        // No other test counts one.
        assert_eq!(jobless(), before + 2);
        drop(one);
        assert_eq!(jobless(), before + 1);
        drop(two);
        assert_eq!(jobless(), before);
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
