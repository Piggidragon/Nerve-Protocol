//! Starting a command forks the whole process, and the child holds a copy of
//! every descriptor the process has open until it execs. A `flock` goes with
//! the open file, not with the descriptor, so a child forked while a thread
//! holds [`crate::secrets::KeysLock`] keeps it held after that thread
//! released it, for as long as the child needs to exec. The node holds it
//! for its whole life and a CLI does not start commands while it writes, but
//! the tests of this crate run in one process, where one test releases the
//! lock while another forks a command.
//!
//! So the code that starts a command holds [`spawning`] from fork to exec
//! (the spawn call returns once the exec happened), and a released lock
//! waits in [`settled`] for the spawns that began while it was held. In a
//! build that is not a test both are empty.

#[cfg(test)]
static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Held while a command is being forked and has not execed yet.
#[must_use = "the command is started while this is held"]
pub(crate) struct Spawning {
    #[cfg(test)]
    _gate: std::sync::MutexGuard<'static, ()>,
}

pub(crate) fn spawning() -> Spawning {
    Spawning {
        #[cfg(test)]
        _gate: GATE.lock().unwrap_or_else(|e| e.into_inner()),
    }
}

/// Returns once no command forked before this call is still short of its
/// exec. Called after a lock's descriptor is closed: a command forked later
/// has no copy of it.
pub(crate) fn settled() {
    #[cfg(test)]
    drop(GATE.lock().unwrap_or_else(|e| e.into_inner()));
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{NodePaths, secrets::KeysLock};
    use std::os::unix::process::CommandExt;

    /// A command forked while the lock is held, and slow to exec, must not
    /// keep the lock once its holder released it: the lock is free when the
    /// release returns.
    #[test]
    fn a_released_lock_is_free_while_a_command_is_still_starting() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let lock = KeysLock::try_take(&paths).unwrap().unwrap();
        let mut fds = [0; 2];
        // SAFETY: a pipe into a local array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let [read, write] = fds;
        let starter = std::thread::spawn(move || {
            let mut c = std::process::Command::new("true");
            // SAFETY: plain system calls only, between fork and exec: it
            // says it is forked, then takes its time to exec.
            unsafe {
                c.pre_exec(move || {
                    libc::write(write, [1u8].as_ptr().cast(), 1);
                    libc::usleep(500_000);
                    Ok(())
                });
            }
            let _spawning = spawning();
            c.spawn().unwrap().wait().unwrap()
        });
        let mut forked = [0u8];
        // SAFETY: reads one byte into a local.
        assert_eq!(
            unsafe { libc::read(read, forked.as_mut_ptr().cast(), 1) },
            1
        );
        drop(lock);
        assert!(
            KeysLock::try_take(&paths).unwrap().is_some(),
            "the lock is still held by the command that was forked meanwhile"
        );
        assert!(starter.join().unwrap().success());
        // SAFETY: the descriptors this test made.
        unsafe {
            libc::close(read);
            libc::close(write);
        }
    }
}
