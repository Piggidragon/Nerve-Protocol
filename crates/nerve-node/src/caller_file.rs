//! The backup file of root's `backup` or `restore` on the installed node.
//! The command runs as the node's user ([`crate::service::become_owner`]),
//! who may not open the folders of whoever asked: a home folder is closed
//! to others, and a backup written there as the node's user would be that
//! user's, not the asker's. So the file is opened as the one who asked: the
//! user who ran `sudo`, or for whom pkexec started the desktop app's broker;
//! root itself where nobody else asked. A process forked before the switch,
//! while the command has one thread, does that for the command: it reads
//! the backup at once, or waits for the backup the command makes and writes
//! it.

use std::path::{Path, PathBuf};

/// What the command does with its file.
pub enum Job {
    Read(PathBuf),
    Write { path: PathBuf, overwrite: bool },
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::Job;

    /// What the process forked for the file did or will do.
    enum Kept {
        Read {
            path: PathBuf,
            bytes: Result<Vec<u8>, String>,
        },
        Write {
            path: PathBuf,
            overwrite: bool,
            to: std::fs::File,
            from: std::fs::File,
            pid: libc::pid_t,
        },
    }

    static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

    /// The user who asked root for the command: `sudo`'s, else pkexec's
    /// (the desktop app's broker), with that user's group. `None` for root
    /// itself.
    fn caller() -> Option<(u32, u32)> {
        let id = |k: &str| std::env::var(k).ok()?.trim().parse::<u32>().ok();
        let (uid, gid) = match (id("SUDO_UID"), id("SUDO_GID")) {
            (Some(u), Some(g)) => (u, g),
            _ => {
                let uid = id("PKEXEC_UID")?;
                (uid, group_of(uid)?)
            }
        };
        (uid != 0).then_some((uid, gid))
    }

    /// The group of `uid` in the account database, and its name.
    fn account(uid: u32) -> Option<(u32, std::ffi::CString)> {
        let mut buf = vec![0u8; 16 * 1024];
        // SAFETY: getpwuid_r writes into `pw` and `buf`, both ours and as
        // large as said; `found` points at `pw` or is null.
        unsafe {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            if libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut found) != 0
                || found.is_null()
            {
                return None;
            }
            Some((pw.pw_gid, std::ffi::CStr::from_ptr(pw.pw_name).to_owned()))
        }
    }

    fn group_of(uid: u32) -> Option<u32> {
        account(uid).map(|(g, _)| g)
    }

    /// Becomes `uid` with `gid` and the user's other groups (none for a uid
    /// the account database does not know), for good: real, effective and
    /// saved ids.
    fn become_caller(uid: u32, gid: u32) -> Result<(), String> {
        let name = account(uid).map(|(_, n)| n);
        // SAFETY: plain calls; `name` lives across initgroups.
        let failed = unsafe {
            (match &name {
                Some(n) => libc::initgroups(n.as_ptr(), gid),
                None => libc::setgroups(0, std::ptr::null()),
            }) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
        };
        if failed {
            return Err(format!(
                "cannot open the file as the user (uid {uid}) who asked: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn pipe() -> Result<(std::fs::File, std::fs::File), String> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(format!(
                "cannot make a pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: both are open, and nothing else owns them.
        unsafe {
            Ok((
                OwnedFd::from_raw_fd(fds[0]).into(),
                OwnedFd::from_raw_fd(fds[1]).into(),
            ))
        }
    }

    /// An answer over a pipe: `0` and the bytes, or `1` and the error.
    fn send(to: &mut std::fs::File, r: Result<Vec<u8>, String>) {
        let frame = match r {
            Ok(mut b) => {
                b.insert(0, b'0');
                b
            }
            Err(e) => [b"1".as_slice(), e.as_bytes()].concat(),
        };
        let _ = to.write_all(&frame);
    }

    fn receive(from: &mut std::fs::File) -> Result<Vec<u8>, String> {
        let mut frame = Vec::new();
        from.read_to_end(&mut frame)
            .map_err(|e| format!("the file's process: {e}"))?;
        match frame.split_first() {
            Some((b'0', bytes)) => Ok(bytes.to_vec()),
            Some((_, e)) => Err(String::from_utf8_lossy(e).into_owned()),
            None => Err("the process that opens the file ended without an answer".into()),
        }
    }

    fn wait(pid: libc::pid_t) {
        let mut status = 0;
        // SAFETY: the child is this process's.
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    pub fn prepare(job: Job) -> Result<(), String> {
        let caller = caller();
        let (mut answer_in, answer_out) = pipe()?;
        let (bytes_in, bytes_out) = match &job {
            Job::Read(_) => (None, None),
            Job::Write { .. } => {
                let (i, o) = pipe()?;
                (Some(i), Some(o))
            }
        };
        // SAFETY: `main` calls this while the process has one thread; the
        // child runs this module's code and leaves with _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!(
                "cannot start the process that opens the file: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            drop(answer_in);
            drop(bytes_out);
            let mut out = answer_out;
            let r = caller.map_or(Ok(()), |(u, g)| become_caller(u, g));
            match (job, r) {
                (_, Err(e)) => send(&mut out, Err(e)),
                (Job::Read(path), Ok(())) => {
                    send(&mut out, nerve_transport::backup::read_file(&path));
                }
                (Job::Write { path, overwrite }, Ok(())) => {
                    let mut bytes = Vec::new();
                    let read = bytes_in
                        .expect("a pipe for the bytes")
                        .read_to_end(&mut bytes);
                    // Nothing came: the command failed before it had a
                    // backup, and no file is made.
                    if read.is_ok() && !bytes.is_empty() {
                        let r = nerve_transport::backup::write_file(&path, &bytes, overwrite);
                        send(&mut out, r.map(|()| Vec::new()));
                    }
                }
            }
            drop(out);
            // SAFETY: leaves the child without running the parent's exit
            // handlers.
            unsafe { libc::_exit(0) };
        }
        drop(answer_out);
        drop(bytes_in);
        let kept = match job {
            Job::Read(path) => {
                let bytes = receive(&mut answer_in);
                wait(pid);
                Kept::Read { path, bytes }
            }
            Job::Write { path, overwrite } => Kept::Write {
                path,
                overwrite,
                to: bytes_out.expect("a pipe for the bytes"),
                from: answer_in,
                pid,
            },
        };
        *KEPT.lock().unwrap_or_else(|p| p.into_inner()) = Some(kept);
        Ok(())
    }

    /// What [`prepare`] read of `path`, once; `None` when it read nothing
    /// or another file.
    pub fn take_read(path: &Path) -> Option<Result<Vec<u8>, String>> {
        let mut kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
        match kept.take() {
            Some(Kept::Read { path: p, bytes }) if p == path => Some(bytes),
            other => {
                *kept = other;
                None
            }
        }
    }

    /// Writes `bytes` through the process [`prepare`] started for `path`;
    /// `None` when there is none for that file.
    pub fn take_write(path: &Path, bytes: &[u8], overwrite: bool) -> Option<Result<(), String>> {
        let mut kept = KEPT.lock().unwrap_or_else(|p| p.into_inner());
        match kept.take() {
            Some(Kept::Write {
                path: p,
                overwrite: o,
                mut to,
                mut from,
                pid,
            }) if p == path && o == overwrite => {
                let sent = to.write_all(bytes);
                drop(to);
                // The process's own error first: one that could not become
                // the user ends before it takes the bytes.
                let answer = receive(&mut from);
                wait(pid);
                Some(answer.and_then(|_| sent.map_err(|e| format!("the file's process: {e}"))))
            }
            other => {
                *kept = other;
                None
            }
        }
    }
}

/// Opens the file of `job` as the user who asked, before `main` makes the
/// command the node's user: reads it now, or starts the process that
/// writes it later ([`write`]). Called while the process has one thread.
pub fn prepare(job: Job) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return linux::prepare(job);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = job;
        Ok(())
    }
}

/// The backup at `path`: what [`prepare`] read as the user who asked, else
/// read now.
pub fn read(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "linux")]
    if let Some(r) = linux::take_read(path) {
        return r;
    }
    nerve_transport::backup::read_file(path)
}

/// Writes the backup to `path`: through the process [`prepare`] started as
/// the user who asked, else here.
pub fn write(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if let Some(r) = linux::take_write(path, bytes, overwrite) {
        return r;
    }
    nerve_transport::backup::write_file(path, bytes, overwrite)
}
