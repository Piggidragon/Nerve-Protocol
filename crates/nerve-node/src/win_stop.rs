//! How a command's processes on Windows are asked to end on their own
//! before its job ends them (crate::job): on a timeout and on `exec.signal`
//! with `term` or `int`. Windows has no signals. A console program hears
//! Ctrl+C, which goes to every process on its console, and a program with a
//! window is asked to close it (WM_CLOSE), as `taskkill` without `/F` asks.
//!
//! The node does neither itself. Sending Ctrl+C means taking the console of
//! the process, and a process has one console at a time: the node's own
//! (when it runs in a terminal) must stay its own, and two stops at once
//! would take each other's. So the node starts a helper, this same program
//! with [`STOP_ARG`], which leaves its console, takes the console of each
//! process it is given in turn, sends Ctrl+C there, and posts WM_CLOSE to
//! their windows on its desktop. Its exit code says whether it asked any.
//!
//! The pids the helper gets are processes in the command's job that the node
//! holds open until the helper has ended, so none of them names another
//! process meanwhile. A console the node itself is on is sent nothing. A
//! command of another account (crate::win_user) is asked by a helper started
//! with that account's token: the node may not open that account's
//! processes, and the command's windows are on that account's desktop.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Once};
use std::time::Duration;

use windows_sys::Win32::Foundation::{HANDLE, HWND, LPARAM, STILL_ACTIVE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    AttachConsole, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleProcessList,
    SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{
    DETACHED_PROCESS, GetExitCodeProcess, GetProcessId, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GW_OWNER, GetWindow, GetWindowThreadProcessId, IsWindowVisible, PostMessageW,
    WM_CLOSE,
};
use windows_sys::core::BOOL;

use crate::win::Job;
use crate::win_user::Token;

/// The argument that makes this program the helper. It is not a command the
/// owner types, so `main` checks it before clap.
pub const STOP_ARG: &str = "__exec-stop";

/// How long the node waits for the helper; one that takes longer is ended.
const HELPER_WAIT: Duration = Duration::from_secs(5);

/// How the node starts the helper for one command.
pub enum Asker {
    /// As the node itself: `exe`, this program.
    Own(PathBuf),
    /// As the account the command runs as, with `token`, the command's own.
    As(PathBuf, Arc<Token>),
}

/// Lets the commands the node starts from now on hear Ctrl+C. Whether a
/// process ignores Ctrl+C passes on to the processes it starts, also through
/// a console of their own, and a node may be started with it ignored (as
/// over ssh, or by cmd's `start /b`): none of its commands could then be
/// asked to end. So the node stops ignoring it before its first command.
/// Ctrl+C on the node's own console then reaches the node too, which ends
/// as it does in a terminal.
pub fn hear_ctrl_c() {
    static ONCE: Once = Once::new();
    // SAFETY: a plain call that sets this process's own Ctrl+C state.
    ONCE.call_once(|| unsafe {
        SetConsoleCtrlHandler(None, 0);
    });
}

/// Asks the processes in `job` to end (blocking, up to [`HELPER_WAIT`]);
/// whether any may have been asked. `shell` is a handle to the command's
/// shell, which the node holds since the start: it can be asked also when
/// it is a process the node could not open now.
pub fn ask(job: &Job, shell: Option<&OwnedHandle>, asker: &Asker) -> bool {
    // Held open until the helper has ended: a pid of an open process is not
    // given to another one.
    let mut held: Vec<OwnedHandle> = Vec::new();
    let mut pids: Vec<u32> = Vec::new();
    if let Some(h) = shell {
        let raw = h.as_raw_handle() as HANDLE;
        if running(raw) && job.holds(raw) {
            // SAFETY: an open process handle.
            pids.push(unsafe { GetProcessId(raw) });
        }
    }
    for pid in job.pids() {
        if pids.contains(&pid) {
            continue;
        }
        // SAFETY: OpenProcess takes plain values and returns null on failure.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            continue;
        }
        // SAFETY: OpenProcess returned a handle this code now owns.
        let p = unsafe { OwnedHandle::from_raw_handle(raw as _) };
        // Opened after the list was taken, so it may be another process by
        // now; one in the job is the command's.
        if running(raw) && job.holds(raw) {
            pids.push(pid);
            held.push(p);
        }
    }
    if pids.is_empty() {
        return false;
    }
    let mut args = vec![STOP_ARG.to_string(), std::process::id().to_string()];
    args.extend(pids.iter().map(u32::to_string));
    let asked = match asker {
        Asker::Own(exe) => helper(exe, &args),
        Asker::As(exe, token) => {
            let line = crate::exec::windows_command_line(&exe.to_string_lossy(), &args);
            match crate::win_user::run_capture(token, &line, HELPER_WAIT) {
                Ok((code, _)) => code != 0,
                // It ran and may have asked.
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => true,
                Err(e) => {
                    tracing::warn!("cannot ask a command to end, it is ended at once: {e}");
                    false
                }
            }
        }
    };
    drop(held);
    asked
}

/// Runs the helper as the node itself, without a console, and waits for it.
fn helper(exe: &Path, args: &[String]) -> bool {
    let child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "cannot ask a command to end, it is ended at once: {}: {e}",
                exe.display()
            );
            return false;
        }
    };
    let ms = u32::try_from(HELPER_WAIT.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the child's handle is open while `child` lives.
    let waited = unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, ms) };
    if waited != WAIT_OBJECT_0 {
        let _ = child.kill();
        let _ = child.wait();
        // It ran and may have asked.
        return true;
    }
    child.wait().is_ok_and(|s| s.code() != Some(0))
}

/// Whether the process behind `h` still runs.
fn running(h: HANDLE) -> bool {
    let mut code = 0u32;
    // SAFETY: an open process handle and a place for the code.
    unsafe { GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32 }
}

/// The helper: `STOP_ARG <node pid> <pid>...`. Posts WM_CLOSE to the
/// visible top-level windows of the pids and sends Ctrl+C to each console
/// one of them is on, but not to one the node is on. Its exit code is how
/// many it asked, 0 for none.
pub fn helper_main() -> i32 {
    let nums: Vec<u32> = std::env::args()
        .skip(2)
        .filter_map(|a| a.parse().ok())
        .collect();
    let Some((&node, pids)) = nums.split_first() else {
        return 0;
    };
    let mut asked = close_windows(pids);
    let mut done: Vec<u32> = Vec::new();
    // SAFETY: plain calls on this process's console. The helper ignores the
    // Ctrl+C it sends, which reaches it too while it is on that console.
    unsafe {
        FreeConsole();
        for &pid in pids {
            if done.contains(&pid) || AttachConsole(pid) == 0 {
                continue;
            }
            SetConsoleCtrlHandler(None, 1);
            let on = console_pids();
            if !on.contains(&node) && GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) != 0 {
                asked += 1;
            }
            done.extend(on);
            FreeConsole();
        }
    }
    asked.min(100) as i32
}

/// The pids on the console this process is on.
fn console_pids() -> Vec<u32> {
    let mut buf = vec![0u32; 64];
    loop {
        // SAFETY: the buffer is valid for its length.
        let n = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n <= buf.len() {
            buf.truncate(n);
            return buf;
        }
        buf = vec![0u32; n + 16];
    }
}

/// Posts WM_CLOSE to the visible windows without an owner, the ones a user
/// would close, of the processes `pids`; how many.
fn close_windows(pids: &[u32]) -> u32 {
    struct Seen<'a> {
        pids: &'a [u32],
        closed: u32,
    }
    unsafe extern "system" fn each(w: HWND, seen: LPARAM) -> BOOL {
        // SAFETY: `seen` is the `Seen` that EnumWindows was given, alive
        // for the call, and `w` a window it enumerates.
        unsafe {
            let seen = &mut *(seen as *mut Seen);
            let mut pid = 0u32;
            GetWindowThreadProcessId(w, &mut pid);
            if seen.pids.contains(&pid)
                && IsWindowVisible(w) != 0
                && GetWindow(w, GW_OWNER).is_null()
                && PostMessageW(w, WM_CLOSE, 0, 0) != 0
            {
                seen.closed += 1;
            }
        }
        1
    }
    let mut seen = Seen { pids, closed: 0 };
    // SAFETY: the callback reads `seen` only during the call.
    unsafe { EnumWindows(Some(each), (&raw mut seen) as LPARAM) };
    seen.closed
}
