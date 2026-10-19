//! One window of the app for each user: a second start, or a `nerve://`
//! link the desktop opens with the app, goes to the window that is open
//! already. The first start listens on a socket only its user can reach
//! (in `$XDG_RUNTIME_DIR` on Linux, a named pipe open to that user on
//! Windows); a later start sends it one line, `{"link": …}` or `{}`, and
//! ends.

use std::io::{BufRead, BufReader, Write};

use serde_json::{Value, json};

/// What a start of the app does.
pub enum Claimed {
    /// It is the first: it opens the window and listens.
    First(Instance),
    /// An open window took the start.
    Forwarded,
}

/// What a later start asks of the open window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The `nerve://` link it was opened with.
    pub link: Option<String>,
}

fn line(link: Option<&str>) -> String {
    match link {
        Some(l) => json!({ "link": l }).to_string(),
        None => json!({}).to_string(),
    }
}

fn asked(line: &str) -> Option<Asked> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    Some(Asked {
        link: v["link"].as_str().map(str::to_string),
    })
}

/// Claims the app for this user, or hands `link` to the window that has it.
/// Where no place for the socket is known, every start opens a window.
pub fn claim(link: Option<&str>) -> Claimed {
    #[cfg(unix)]
    {
        let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) else {
            return Claimed::First(Instance::none());
        };
        unix::claim_at(
            &std::path::Path::new(&dir).join("nerve-node-desktop.sock"),
            link,
        )
    }
    #[cfg(windows)]
    {
        win::claim(link)
    }
}

/// The open window's claim; it ends, and lets another start have it, when
/// this is dropped.
pub struct Instance {
    #[cfg(unix)]
    listener: Option<(std::os::unix::net::UnixListener, std::path::PathBuf)>,
    #[cfg(windows)]
    pipe: Option<win::Pipe>,
}

impl Instance {
    fn none() -> Instance {
        Instance {
            #[cfg(unix)]
            listener: None,
            #[cfg(windows)]
            pipe: None,
        }
    }

    /// Hands what each later start asks to `on`, on a thread of its own.
    pub fn listen(&self, on: impl Fn(Asked) + Send + Sync + 'static) {
        #[cfg(unix)]
        if let Some((l, _)) = &self.listener
            && let Ok(l) = l.try_clone()
        {
            std::thread::spawn(move || {
                for conn in l.incoming() {
                    let Ok(conn) = conn else { break };
                    let mut text = String::new();
                    if BufReader::new(conn).read_line(&mut text).is_ok()
                        && let Some(a) = asked(&text)
                    {
                        on(a);
                    }
                }
            });
        }
        #[cfg(windows)]
        if let Some(p) = &self.pipe {
            p.listen(Box::new(move |text: String| {
                if let Some(a) = asked(&text) {
                    on(a);
                }
            }));
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some((_, path)) = self.listener.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    use super::*;

    /// [`claim`] with the socket at `path`.
    pub fn claim_at(path: &Path, link: Option<&str>) -> Claimed {
        if let Ok(mut s) = UnixStream::connect(path)
            && writeln!(s, "{}", line(link)).is_ok()
        {
            return Claimed::Forwarded;
        }
        // Nobody listens: a socket left by a window that crashed goes.
        let _ = std::fs::remove_file(path);
        match UnixListener::bind(path) {
            Ok(l) => Claimed::First(Instance {
                listener: Some((l, path.to_path_buf())),
            }),
            Err(_) => Claimed::First(Instance::none()),
        }
    }
}

#[cfg(windows)]
mod win {
    use std::os::windows::io::FromRawHandle;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use super::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The first instance of the pipe, and its name and owner.
    pub struct Pipe {
        name: String,
        sid: String,
        first: std::sync::Mutex<Option<isize>>,
    }

    /// An instance of the pipe, open to SYSTEM, the administrators and
    /// this user only; the first one owns the name.
    fn make(name: &str, sid: &str, first: bool) -> Option<isize> {
        let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})"));
        // SAFETY: the descriptor Windows makes from the SDDL is freed after
        // the pipe took it.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return None;
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let flags = PIPE_ACCESS_INBOUND
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            let h = CreateNamedPipeW(
                wide(name).as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                0,
                4096,
                0,
                &sa,
            );
            LocalFree(sd as HLOCAL);
            (h != INVALID_HANDLE_VALUE).then_some(h as isize)
        }
    }

    pub fn claim(link: Option<&str>) -> Claimed {
        let Ok(sid) = crate::broker::win::own_sid() else {
            return Claimed::First(Instance::none());
        };
        let name = format!(r"\\.\pipe\nerve-node-desktop-{sid}");
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&name)
            && writeln!(f, "{}", line(link)).is_ok()
        {
            return Claimed::Forwarded;
        }
        match make(&name, &sid, true) {
            Some(h) => Claimed::First(Instance {
                pipe: Some(Pipe {
                    name,
                    sid,
                    first: std::sync::Mutex::new(Some(h)),
                }),
            }),
            None => Claimed::First(Instance::none()),
        }
    }

    impl Pipe {
        pub fn listen(&self, on: Box<dyn Fn(String) + Send + Sync>) {
            let Some(mut h) = self.first.lock().unwrap_or_else(|p| p.into_inner()).take() else {
                return;
            };
            let (name, sid) = (self.name.clone(), self.sid.clone());
            std::thread::spawn(move || {
                loop {
                    // SAFETY: an instance of the pipe this process made.
                    let ok = unsafe { ConnectNamedPipe(h as _, std::ptr::null_mut()) } != 0
                        // ERROR_PIPE_CONNECTED: the client came first;
                        // ERROR_NO_DATA: and has gone already, its line
                        // still there to read.
                        || matches!(unsafe { GetLastError() }, 535 | 232);
                    // The next instance first, so the name stays this app's.
                    let next = make(&name, &sid, false);
                    if ok {
                        // SAFETY: the instance's handle, owned by the File.
                        let f = unsafe { std::fs::File::from_raw_handle(h as _) };
                        let mut text = String::new();
                        if BufReader::new(f).read_line(&mut text).is_ok() {
                            on(text);
                        }
                    } else {
                        // SAFETY: the instance this process made.
                        unsafe { CloseHandle(h as _) };
                    }
                    match next {
                        Some(n) => h = n,
                        None => return,
                    }
                }
            });
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_second_start_goes_to_the_first() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("app.sock");
        let Claimed::First(first) = unix::claim_at(&sock, None) else {
            panic!("the first start is the first");
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        first.listen(move |a| {
            let _ = tx.lock().unwrap().send(a);
        });
        assert!(matches!(
            unix::claim_at(&sock, Some("nerve://pair?center=x")),
            Claimed::Forwarded
        ));
        let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(got.link.as_deref(), Some("nerve://pair?center=x"));
        assert!(matches!(unix::claim_at(&sock, None), Claimed::Forwarded));
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .unwrap()
                .link,
            None
        );
        // Gone with the window: the next start is the first again, also
        // over a socket a crash left.
        drop(first);
        assert!(!sock.exists());
        std::os::unix::net::UnixListener::bind(&sock)
            .map(drop)
            .unwrap();
        assert!(matches!(unix::claim_at(&sock, None), Claimed::First(_)));
    }
}

#[cfg(all(test, windows))]
mod win_tests {
    use super::*;

    /// On the user's own pipe: run where the app is not open.
    #[test]
    fn a_second_start_goes_to_the_first_over_the_pipe() {
        let Claimed::First(first) = claim(None) else {
            panic!("the app is open: close it to run this test");
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        first.listen(move |a| {
            let _ = tx.lock().unwrap().send(a);
        });
        for link in [
            Some("nerve://pair?center=x"),
            None,
            Some("nerve://pair?center=y"),
        ] {
            assert!(matches!(claim(link), Claimed::Forwarded));
            let got = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert_eq!(got.link.as_deref(), link);
        }
    }
}
