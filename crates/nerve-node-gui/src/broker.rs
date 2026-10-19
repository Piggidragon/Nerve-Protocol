//! The elevated broker: on a node installed as a service the node's files
//! are root's (the administrators' on Windows), so every command needs the
//! rights the owner gives in a terminal with `sudo`. The app asks for them
//! once, the way the desktop does (polkit's `pkexec` on Linux, the UAC
//! prompt on Windows), and starts this program elevated as the broker. The
//! broker runs the app's commands as `nerve-node --json …` (this program,
//! nothing else) and sends back what each answered, until the app ends.
//!
//! The app and the broker speak JSON lines. A request is
//! `{"id", "args", "input", "follow"}` or `{"id", "cancel": true}`; the
//! broker answers `{"id", "line"}` for each line of a command that keeps
//! running and `{"id", "done": {"ok", "code", "stdout", "stderr"}}` when it
//! ends. Its first line is `{"hello": …}`, so the app knows it runs.
//!
//! Only the app reaches the broker: on Linux over the broker's stdin and
//! stdout, which pkexec hands from the app; on Windows over a named pipe
//! the broker makes, open to the app's user only, which it serves to the
//! app's process alone (`win`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use serde_json::{Value, json};

use crate::runner::{Follow, Output, follow_process, run_process};

/// The argument that starts this program as the broker.
pub const ARG: &str = "__gui-broker";

const HELLO: &str = "nerve-node-gui broker";

type Out = Arc<Mutex<Box<dyn Write + Send>>>;

fn send(out: &Out, v: &Value) -> bool {
    let mut o = out.lock().unwrap_or_else(|p| p.into_inner());
    writeln!(o, "{v}").and_then(|_| o.flush()).is_ok()
}

fn done(o: &Output) -> Value {
    json!({
        "ok": o.ok,
        "code": o.code,
        "stdout": String::from_utf8_lossy(&o.stdout),
        "stderr": String::from_utf8_lossy(&o.stderr),
    })
}

fn output_of(v: &Value) -> Output {
    Output {
        ok: v["ok"] == true,
        code: v["code"].as_i64().map(|c| c as i32),
        stdout: v["stdout"].as_str().unwrap_or_default().as_bytes().to_vec(),
        stderr: v["stderr"].as_str().unwrap_or_default().as_bytes().to_vec(),
    }
}

/// The broker's side: answers the requests on `input` with `exe`, the
/// program itself, until `input` ends; then ends what still runs.
pub fn serve(input: impl Read, output: Box<dyn Write + Send>, exe: PathBuf) {
    let out: Out = Arc::new(Mutex::new(output));
    if !send(&out, &json!({ "hello": HELLO })) {
        return;
    }
    let follows: Arc<Mutex<HashMap<u64, Follow>>> = Arc::default();
    for line in BufReader::new(input).lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = req["id"].as_u64() else {
            continue;
        };
        if req["cancel"] == true {
            follows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            continue;
        }
        let args: Vec<String> = req["args"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(str::to_string))
            .collect();
        // Commands of the node only: its options first, never one of the
        // helpers this program also is (the exec shim, this broker).
        if !args.first().is_some_and(|a| a.starts_with("--")) {
            let refused = Output {
                stderr: b"the broker runs nerve-node commands only".to_vec(),
                ..Output::default()
            };
            send(&out, &json!({ "id": id, "done": done(&refused) }));
            continue;
        }
        let input = req["input"].as_str().map(str::to_string);
        let (out, exe) = (out.clone(), exe.clone());
        if req["follow"] == true {
            let (o1, o2) = (out.clone(), out.clone());
            let follow = follow_process(
                &exe,
                &args,
                Box::new(move |line| {
                    send(&o1, &json!({ "id": id, "line": line }));
                }),
                Box::new(move |end| {
                    send(&o2, &json!({ "id": id, "done": done(&end) }));
                }),
            );
            match follow {
                Ok(f) => {
                    follows
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(id, f);
                }
                Err(e) => {
                    let failed = Output {
                        stderr: e.into_bytes(),
                        ..Output::default()
                    };
                    send(&out, &json!({ "id": id, "done": done(&failed) }));
                }
            }
            continue;
        }
        std::thread::spawn(move || {
            let o = run_process(&exe, &args, input.as_deref()).unwrap_or_else(|e| Output {
                stderr: e.into_bytes(),
                ..Output::default()
            });
            send(&out, &json!({ "id": id, "done": done(&o) }));
        });
    }
    // The app ended: so does every command that keeps running.
    follows.lock().unwrap_or_else(|p| p.into_inner()).clear();
}

enum Msg {
    Line(String),
    Done(Output),
    Gone,
}

/// The app's side of the broker.
pub struct Client {
    out: Out,
    waiting: Arc<Mutex<HashMap<u64, mpsc::Sender<Msg>>>>,
    next: AtomicU64,
    alive: Arc<AtomicBool>,
    // The broker's process, kept while the app talks to it.
    _process: Mutex<Option<std::process::Child>>,
}

/// Why a command did not go through the broker.
pub const GONE: &str = "the administrator rights ended; give them again to go on";

impl Client {
    /// Talks to a broker over `input` and `output`, once it said hello.
    pub fn start(
        input: Box<dyn Read + Send>,
        output: Box<dyn Write + Send>,
        process: Option<std::process::Child>,
    ) -> Result<Arc<Client>, String> {
        let mut lines = BufReader::new(input).lines();
        // Until the owner answered the system's question.
        match lines.next() {
            Some(Ok(l)) if serde_json::from_str::<Value>(&l).is_ok_and(|v| v["hello"] == HELLO) => {
            }
            _ => return Err("the administrator rights were not given".into()),
        }
        let waiting: Arc<Mutex<HashMap<u64, mpsc::Sender<Msg>>>> = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        {
            let (waiting, alive) = (waiting.clone(), alive.clone());
            std::thread::spawn(move || {
                for line in lines {
                    let Ok(line) = line else { break };
                    let Ok(v) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    let Some(id) = v["id"].as_u64() else {
                        continue;
                    };
                    let mut w = waiting.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(l) = v["line"].as_str() {
                        if let Some(tx) = w.get(&id) {
                            let _ = tx.send(Msg::Line(l.to_string()));
                        }
                    } else if v.get("done").is_some()
                        && let Some(tx) = w.remove(&id)
                    {
                        let _ = tx.send(Msg::Done(output_of(&v["done"])));
                    }
                }
                alive.store(false, Ordering::SeqCst);
                for (_, tx) in waiting.lock().unwrap_or_else(|p| p.into_inner()).drain() {
                    let _ = tx.send(Msg::Gone);
                }
            });
        }
        Ok(Arc::new(Client {
            out: Arc::new(Mutex::new(output)),
            waiting,
            next: AtomicU64::new(1),
            alive,
            _process: Mutex::new(process),
        }))
    }

    /// Whether the broker still answers.
    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    fn ask(
        &self,
        args: Vec<String>,
        input: Option<&str>,
        follow: bool,
    ) -> Result<(u64, mpsc::Receiver<Msg>), String> {
        if !self.alive() {
            return Err(GONE.into());
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.waiting
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, tx);
        let req = json!({ "id": id, "args": args, "input": input, "follow": follow });
        if !send(&self.out, &req) {
            self.waiting
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            return Err(GONE.into());
        }
        Ok((id, rx))
    }

    /// Runs one command and waits for its end.
    pub fn run(&self, args: Vec<String>, input: Option<&str>) -> Result<Output, String> {
        let (_, rx) = self.ask(args, input, false)?;
        loop {
            match rx.recv() {
                Ok(Msg::Done(o)) => return Ok(o),
                Ok(Msg::Line(_)) => {}
                Ok(Msg::Gone) | Err(_) => return Err(GONE.into()),
            }
        }
    }

    /// Runs a command that keeps answering; see [`follow_process`].
    pub fn follow(
        self: &Arc<Self>,
        args: Vec<String>,
        mut on_line: Box<dyn FnMut(String) + Send>,
        on_end: Box<dyn FnOnce(Output) + Send>,
    ) -> Result<Follow, String> {
        let (id, rx) = self.ask(args, None, true)?;
        let stopped = Arc::new(AtomicBool::new(false));
        {
            let stopped = stopped.clone();
            std::thread::spawn(move || {
                loop {
                    match rx.recv() {
                        Ok(Msg::Line(l)) if !stopped.load(Ordering::SeqCst) => on_line(l),
                        Ok(Msg::Line(_)) => {}
                        Ok(Msg::Done(o)) => {
                            if !stopped.load(Ordering::SeqCst) {
                                on_end(o);
                            }
                            return;
                        }
                        Ok(Msg::Gone) | Err(_) => {
                            if !stopped.load(Ordering::SeqCst) {
                                on_end(Output {
                                    stderr: GONE.as_bytes().to_vec(),
                                    ..Output::default()
                                });
                            }
                            return;
                        }
                    }
                }
            });
        }
        let me = self.clone();
        Ok(Follow::new(Box::new(move || {
            stopped.store(true, Ordering::SeqCst);
            me.waiting
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
            send(&me.out, &json!({ "id": id, "cancel": true }));
        })))
    }
}

/// How the broker is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// With the rights the desktop gives after asking.
    Elevated,
    /// As this user, for tests: the same broker, no question.
    Plain,
}

/// Starts this program as the broker and talks to it.
pub fn launch(exe: &Path, how: Launch) -> Result<Arc<Client>, String> {
    // Windows starts the broker without the app's stdin and stdout when it
    // asks for the rights, so it talks over pipes either way.
    #[cfg(windows)]
    return win::launch(exe, how == Launch::Elevated);
    #[cfg(not(windows))]
    launch_stdio(exe, how)
}

/// The broker on its stdin and stdout, which pkexec hands on.
#[cfg(not(windows))]
fn launch_stdio(exe: &Path, how: Launch) -> Result<Arc<Client>, String> {
    use std::process::{Command, Stdio};
    let mut cmd = match how {
        // pkexec hands its stdin and stdout to the program, and asks with
        // the desktop's polkit agent.
        Launch::Elevated => {
            let mut c = Command::new("pkexec");
            c.arg(exe);
            c
        }
        Launch::Plain => Command::new(exe),
    };
    let mut child = cmd
        .arg(ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| match how {
            Launch::Elevated => format!(
                "cannot ask for administrator rights: pkexec did not start ({e}); is polkit installed?"
            ),
            Launch::Plain => format!("cannot start the broker: {e}"),
        })?;
    let input = child.stdout.take().expect("piped");
    let output = child.stdin.take().expect("piped");
    Client::start(Box::new(input), Box::new(output), Some(child))
}

/// The broker's start: `__gui-broker`, on Windows with the pipe's name and
/// the app's process id. The exit code.
pub fn main(args: &[String]) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return 1,
    };
    #[cfg(windows)]
    if let [name, pid] = args {
        return win::serve_pipe(name, pid, exe);
    }
    if !args.is_empty() {
        return 2;
    }
    serve(std::io::stdin(), Box::new(std::io::stdout()), exe);
    0
}

/// The broker over a named pipe on Windows, where the UAC prompt starts a
/// program without handing it the app's stdin and stdout.
#[cfg(windows)]
mod win {
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_ATTRIBUTES, PIPE_ACCESS_INBOUND,
        PIPE_ACCESS_OUTBOUND,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessId, OpenProcessToken, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use super::Client;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// The SID of the user this process runs as, as text.
    fn own_sid() -> Result<String, String> {
        // SAFETY: the token of this process, read into a buffer of the size
        // Windows asks for; the strings it allocates are freed.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(format!("the process token: error {}", GetLastError()));
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(format!("the token's user: error {}", GetLastError()));
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
                return Err(format!("the user's SID: error {}", GetLastError()));
            }
            let n = (0..).take_while(|i| *text.add(*i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
            LocalFree(text as HLOCAL);
            Ok(sid)
        }
    }

    /// One end of the broker: a pipe one way, open to SYSTEM, the
    /// administrators and this user alone, connected to the app's process
    /// (`app`) only. Each way has a pipe of its own: a synchronous pipe
    /// handle reads and writes one at a time, so a read that waits would
    /// hold up every write.
    fn serve_end(name: &str, sid: &str, inbound: bool, app: u32) -> Option<std::fs::File> {
        let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})"));
        // SAFETY: the descriptor Windows makes from the SDDL is freed after
        // the pipe took it; the handle becomes the File returned.
        let handle = unsafe {
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
            let way = if inbound {
                PIPE_ACCESS_INBOUND
            } else {
                PIPE_ACCESS_OUTBOUND
            };
            let h = CreateNamedPipeW(
                wide(name).as_ptr(),
                way | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &sa,
            );
            LocalFree(sd as HLOCAL);
            if h == INVALID_HANDLE_VALUE {
                return None;
            }
            // ERROR_PIPE_CONNECTED: the client came before this call.
            if ConnectNamedPipe(h, std::ptr::null_mut()) == 0 && GetLastError() != 535 {
                CloseHandle(h);
                return None;
            }
            let mut client = 0u32;
            if GetNamedPipeClientProcessId(h, &mut client) == 0 || client != app {
                CloseHandle(h);
                return None;
            }
            h
        };
        // SAFETY: the pipe's handle, owned by this File from here on.
        Some(unsafe { std::fs::File::from_raw_handle(handle as _) })
    }

    /// The broker over its two pipes, `<name>-in` and `<name>-out`.
    pub fn serve_pipe(name: &str, pid: &str, exe: PathBuf) -> i32 {
        let Ok(app) = pid.parse::<u32>() else {
            return 2;
        };
        if !name.starts_with(r"\\.\pipe\nerve-gui-") {
            return 2;
        }
        let Ok(sid) = own_sid() else {
            return 1;
        };
        let Some(requests) = serve_end(&format!("{name}-in"), &sid, true, app) else {
            return 1;
        };
        let Some(answers) = serve_end(&format!("{name}-out"), &sid, false, app) else {
            return 1;
        };
        super::serve(requests, Box::new(answers), exe);
        0
    }

    /// Opens one end of the broker's pipes once it is there, as long as the
    /// broker runs, and makes sure the broker made it.
    fn open_end(
        name: &str,
        inbound: bool,
        broker: u32,
        running: &dyn Fn() -> bool,
    ) -> Result<std::fs::File, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let file = loop {
            let mut o = std::fs::OpenOptions::new();
            if inbound {
                // Writing, and the attributes the check below reads.
                o.access_mode(GENERIC_WRITE | FILE_READ_ATTRIBUTES);
            } else {
                o.read(true);
            }
            match o.open(name) {
                Ok(f) => break f,
                Err(e) if !running() => {
                    return Err(format!("the broker ended before it answered: {e}"));
                }
                Err(e) if std::time::Instant::now() > deadline => {
                    return Err(format!("the broker did not answer: {e}"));
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        };
        // The pipe must be the broker's, not one another process made of
        // the same name.
        let mut server = 0u32;
        // SAFETY: a query on the open pipe.
        let ok =
            unsafe { GetNamedPipeServerProcessId(file.as_raw_handle() as HANDLE, &mut server) };
        if ok == 0 || server != broker {
            return Err("the pipe is not the broker's".into());
        }
        Ok(file)
    }

    /// Starts this program as the broker, with the UAC prompt when
    /// `elevated`, and talks to it over its pipes.
    pub fn launch(exe: &Path, elevated: bool) -> Result<Arc<Client>, String> {
        let name = format!(
            r"\\.\pipe\nerve-gui-{}",
            nerve_transport::keys::random_token(24)
        );
        let args = format!("{} {name} {}", super::ARG, std::process::id());
        let (process, child) = if elevated {
            let params = wide(&args);
            let file = wide(&exe.display().to_string());
            let verb = wide("runas");
            // SAFETY: a filled SHELLEXECUTEINFOW whose strings live until the
            // call returns; the process handle it gives is closed below.
            let process = unsafe {
                let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
                info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
                info.fMask = SEE_MASK_NOCLOSEPROCESS;
                info.lpVerb = verb.as_ptr();
                info.lpFile = file.as_ptr();
                info.lpParameters = params.as_ptr();
                info.nShow = SW_HIDE;
                if ShellExecuteExW(&mut info) == 0 {
                    // ERROR_CANCELLED: the owner said no.
                    return Err(if GetLastError() == 1223 {
                        "the administrator rights were not given".into()
                    } else {
                        format!(
                            "cannot ask for administrator rights: error {}",
                            GetLastError()
                        )
                    });
                }
                info.hProcess
            };
            (process, None)
        } else {
            use std::os::windows::io::AsRawHandle;
            use std::process::{Command, Stdio};
            let child = Command::new(exe)
                .args([super::ARG, &name, &std::process::id().to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("cannot start the broker: {e}"))?;
            (child.as_raw_handle() as HANDLE, Some(child))
        };
        // SAFETY: queries on the broker's process handle, which lives until
        // it is closed below (or, for a child, with the child).
        let broker = unsafe { GetProcessId(process) };
        let running = || unsafe { WaitForSingleObject(process, 0) } != 0;
        let ends = open_end(&format!("{name}-in"), true, broker, &running).and_then(|i| {
            Ok((
                i,
                open_end(&format!("{name}-out"), false, broker, &running)?,
            ))
        });
        if child.is_none() {
            unsafe { CloseHandle(process) };
        }
        let (requests, answers) = ends?;
        Client::start(Box::new(answers), Box::new(requests), child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe in memory: what one side writes, the other reads.
    fn pipe() -> (std::io::PipeReader, std::io::PipeWriter) {
        std::io::pipe().unwrap()
    }

    #[test]
    fn the_broker_refuses_anything_but_a_node_command() {
        let (req_r, mut req_w) = pipe();
        let (ans_r, ans_w) = pipe();
        // A program that is not this one would be refused before it ran;
        // here nothing must run at all.
        let t = std::thread::spawn(move || {
            serve(
                req_r,
                Box::new(ans_w),
                PathBuf::from("/nonexistent/program"),
            )
        });
        writeln!(req_w, "{}", json!({"id": 7, "args": ["__exec-shim", "x"]})).unwrap();
        drop(req_w);
        let lines: Vec<Value> = BufReader::new(ans_r)
            .lines()
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect();
        t.join().unwrap();
        assert_eq!(lines[0]["hello"], HELLO);
        assert_eq!(lines[1]["id"], 7);
        assert!(
            lines[1]["done"]["stderr"]
                .as_str()
                .unwrap()
                .contains("commands only")
        );
    }

    #[test]
    fn a_client_without_hello_has_no_rights() {
        let (r, w) = pipe();
        drop(w);
        let (_r2, w2) = pipe();
        let e = Client::start(Box::new(r), Box::new(w2), None)
            .err()
            .unwrap();
        assert!(e.contains("not given"), "{e}");
    }
}
