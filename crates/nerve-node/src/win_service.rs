//! `nerve-node run` under the Windows service control manager. The service
//! `install` registers starts the program with the installed folders; the
//! program then hands its main thread to the manager, which runs the node
//! on a thread of its own and stops it on request. The node says it runs
//! once it has started ([`running`]), so a service that runs is a node that
//! took its config; one that fails stops with exit code 1, and its log says
//! why.

use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

use crate::win_user::wide;
use crate::winsvc::SERVICE_NAME;

/// What the service runs: the command line's `run`.
type Body = Box<dyn FnOnce() -> Result<(), String> + Send>;

static BODY: Mutex<Option<Body>> = Mutex::new(None);
/// The handle the manager gave for this service's status, as a number:
/// set while the program runs as the service.
static STATUS: Mutex<Option<usize>> = Mutex::new(None);
/// Rung when the manager asks the service to stop.
static STOP: OnceLock<tokio::sync::Notify> = OnceLock::new();
/// Where a start that fails is logged.
static LOG: OnceLock<std::path::PathBuf> = OnceLock::new();

fn stop_bell() -> &'static tokio::sync::Notify {
    STOP.get_or_init(tokio::sync::Notify::new)
}

/// Runs `body` as the service when the service control manager started
/// this program, else as it is; its exit code. `log` is the node's log
/// file, where a start that fails is said.
pub fn serve(body: Body, log: std::path::PathBuf) -> i32 {
    let _ = LOG.set(log);
    *crate::daemon::lock(&BODY) = Some(body);
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: a table ended by an empty entry; it returns when the service
    // has stopped, or at once when no manager started this program.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
        return 0;
    }
    let e = std::io::Error::last_os_error();
    let body = crate::daemon::lock(&BODY).take();
    if e.raw_os_error() != Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) {
        eprintln!("nerve-node: cannot run as a service: {e}");
        return 1;
    }
    // Started from a terminal: the node runs there.
    match body.map(|b| b()) {
        Some(Err(e)) => {
            eprintln!("nerve-node: {e}");
            1
        }
        _ => 0,
    }
}

/// Whether this program runs as the service.
pub fn is_service() -> bool {
    crate::daemon::lock(&STATUS).is_some()
}

/// Tells the manager the node runs: called once it has started.
pub fn running() {
    report(SERVICE_RUNNING, 0);
}

/// Waits until the manager asks the service to stop.
pub async fn stop_requested() {
    stop_bell().notified().await;
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, code: u32) {
    let Some(h) = *crate::daemon::lock(&STATUS) else {
        return;
    };
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if code == 0 {
            NO_ERROR
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: code,
        dwCheckPoint: 0,
        // The node takes a few seconds at most to start or stop.
        dwWaitHint: 30_000,
    };
    // SAFETY: the handle the manager gave and a filled status.
    unsafe { SetServiceStatus(h as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(SERVICE_NAME);
    // SAFETY: a NUL-terminated name and a handler that lives as long as the
    // program.
    let h =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null()) };
    if h.is_null() {
        return;
    }
    *crate::daemon::lock(&STATUS) = Some(h as usize);
    report(SERVICE_START_PENDING, 0);
    let body = crate::daemon::lock(&BODY).take();
    let code = match body.map(|b| b()) {
        Some(Err(e)) => {
            // Nobody reads stderr here: the node's log file has it.
            if let (Some(log), Some(path)) = (nerve_transport::log::global(), LOG.get()) {
                let _ = log.attach_file(path);
            }
            tracing::error!("the service stopped: {e}");
            1
        }
        _ => 0,
    };
    report(SERVICE_STOPPED, code);
}

unsafe extern "system" fn control(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, 0);
            // A permit is kept when the node does not wait yet.
            stop_bell().notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
