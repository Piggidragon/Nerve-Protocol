//! On Windows the app is a GUI program, so a double click opens no console
//! window behind it. Started with arguments from a terminal, it takes that
//! terminal's console, so the CLI's output shows there; a program that
//! started it with pipes or a file (the app itself, a script) keeps them.

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};

fn none(h: HANDLE) -> bool {
    h.is_null() || h == INVALID_HANDLE_VALUE
}

/// Takes the console of the process that started this one, when this one
/// was given no output.
pub fn attach() {
    // SAFETY: plain calls on this process's own standard handles, with
    // NUL-terminated names.
    unsafe {
        if !none(GetStdHandle(STD_OUTPUT_HANDLE)) || AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        let ends: [(STD_HANDLE, &str); 3] = [
            (STD_INPUT_HANDLE, "CONIN$"),
            (STD_OUTPUT_HANDLE, "CONOUT$"),
            (STD_ERROR_HANDLE, "CONOUT$"),
        ];
        for (which, name) in ends {
            if !none(GetStdHandle(which)) {
                continue;
            }
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let h = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if !none(h) {
                SetStdHandle(which, h);
            }
        }
    }
}
