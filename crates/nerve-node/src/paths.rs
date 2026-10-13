//! Where a node keeps its files, and the system folders its protected list
//! hangs off.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use nerve_policy::protected::{Platform, WinFolders};

/// The node's config directory (`node.toml`, keys) and state directory
/// (control socket, audit log, log, the config's MAC key). Tests point both at
/// temporary folders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePaths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl NodePaths {
    pub fn new(config_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> NodePaths {
        NodePaths {
            config_dir: config_dir.into(),
            state_dir: state_dir.into(),
        }
    }

    /// `--config-dir`/`NERVE_CONFIG_DIR`, else `~/.config/nerve`; likewise
    /// `--state-dir`/`NERVE_STATE_DIR`, else `~/.local/state/nerve`. When
    /// neither folder is named and `nerve-node install` put the node on this
    /// machine as a service, both are the installed node's
    /// ([`crate::service::Layout`]): the commands then reach the node that
    /// runs.
    pub fn from_args(config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> NodePaths {
        let env = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let config_dir = config_dir.or_else(|| env("NERVE_CONFIG_DIR"));
        let state_dir = state_dir.or_else(|| env("NERVE_STATE_DIR"));
        if config_dir.is_none() && state_dir.is_none() {
            let layout = crate::service::Layout::system();
            if layout.installed() {
                return layout.paths;
            }
        }
        let home = home_dir();
        NodePaths {
            config_dir: config_dir.unwrap_or_else(|| home.join(".config/nerve")),
            state_dir: state_dir.unwrap_or_else(|| home.join(".local/state/nerve")),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("node.toml")
    }

    /// The node's private key for `center` (a 0600 file).
    pub fn key_file(&self, center: &str) -> PathBuf {
        self.config_dir.join("keys").join(format!("{center}.key"))
    }

    pub fn ctl_socket(&self) -> PathBuf {
        self.state_dir.join("run").join("ctl.sock")
    }

    pub fn audit_log(&self) -> PathBuf {
        self.state_dir.join("audit.jsonl")
    }

    /// The log (docs/user/logs.md): what the node did, apart from the audit
    /// log, which is what it decided.
    pub fn log_file(&self) -> PathBuf {
        nerve_transport::log::file_in(&self.state_dir)
    }

    /// The key of the MAC over `node.toml`. It is not beside the file it
    /// signs: whatever could read the config folder would hold both, and the
    /// key must not depend on a setting in the file it checks.
    pub fn config_key(&self) -> PathBuf {
        self.state_dir.join("config.key")
    }

    /// The node's own files: no center reaches them, whatever its policy.
    pub fn own(&self) -> Vec<PathBuf> {
        vec![self.config_dir.clone(), self.state_dir.clone()]
    }
}

/// The owner's home directory.
pub fn home_dir() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("/").to_path_buf())
}

/// The platform the protected list follows: this one, on Windows with its
/// system folders from the environment and the Documents folder from the
/// known-folder API.
pub fn platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows(windows_folders(|k| std::env::var_os(k), documents()))
    } else {
        Platform::Unix
    }
}

/// The Documents folder as Windows has it, wherever OneDrive's backup or a
/// redirect moved it; `None`, logged, when it cannot be read (the usual
/// place below the profile is protected all the same).
fn documents() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let found = known_documents();
        if found.is_none() {
            tracing::warn!(
                "cannot read the Documents known folder; protecting PowerShell's profiles below %USERPROFILE%\\Documents only"
            );
        }
        found
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// `SHGetKnownFolderPath(FOLDERID_Documents)`, which PowerShell's
/// `$PROFILE` follows.
#[cfg(windows)]
fn known_documents() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Documents, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: the GUID is a static, a null token means the calling user,
    // and the call sets `raw` to a string it allocated (or to null).
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_Documents,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut raw,
        )
    };
    let path = (hr >= 0 && !raw.is_null()).then(|| {
        // SAFETY: on success `raw` is a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        let wide = unsafe { std::slice::from_raw_parts(raw, len) };
        PathBuf::from(OsString::from_wide(wide))
    });
    // SAFETY: the string is freed with the allocator that made it, also
    // after a failure, as the API asks; freeing null does nothing.
    unsafe { CoTaskMemFree(raw as *const _) };
    path.filter(|p| p.is_absolute())
}

/// Each path once, ignoring case as Windows does, in the order given.
fn distinct(paths: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        let same = |o: &PathBuf| {
            o.to_string_lossy()
                .eq_ignore_ascii_case(&p.to_string_lossy())
        };
        if !out.iter().any(same) {
            out.push(p);
        }
    }
    out
}

/// `%ProgramData%`, `%SystemRoot%` and `%ProgramFiles%` as `var` reads them,
/// each with its usual place as well: a center does not set the node's
/// environment, but an odd one must not leave `C:\ProgramData\ssh`
/// unprotected. Likewise `documents`, the Documents folder where Windows
/// has it, and `%USERPROFILE%\Documents`.
pub fn windows_folders(
    var: impl Fn(&str) -> Option<OsString>,
    documents: Option<PathBuf>,
) -> WinFolders {
    let var = |n: &str| var(n).filter(|v| !v.is_empty()).map(PathBuf::from);
    let all = |names: &[&str], usual: &str| -> Vec<PathBuf> {
        distinct(
            names
                .iter()
                .filter_map(|n| var(n))
                .chain(std::iter::once(PathBuf::from(usual))),
        )
    };
    WinFolders {
        program_data: all(&["ProgramData", "ALLUSERSPROFILE"], "C:\\ProgramData"),
        system_root: all(&["SystemRoot", "windir"], "C:\\Windows"),
        // A 32-bit process sees the x86 folder as `ProgramFiles` and the
        // 64-bit one as `ProgramW6432`; both hold a PowerShell 7 of their own.
        program_files: all(
            &["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"],
            "C:\\Program Files",
        ),
        // Joined with `\` as on Windows, also when a test runs elsewhere.
        documents: distinct(documents.into_iter().chain(var("USERPROFILE").map(|h| {
            let h = h
                .to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .to_string();
            PathBuf::from(format!("{h}\\Documents"))
        }))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_folders_come_from_the_environment_and_their_usual_place() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let f = windows_folders(
            env(&[
                ("ProgramData", "D:\\ProgramData"),
                ("SystemRoot", "D:\\WINDOWS"),
                ("windir", "D:\\WINDOWS"),
                ("ProgramFiles", "D:\\Program Files"),
                ("ProgramW6432", "D:\\Program Files"),
                ("ProgramFiles(x86)", "D:\\Program Files (x86)"),
            ]),
            None,
        );
        assert_eq!(
            f.program_data,
            [PathBuf::from("D:\\ProgramData"), "C:\\ProgramData".into()]
        );
        assert_eq!(
            f.system_root,
            [PathBuf::from("D:\\WINDOWS"), "C:\\Windows".into()]
        );
        assert_eq!(
            f.program_files,
            [
                PathBuf::from("D:\\Program Files"),
                "D:\\Program Files (x86)".into(),
                "C:\\Program Files".into()
            ]
        );
        // A 32-bit process: each folder once, however often it is named.
        let f = windows_folders(
            env(&[
                ("ProgramFiles", "C:\\Program Files (x86)"),
                ("ProgramW6432", "C:\\Program Files"),
                ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
            ]),
            None,
        );
        assert_eq!(
            f.program_files,
            [
                PathBuf::from("C:\\Program Files (x86)"),
                "C:\\Program Files".into()
            ]
        );
        // An empty or missing environment still protects the usual places.
        let f = windows_folders(env(&[("ProgramData", "")]), None);
        assert_eq!(f.program_data, [PathBuf::from("C:\\ProgramData")]);
        assert_eq!(f.system_root, [PathBuf::from("C:\\Windows")]);
        assert_eq!(f.program_files, [PathBuf::from("C:\\Program Files")]);
        let f = windows_folders(env(&[("SystemRoot", "c:\\windows")]), None);
        assert_eq!(f.system_root, [PathBuf::from("c:\\windows")]);
        assert_eq!(platform() == Platform::Unix, cfg!(not(windows)));
    }

    /// The Documents folder where the known-folder API puts it (OneDrive's
    /// backup, a redirect), and its usual place below the profile as well.
    #[test]
    fn the_documents_folder_comes_from_the_known_folder_and_the_profile() {
        let env = |k: &str| (k == "USERPROFILE").then(|| OsString::from("C:\\Users\\u"));
        let moved = PathBuf::from("C:\\Users\\u\\OneDrive\\Documents");
        let f = windows_folders(env, Some(moved.clone()));
        assert_eq!(f.documents, [moved, "C:\\Users\\u\\Documents".into()]);
        // When the known folder cannot be read, the usual place is left.
        let f = windows_folders(env, None);
        assert_eq!(f.documents, [PathBuf::from("C:\\Users\\u\\Documents")]);
        // Not moved: once.
        let f = windows_folders(env, Some("c:\\users\\u\\documents".into()));
        assert_eq!(f.documents, [PathBuf::from("c:\\users\\u\\documents")]);
    }

    /// The real known-folder read; only a Windows run reaches it.
    #[cfg(windows)]
    #[test]
    fn the_known_documents_folder_is_read() {
        let docs = known_documents().expect("the Documents known folder");
        assert!(docs.is_absolute(), "{docs:?}");
    }
}
