//! Where a node keeps its files, and the system folders its protected list
//! hangs off.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use nerve_policy::protected::{Platform, WinFolders};

/// The node's config directory (`node.toml`, keys) and state directory
/// (control socket, audit log, the config's MAC key). Tests point both at
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
    /// `--state-dir`/`NERVE_STATE_DIR`, else `~/.local/state/nerve`.
    pub fn from_args(config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> NodePaths {
        let home = home_dir();
        let env = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        NodePaths {
            config_dir: config_dir
                .or_else(|| env("NERVE_CONFIG_DIR"))
                .unwrap_or_else(|| home.join(".config/nerve")),
            state_dir: state_dir
                .or_else(|| env("NERVE_STATE_DIR"))
                .unwrap_or_else(|| home.join(".local/state/nerve")),
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
/// system folders from the environment.
pub fn platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows(windows_folders(|k| std::env::var_os(k)))
    } else {
        Platform::Unix
    }
}

/// `%ProgramData%`, `%SystemRoot%` and `%ProgramFiles%` as `var` reads them,
/// each with its usual place as well: a center does not set the node's
/// environment, but an odd one must not leave `C:\ProgramData\ssh`
/// unprotected.
pub fn windows_folders(var: impl Fn(&str) -> Option<OsString>) -> WinFolders {
    let all = |names: &[&str], usual: &str| -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for p in names
            .iter()
            .filter_map(|n| var(n))
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .chain(std::iter::once(PathBuf::from(usual)))
        {
            let same = |o: &PathBuf| {
                o.to_string_lossy()
                    .eq_ignore_ascii_case(&p.to_string_lossy())
            };
            if !out.iter().any(same) {
                out.push(p);
            }
        }
        out
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
        let f = windows_folders(env(&[
            ("ProgramData", "D:\\ProgramData"),
            ("SystemRoot", "D:\\WINDOWS"),
            ("windir", "D:\\WINDOWS"),
            ("ProgramFiles", "D:\\Program Files"),
            ("ProgramW6432", "D:\\Program Files"),
            ("ProgramFiles(x86)", "D:\\Program Files (x86)"),
        ]));
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
        let f = windows_folders(env(&[
            ("ProgramFiles", "C:\\Program Files (x86)"),
            ("ProgramW6432", "C:\\Program Files"),
            ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        ]));
        assert_eq!(
            f.program_files,
            [
                PathBuf::from("C:\\Program Files (x86)"),
                "C:\\Program Files".into()
            ]
        );
        // An empty or missing environment still protects the usual places.
        let f = windows_folders(env(&[("ProgramData", "")]));
        assert_eq!(f.program_data, [PathBuf::from("C:\\ProgramData")]);
        assert_eq!(f.system_root, [PathBuf::from("C:\\Windows")]);
        assert_eq!(f.program_files, [PathBuf::from("C:\\Program Files")]);
        let f = windows_folders(env(&[("SystemRoot", "c:\\windows")]));
        assert_eq!(f.system_root, [PathBuf::from("c:\\windows")]);
        assert_eq!(platform() == Platform::Unix, cfg!(not(windows)));
    }
}
