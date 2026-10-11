//! Where a node keeps its files.

use std::path::{Path, PathBuf};

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
