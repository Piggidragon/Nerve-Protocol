//! Protected paths: places whose content gives away secrets or runs code later.
//!
//! They are refused in every mode, also in `user`, unless the
//! owner releases them by name: a folder grant at or inside the protected path, or an
//! entry in `protected.allow`. A grant of a whole home does not release `~/.ssh`.
//! Matching ignores case, so a case-insensitive filesystem cannot slip `~/.SSH` past.
//!
//! The node's own folders (its config, keys, state and audit log) are refused
//! harder still: nothing releases them, and `decide` looks at them before any
//! rule or mode.

use std::path::{Component, Path, PathBuf};

use crate::config::{Folder, ProtectedOptions};
use crate::paths::{resolve, within};

/// Relative to the home directory.
#[cfg(not(windows))]
const HOME: &[&str] = &[
    // keys and credentials
    ".ssh",
    ".gnupg",
    ".local/share/keyrings",
    ".local/share/kwalletd",
    ".kde/share/apps/kwallet",
    ".kde4/share/apps/kwallet",
    ".password-store",
    ".config/keepassxc",
    ".config/Bitwarden",
    ".config/1Password",
    ".git-credentials",
    ".netrc",
    ".aws",
    ".kube",
    ".docker",
    ".config/gh",
    ".config/hub",
    ".config/gcloud",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
    // browser and mail profiles
    ".mozilla",
    ".librewolf",
    ".thunderbird",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/vivaldi",
    ".config/microsoft-edge",
    ".config/opera",
    ".var/app",
    ".local/share/flatpak/app",
    // shell start-up and session environment
    ".bashrc",
    ".bashrc.d",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".config/fish",
    ".config/nushell",
    ".xprofile",
    ".xinitrc",
    ".xsession",
    ".xsessionrc",
    ".pam_environment",
    ".config/environment.d",
    // autostart, systemd user units, cron
    ".config/autostart",
    ".config/autostart-scripts",
    ".config/plasma-workspace",
    ".kde/Autostart",
    ".config/systemd",
    ".local/share/systemd",
];

/// Relative to the home directory: config that makes tools run commands, and
/// programs that run later in place of others (`~/.local/bin` comes early in
/// `PATH` on many systems, a fake `sudo` there would catch the password; a
/// `.desktop` file runs its `Exec=` line when its app is opened). Reading them is
/// harmless and tools need it (git's identity), so only writes prompt.
const HOME_WRITE_ONLY: &[&str] = &[
    ".gitconfig",
    ".config/git",
    ".local/bin",
    ".local/share/applications",
];

/// Relative to the user profile on Windows.
#[cfg(windows)]
const HOME: &[&str] = &[
    // keys and credentials
    ".ssh",
    ".gnupg",
    "AppData/Roaming/gnupg",
    "AppData/Roaming/Microsoft/Credentials",
    "AppData/Local/Microsoft/Credentials",
    "AppData/Roaming/Microsoft/Protect",
    "AppData/Roaming/Microsoft/Vault",
    "AppData/Local/Microsoft/Vault",
    "AppData/Roaming/Microsoft/Crypto",
    "AppData/Roaming/Microsoft/SystemCertificates",
    "AppData/Roaming/Bitwarden",
    "AppData/Roaming/KeePass",
    "AppData/Roaming/KeePassXC",
    "AppData/Local/1Password",
    "AppData/Roaming/GitHub CLI",
    "AppData/Roaming/gcloud",
    ".git-credentials",
    "_netrc",
    ".aws",
    ".kube",
    ".docker",
    ".azure",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
    // browser and mail profiles
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Local/BraveSoftware",
    "AppData/Local/Vivaldi",
    "AppData/Roaming/Mozilla",
    "AppData/Roaming/Opera Software",
    "AppData/Roaming/Thunderbird",
    // start-up, shell profiles and history
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    "AppData/Roaming/Microsoft/Windows/PowerShell",
    "Documents/WindowsPowerShell",
    "Documents/PowerShell",
];

/// System paths, for a client that runs as root (or reads what others may write).
#[cfg(not(windows))]
const SYSTEM: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/pam.d",
    "/etc/security",
    "/etc/polkit-1",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/systemd",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/environment",
    "/etc/bash.bashrc",
    "/etc/zsh",
    "/etc/xdg/autostart",
];

/// System paths on Windows come from the known folders (`KnownFolders`), since
/// Windows need not live in `C:\Windows`.
#[cfg(windows)]
const SYSTEM: &[&str] = &[];

/// Inside any folder: whose content the user's tools run. Writes there are refused.
pub const TOOL_CONFIG: &[&str] = &[".git", ".envrc", ".vscode", ".idea"];

#[derive(Debug, Clone)]
pub struct Protected {
    entries: Vec<PathBuf>,
    write_only: Vec<PathBuf>,
    /// The node's own folders, folded and resolved; never released.
    own: Vec<PathBuf>,
    /// How a command line may name them: absolute, and `~/`, `$HOME/` or
    /// `${HOME}/` for those in the home; folded.
    own_names: Vec<(String, PathBuf)>,
}

fn fold(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

/// `~/x` relative to `home`, or an absolute path; `None` for anything else.
pub fn expand(home: &Path, s: &str) -> Option<PathBuf> {
    if let Some(rest) = s.strip_prefix("~/") {
        Some(home.join(rest))
    } else if s == "~" {
        Some(home.to_path_buf())
    } else if Path::new(s).is_absolute() {
        Some(PathBuf::from(s))
    } else {
        None
    }
}

/// Folds a list, adds each entry's resolved form (resolved paths are what gets
/// checked, also when the home is a symlink and the entry does not exist yet) and
/// drops what the owner released.
fn finish(list: impl Iterator<Item = PathBuf>, allow: &[PathBuf]) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = list.collect();
    let real: Vec<PathBuf> = all.iter().filter_map(|e| resolve(e).ok()).collect();
    all.extend(real);
    let mut all: Vec<PathBuf> = all.iter().map(|e| fold(e)).collect();
    all.retain(|e| !allow.contains(e));
    all.sort();
    all.dedup();
    all
}

impl Protected {
    /// `own` are the node's own config and state directories: a command or a
    /// write must not change the node's policy behind its back, nor read the
    /// keys there. No folder grant and no `protected.allow` releases them.
    pub fn new(home: &Path, own: &[PathBuf], opts: &ProtectedOptions) -> Protected {
        let allow: Vec<PathBuf> = opts
            .allow
            .iter()
            .filter_map(|s| expand(home, s))
            .map(|p| fold(&p))
            .collect();
        let entries = HOME
            .iter()
            .map(|r| home.join(r))
            .chain(SYSTEM.iter().map(PathBuf::from))
            .chain(opts.extra.iter().filter_map(|s| expand(home, s)));
        let write_only = HOME_WRITE_ONLY.iter().map(|r| home.join(r));
        let own = finish(own.iter().cloned(), &[]);
        let homes = finish(std::iter::once(home.to_path_buf()), &[]);
        let mut own_names = Vec::new();
        for o in &own {
            own_names.push((o.to_string_lossy().into_owned(), o.clone()));
            for h in &homes {
                if let Ok(rel) = o.strip_prefix(h)
                    && !rel.as_os_str().is_empty()
                {
                    let rel = rel.to_string_lossy();
                    for prefix in ["~/", "$home/", "${home}/"] {
                        own_names.push((format!("{prefix}{rel}"), o.clone()));
                    }
                }
            }
        }
        Protected {
            entries: finish(entries, &allow),
            write_only: finish(write_only, &allow),
            own,
            own_names,
        }
    }

    /// The node's own folder `path` falls in.
    pub fn own(&self, path: &Path) -> Option<&Path> {
        let folded = fold(path);
        self.own
            .iter()
            .find(|o| within(&folded, o))
            .map(PathBuf::as_path)
    }

    /// The node's own folder a command line names, as far as a plain look
    /// can tell: an absolute path or one from the home (`~/`, `$HOME/`). A
    /// path built at run time (`cd ~/.config; cat nerve/x`) is not seen here;
    /// in `folder` mode Landlock still keeps the command out.
    pub fn own_in_command(&self, command: &str) -> Option<&Path> {
        let folded = command.to_lowercase();
        let name_char = |c: char| c.is_alphanumeric() || matches!(c, '.' | '_' | '-');
        self.own_names.iter().find_map(|(name, own)| {
            let hit = folded
                .match_indices(name.as_str())
                .any(|(at, _)| !folded[at + name.len()..].starts_with(name_char));
            hit.then_some(own.as_path())
        })
    }

    /// The protected entry `path` falls in, unless a folder names it. The
    /// node's own folders are never released.
    pub fn check(&self, path: &Path, write: bool, folders: &[Folder]) -> Option<&Path> {
        if let Some(own) = self.own(path) {
            return Some(own);
        }
        let folded = fold(path);
        let mut write_only = self.write_only.iter().filter(|_| write);
        let entry = self
            .entries
            .iter()
            .find(|e| within(&folded, e))
            .or_else(|| write_only.find(|e| within(&folded, e)))?;
        // Granted by name: a folder at or inside the protected entry that holds `path`.
        let named = folders.iter().any(|g| {
            let gf = fold(Path::new(&g.path));
            within(&gf, entry) && within(&folded, &gf)
        });
        if named { None } else { Some(entry) }
    }

    /// The tool-config component (`.git`, `.envrc`, ...) a write to `path` touches.
    pub fn tool_config(&self, path: &Path) -> Option<&'static str> {
        path.components().find_map(|c| match c {
            Component::Normal(n) => {
                let n = n.to_string_lossy().to_lowercase();
                TOOL_CONFIG.iter().find(|t| **t == n).copied()
            }
            _ => None,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::Access;

    fn prot() -> Protected {
        Protected::new(
            Path::new("/home/u"),
            &[PathBuf::from("/home/u/.config/nerve")],
            &ProtectedOptions::default(),
        )
    }

    fn folder(p: &str) -> Folder {
        Folder {
            path: p.into(),
            access: Access::Rw,
            execute: false,
        }
    }

    #[test]
    fn protects_keys_shell_startup_and_own_config() {
        let p = prot();
        for path in [
            "/home/u/.ssh/id_ed25519",
            "/home/u/.bashrc",
            "/home/u/.config/systemd/user/x.service",
            "/home/u/.config/nerve/node.toml",
            "/etc/sudoers.d/x",
            "/home/u/.SSH/id_rsa",
        ] {
            assert!(p.check(Path::new(path), false, &[]).is_some(), "{path}");
        }
        assert!(
            p.check(Path::new("/home/u/.local/bin/sudo"), false, &[])
                .is_none()
        );
        assert!(
            p.check(Path::new("/home/u/.local/bin/sudo"), true, &[])
                .is_some()
        );
        for path in ["/home/u/proj/a.rs", "/home/u/.sshx", "/home/u/.config"] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
    }

    #[test]
    fn released_only_by_name() {
        let p = prot();
        let ssh = Path::new("/home/u/.ssh/config");
        assert!(p.check(ssh, false, &[folder("/home/u")]).is_some());
        assert!(p.check(ssh, false, &[folder("/home/u/.ssh")]).is_none());
        let opts = ProtectedOptions {
            allow: vec!["~/.docker".into()],
            extra: vec!["~/secret".into()],
        };
        let p = Protected::new(Path::new("/home/u"), &[], &opts);
        assert!(
            p.check(Path::new("/home/u/.docker/x"), false, &[])
                .is_none()
        );
        assert!(p.check(Path::new("/home/u/secret/x"), false, &[]).is_some());
    }

    #[test]
    fn finds_tool_config() {
        let p = prot();
        assert_eq!(p.tool_config(Path::new("/w/.git/hooks/x")), Some(".git"));
        assert_eq!(p.tool_config(Path::new("/w/src/git.rs")), None);
    }
}
