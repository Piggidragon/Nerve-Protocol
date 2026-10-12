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
//!
//! Both platforms' lists and path rules are here on every platform, picked by
//! [`Platform`], so the Windows ones are tested on Linux as well.

use std::path::{Path, PathBuf};

use crate::config::{Folder, ProtectedOptions};
use crate::paths::{resolve, win};

/// Relative to the home directory.
const UNIX_HOME: &[&str] = &[
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
const WIN_HOME: &[&str] = &[
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
    // The user's registry hive: its Run keys start programs at every logon,
    // and programs keep credentials in it.
    "NTUSER.DAT",
];

/// System paths, for a client that runs as root (or reads what others may write).
const UNIX_SYSTEM: &[&str] = &[
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

/// Relative to `%ProgramData%`, for a node that runs as an administrator.
const WIN_PROGRAM_DATA: &[&str] = &[
    // The OpenSSH server: `sshd_config`, the host keys, and
    // `administrators_authorized_keys`, the key list of every administrator
    // account; a line there opens the machine, a broken file locks it.
    "ssh",
];

/// Relative to the Windows folder (`%SystemRoot%`), likewise.
const WIN_SYSTEM_ROOT: &[&str] = &[
    // The registry hives: SAM and SECURITY hold the password hashes and the
    // LSA secrets, SYSTEM the key that opens them.
    "System32/config",
];

/// Which platform's lists and path rules a [`Protected`] follows. The node
/// passes the one it runs on; a test may pass either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    Unix,
    Windows(WinFolders),
}

/// Where the Windows system entries hang off. Windows need not live in
/// `C:\Windows`, so the node takes them from the environment; each may have
/// more than one path, all of them protected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WinFolders {
    /// `%ProgramData%`.
    pub program_data: Vec<PathBuf>,
    /// `%SystemRoot%`, the Windows folder.
    pub system_root: Vec<PathBuf>,
}

impl Platform {
    fn windows(&self) -> bool {
        matches!(self, Platform::Windows(_))
    }
}

/// Inside any folder: whose content the user's tools run. Writes there are refused.
pub const TOOL_CONFIG: &[&str] = &[".git", ".envrc", ".vscode", ".idea"];

#[derive(Debug, Clone)]
pub struct Protected {
    /// Windows path rules: `\` and `/` both separate, case never counts.
    windows: bool,
    entries: Vec<PathBuf>,
    write_only: Vec<PathBuf>,
    /// The node's own folders, folded and resolved; never released.
    own: Vec<PathBuf>,
    /// The same as a command line names them once it is [`normalise`]d,
    /// with the folder each one stands for.
    own_names: Vec<(String, PathBuf)>,
    /// The home as `~` and `$HOME` stand for it in a command line,
    /// normalised: as given and resolved.
    homes: Vec<String>,
}

fn fold(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().to_lowercase())
}

/// Characters that end a word on a command line, besides white space: quotes,
/// shell control and the `=` of `--file=x`.
const BREAKS: &[char] = &['"', '\'', '`', ';', '&', '|', '<', '>', '(', ')', ',', '='];

fn breaks(c: char) -> bool {
    c.is_whitespace() || BREAKS.contains(&c)
}

/// A command line or a path the way the own-folder check compares them:
/// lower case, `/` for `\` and no `\\?\` prefix on Windows, and no doubled
/// separator or `/./`.
fn normalise(s: &str, windows: bool) -> String {
    let mut s = s.to_lowercase();
    if windows {
        s = s.replace('\\', "/").replace("//?/", "").replace("//./", "");
    }
    tidy(&s)
}

/// Folds `//` and `/./` into one `/`.
fn tidy(s: &str) -> String {
    let mut s = s.to_string();
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    while s.contains("/./") {
        s = s.replace("/./", "/");
    }
    s
}

/// Takes out every `seg/..` whose `seg` is a plain name after a `/`, word
/// by word, in one pass (the line comes from the center and may be long).
fn fold_dotdot(s: &str) -> String {
    fn word(w: &str, out: &mut String) {
        let mut kept: Vec<&str> = Vec::new();
        for seg in w.split('/') {
            let top = kept.last().copied();
            let plain = top.is_some_and(|t| !t.is_empty() && t != ".." && t != ".");
            if seg == ".." && plain && kept.len() > 1 {
                kept.pop();
            } else {
                kept.push(seg);
            }
        }
        out.push_str(&kept.join("/"));
    }
    let mut out = String::with_capacity(s.len());
    let mut start = 0;
    for (at, c) in s.char_indices().filter(|(_, c)| breaks(*c)) {
        word(&s[start..at], &mut out);
        out.push(c);
        start = at + c.len_utf8();
    }
    word(&s[start..], &mut out);
    out
}

/// `text` with every way a shell names the home replaced by `home`: `~` at
/// the start of a word, `$HOME` and `${HOME}`, and on Windows also
/// `$env:USERPROFILE`, `${env:USERPROFILE}` and `%USERPROFILE%`. `text` is
/// normalised already, so the names are in lower case.
fn expand_home(text: &str, home: &str, windows: bool) -> String {
    let mut vars = vec!["${home}", "$home"];
    if windows {
        vars.extend(["${env:userprofile}", "$env:userprofile", "%userprofile%"]);
    }
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut prev: Option<char> = None;
    while let Some(c) = rest.chars().next() {
        let var = vars.iter().find(|v| {
            rest.starts_with(**v)
                && (v.ends_with(['}', '%']) || !rest[v.len()..].starts_with(ident))
        });
        let tilde = c == '~'
            && prev.is_none_or(|p| breaks(p) || p == ':')
            && rest[1..]
                .chars()
                .next()
                .is_none_or(|n| n == '/' || breaks(n));
        let len = match var {
            Some(v) => v.len(),
            None if tilde => 1,
            None => {
                out.push(c);
                prev = Some(c);
                rest = &rest[c.len_utf8()..];
                continue;
            }
        };
        out.push_str(home);
        prev = home.chars().last();
        rest = &rest[len..];
    }
    out
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
    pub fn new(
        platform: &Platform,
        home: &Path,
        own: &[PathBuf],
        opts: &ProtectedOptions,
    ) -> Protected {
        let allow: Vec<PathBuf> = opts
            .allow
            .iter()
            .filter_map(|s| expand(home, s))
            .map(|p| fold(&p))
            .collect();
        let (in_home, system): (&[&str], Vec<PathBuf>) = match platform {
            Platform::Unix => (UNIX_HOME, UNIX_SYSTEM.iter().map(PathBuf::from).collect()),
            Platform::Windows(f) => {
                let below = |roots: &[PathBuf], list: &[&str]| -> Vec<PathBuf> {
                    roots
                        .iter()
                        .flat_map(|r| list.iter().map(move |e| r.join(e)))
                        .collect()
                };
                let mut system = below(&f.program_data, WIN_PROGRAM_DATA);
                system.extend(below(&f.system_root, WIN_SYSTEM_ROOT));
                (WIN_HOME, system)
            }
        };
        let entries = in_home
            .iter()
            .map(|r| home.join(r))
            .chain(system)
            .chain(opts.extra.iter().filter_map(|s| expand(home, s)));
        let write_only = HOME_WRITE_ONLY.iter().map(|r| home.join(r));
        let windows = platform.windows();
        let own = finish(own.iter().cloned(), &[]);
        let spelled = |p: &Path| {
            let s = normalise(&p.to_string_lossy(), windows);
            match s.trim_end_matches('/') {
                "" => s,
                t => t.to_string(),
            }
        };
        let own_names = own.iter().map(|o| (spelled(o), o.clone())).collect();
        let homes = finish(std::iter::once(home.to_path_buf()), &[])
            .iter()
            .map(|h| spelled(h))
            .collect();
        Protected {
            windows,
            entries: finish(entries, &allow),
            write_only: finish(write_only, &allow),
            own,
            own_names,
            homes,
        }
    }

    /// `path` is `base` or inside it, by whole components; on Windows by
    /// either separator and ignoring case. Both are folded already.
    fn inside(&self, path: &Path, base: &Path) -> bool {
        if self.windows {
            win::within(&path.to_string_lossy(), &base.to_string_lossy())
        } else {
            path.starts_with(base)
        }
    }

    /// The node's own folder `path` falls in.
    pub fn own(&self, path: &Path) -> Option<&Path> {
        let folded = fold(path);
        self.own
            .iter()
            .find(|o| self.inside(&folded, o))
            .map(PathBuf::as_path)
    }

    /// The node's own folder a command line names, as far as a plain look
    /// can tell. The line is normalised first: case, on Windows `\` or `/`
    /// and a `\\?\` prefix, doubled separators, `seg/..`, and the home in
    /// any spelling the shells take (`~`, `$HOME`, `${HOME}`, and on Windows
    /// `$env:USERPROFILE` and `%USERPROFILE%`). Then it looks for an absolute
    /// path, and for a word that is a relative path from `cwd`. A path built
    /// at run time (`cd ~/.config; cat nerve/x`) is not seen here; in
    /// `folder` mode Landlock still keeps the command out.
    pub fn own_in_command(&self, command: &str, cwd: Option<&Path>) -> Option<&Path> {
        let text = normalise(command, self.windows);
        let cwd = cwd.map(|c| {
            normalise(&c.to_string_lossy(), self.windows)
                .trim_end_matches('/')
                .to_string()
        });
        let absolute =
            |w: &str| w.starts_with('/') || (self.windows && w.as_bytes().get(1) == Some(&b':'));
        for home in &self.homes {
            let text = fold_dotdot(&tidy(&expand_home(&text, home, self.windows)));
            if let Some(own) = self.names_own(&text) {
                return Some(own);
            }
            let Some(cwd) = &cwd else { continue };
            for word in text.split(breaks).filter(|w| !w.is_empty() && !absolute(w)) {
                let path = fold_dotdot(&tidy(&format!("{cwd}/{word}")));
                if let Some(own) = self.names_own(&path) {
                    return Some(own);
                }
            }
        }
        None
    }

    /// The own folder whose name `text` holds, followed by anything but
    /// more of a file name (`nerve-notes` is not `nerve`).
    fn names_own(&self, text: &str) -> Option<&Path> {
        let name_char = |c: char| c.is_alphanumeric() || matches!(c, '.' | '_' | '-');
        self.own_names.iter().find_map(|(name, own)| {
            let hit = text
                .match_indices(name.as_str())
                .any(|(at, _)| !text[at + name.len()..].starts_with(name_char));
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
            .find(|e| self.inside(&folded, e))
            .or_else(|| write_only.find(|e| self.inside(&folded, e)))?;
        // Granted by name: a folder at or inside the protected entry that holds `path`.
        let named = folders.iter().any(|g| {
            let gf = fold(Path::new(&g.path));
            self.inside(&gf, entry) && self.inside(&folded, &gf)
        });
        if named { None } else { Some(entry) }
    }

    /// The tool-config component (`.git`, `.envrc`, ...) a write to `path` touches.
    pub fn tool_config(&self, path: &Path) -> Option<&'static str> {
        let windows = self.windows;
        path.to_string_lossy()
            .split(|c| c == '/' || (windows && c == '\\'))
            .find_map(|n| {
                let n = n.to_lowercase();
                TOOL_CONFIG.iter().find(|t| **t == n).copied()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Access;

    fn prot() -> Protected {
        Protected::new(
            &Platform::Unix,
            Path::new("/home/u"),
            &[PathBuf::from("/home/u/.config/nerve")],
            &ProtectedOptions::default(),
        )
    }

    /// A Windows node's list, built from plain strings so it is tested on
    /// every platform.
    fn win_prot() -> Protected {
        let folders = WinFolders {
            program_data: vec![PathBuf::from("C:\\ProgramData")],
            system_root: vec![PathBuf::from("C:\\Windows")],
        };
        Protected::new(
            &Platform::Windows(folders),
            Path::new("C:\\Users\\u"),
            &[
                PathBuf::from("C:\\Users\\u\\nerve-test\\node-config"),
                PathBuf::from("C:\\Users\\u\\nerve-test\\node-state"),
            ],
            &ProtectedOptions::default(),
        )
    }

    fn folder(p: &str) -> Folder {
        Folder {
            path: p.into(),
            access: Access::parse("rw").unwrap(),
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

    /// The OpenSSH server's files, the registry hives with the password
    /// hashes and the user's own hive, besides the keys in the profile
    /// (Windows review of PR #19, finding 1).
    #[test]
    fn protects_windows_system_and_credential_files() {
        let p = win_prot();
        for path in [
            "C:\\ProgramData\\ssh\\administrators_authorized_keys",
            "C:\\ProgramData\\ssh\\sshd_config",
            "C:\\ProgramData\\ssh\\ssh_host_ed25519_key",
            "c:\\programdata\\SSH",
            "\\\\?\\C:\\ProgramData\\ssh\\sshd_config",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\WINDOWS\\system32\\CONFIG\\security",
            "C:\\Windows\\System32\\config\\RegBack\\SAM",
            "C:\\Users\\u\\NTUSER.DAT",
            "C:\\Users\\u\\ntuser.dat",
            "C:\\Users\\u\\.ssh\\id_ed25519",
            "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Credentials\\x",
            "C:\\Users\\u\\.cargo\\credentials.toml",
            "C:\\Users\\u\\nerve-test\\node-config\\node.toml",
        ] {
            for write in [false, true] {
                assert!(
                    p.check(Path::new(path), write, &[]).is_some(),
                    "{path} {write}"
                );
            }
        }
        for path in [
            "C:\\ProgramData\\sshx",
            "C:\\ProgramData\\Other\\ssh",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\configx",
            "C:\\Users\\u\\NTUSER.DAT.txt",
            "C:\\Users\\u\\proj\\a.rs",
            "D:\\ProgramData\\ssh\\sshd_config",
        ] {
            assert!(p.check(Path::new(path), true, &[]).is_none(), "{path}");
        }
        // A grant of the whole drive does not release them; one by name does.
        let keys = Path::new("C:\\ProgramData\\ssh\\administrators_authorized_keys");
        assert!(p.check(keys, true, &[folder("C:\\")]).is_some());
        assert!(
            p.check(keys, true, &[folder("C:\\ProgramData\\ssh")])
                .is_none()
        );
        // Writes to tool config by either separator.
        assert_eq!(
            p.tool_config(Path::new("C:\\w\\.GIT\\hooks\\x")),
            Some(".git")
        );
        assert_eq!(p.tool_config(Path::new("C:\\w\\src\\git.rs")), None);
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
        let p = Protected::new(&Platform::Unix, Path::new("/home/u"), &[], &opts);
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

    /// The spellings of the Windows review of PR #19 (finding 2): forward
    /// slashes, the home in each shell's form, `..` from the working
    /// directory, quotes and other case.
    #[test]
    fn sees_the_own_folders_in_windows_spellings() {
        let p = win_prot();
        let proj = Path::new("C:\\Users\\u\\nerve-test\\proj");
        let home = Path::new("C:\\Users\\u");
        for (command, cwd) in [
            (
                "type C:\\Users\\u\\nerve-test\\node-config\\node.toml",
                home,
            ),
            (
                "type \"C:\\Users\\U\\Nerve-Test\\node-config\\node.toml\"",
                home,
            ),
            (
                "type \\\\?\\C:\\Users\\u\\nerve-test\\node-config\\node.toml",
                home,
            ),
            ("type C:/Users/u/nerve-test/node-state/config.key", home),
            ("type \"C:/Users/u/nerve-test/node-state/config.key\"", home),
            ("type 'c:/users/u/nerve-test/node-state'", home),
            (
                "type C:\\\\Users\\\\u\\\\nerve-test\\\\node-state\\\\config.key",
                home,
            ),
            ("Get-Content ~/nerve-test/node-config/node.toml", proj),
            ("Get-Content ~\\nerve-test\\node-config\\node.toml", proj),
            (
                "Get-Content \"~\\nerve-test\\node-config\\node.toml\"",
                proj,
            ),
            ("Get-Content $HOME/nerve-test/node-config/node.toml", proj),
            (
                "Get-Content $HOME\\nerve-test\\node-state\\config.key",
                proj,
            ),
            (
                "Get-Content ${HOME}\\nerve-test\\node-state\\config.key",
                proj,
            ),
            (
                "Get-Content $env:USERPROFILE\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            (
                "gc \"$env:userprofile/nerve-test/node-config/node.toml\"",
                proj,
            ),
            (
                "gc ${env:USERPROFILE}\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            (
                "cmd /c type %USERPROFILE%\\nerve-test\\node-config\\node.toml",
                proj,
            ),
            ("Get-Content ..\\node-config\\node.toml", proj),
            ("Get-Content '..\\node-state\\config.key'", proj),
            ("Get-Content ../node-config/node.toml", proj),
            ("Get-Content .\\nerve-test\\node-config\\node.toml", home),
            ("Get-Content nerve-test\\node-config", home),
            (
                "type C:\\Users\\u\\nerve-test\\proj\\..\\node-config\\node.toml",
                home,
            ),
            (
                "Set-Content -Path=~\\nerve-test\\node-config\\node.toml x",
                proj,
            ),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_some(),
                "{command} in {cwd:?}"
            );
        }
        for (command, cwd) in [
            ("type C:\\Users\\u\\nerve-test\\node-config-notes\\a", home),
            ("type C:/Users/u/nerve-test/proj/a", home),
            ("Get-Content ~/nerve-test/proj/a", proj),
            ("Get-Content ..\\proj\\a", proj),
            ("Get-Content node-config\\node.toml", proj),
            ("type D:\\Users\\u\\nerve-test\\node-config\\x", home),
            ("Get-Content $HOMEX\\nerve-test\\node-config", proj),
            ("echo a~\\nerve-test\\node-config", proj),
        ] {
            assert!(
                p.own_in_command(command, Some(cwd)).is_none(),
                "{command} in {cwd:?}"
            );
        }
    }

    /// The Unix shells' forms; the Windows ones mean nothing there.
    #[test]
    fn sees_the_own_folders_in_unix_spellings() {
        let p = prot();
        let home = Path::new("/home/u");
        for command in [
            "cat ~/.config/nerve/node.toml",
            "cat $HOME/.config/nerve",
            "cat ${HOME}/.config//nerve/x",
            "cat /home/u/./.config/nerve/x",
            "cat /home/u/a/b/../../.config/nerve/x",
            "cat '~/.config/nerve/x'",
            "cat .config/nerve/x",
            "cat x>~/.config/nerve/x",
            // Two words; the second is a path from the working directory.
            "cat /home/u/a b/../.config/nerve/x",
        ] {
            assert!(p.own_in_command(command, Some(home)).is_some(), "{command}");
        }
        for command in [
            "cat $env:USERPROFILE/.config/nerve/x",
            "cat %USERPROFILE%/.config/nerve/x",
            "cat ~\\.config\\nerve\\x",
            "cat ~/.config/nerve-notes",
        ] {
            assert!(p.own_in_command(command, Some(home)).is_none(), "{command}");
        }
    }

    #[test]
    fn dotdot_folds_only_plain_names_within_a_word() {
        assert_eq!(fold_dotdot("/a/b/../c"), "/a/c");
        assert_eq!(fold_dotdot("/a/b/c/../../d"), "/a/d");
        assert_eq!(fold_dotdot("/a/b/.."), "/a");
        assert_eq!(fold_dotdot("/../a"), "/../a");
        assert_eq!(fold_dotdot("/a/../../b"), "/../b");
        assert_eq!(fold_dotdot("/a/..b/c"), "/a/..b/c");
        assert_eq!(fold_dotdot("x a b/../c"), "x a b/../c");
        assert_eq!(fold_dotdot("c:/../x"), "c:/../x");
        assert_eq!(
            expand_home("~ ~/a a~ x=~/b", "/h", false),
            "/h /h/a a~ x=/h/b"
        );
        assert_eq!(expand_home("$home/a $homes", "/h", false), "/h/a $homes");
    }
}
