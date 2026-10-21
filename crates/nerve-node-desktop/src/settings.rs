//! The app's own settings, kept for each user apart from the node's: the
//! appearance the owner chose (system, light or dark), and the Overview's
//! card on commands that run as the user, when they hid it. A small JSON file in
//! the user's config folder, `nerve-node-desktop/settings.json`; the node's
//! settings stay the node's (`nerve-node config`).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

const WORDS: [&str; 3] = ["system", "light", "dark"];

/// Where this user's settings of the app are: `$XDG_CONFIG_HOME` or
/// `~/.config` on Linux, `%APPDATA%` on Windows.
pub fn file() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        var("APPDATA")?
    } else {
        var("XDG_CONFIG_HOME").or_else(|| Some(var("HOME")?.join(".config")))?
    };
    Some(base.join("nerve-node-desktop").join("settings.json"))
}

/// The appearance saved in `path`: 0 follows the system, 1 light, 2 dark.
/// A file that is not there, or not readable, follows the system.
pub fn appearance(path: &Path) -> i32 {
    let v: Value = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    WORDS
        .iter()
        .position(|w| v["appearance"] == *w)
        .unwrap_or_default() as i32
}

/// Saves `appearance` in `path`, the rest of the file as it was.
pub fn save_appearance(path: &Path, appearance: i32) -> Result<(), String> {
    let word = WORDS.get(appearance as usize).copied().unwrap_or("system");
    change(path, |v| v["appearance"] = json!(word))
}

/// The file at `path` with `f` applied, the rest as it was.
fn change(path: &Path, f: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut v = read(path)
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    f(&mut v);
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(path, format!("{v:#}\n")).map_err(|e| format!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Option<Value> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The ways to root in words ("docker, lxd and sudo"), one by one.
fn ways(via: &str) -> Vec<String> {
    via.replace(" and ", ", ")
        .split(", ")
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

/// Hides the card on commands that run as `account`, with root through
/// `via`, until that changes.
pub fn dismiss(path: &Path, account: &str, via: &str) -> Result<(), String> {
    change(path, |v| {
        v["commands_as_you_hidden"] = json!({ "account": account, "root_via": ways(via) });
    })
}

/// Shows the card again.
pub fn undismiss(path: &Path) -> Result<(), String> {
    change(path, |v| {
        if let Some(o) = v.as_object_mut() {
            o.remove("commands_as_you_hidden");
        }
    })
}

/// Whether the card stays hidden: it was hidden for this account, and no
/// way to root came since. Another account, or a new way, shows it again.
pub fn dismissed(path: &Path, account: &str, via: &str) -> bool {
    let Some(v) = read(path) else {
        return false;
    };
    let h = &v["commands_as_you_hidden"];
    let known: Vec<&str> = h["root_via"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    h["account"] == account && ways(via).iter().all(|w| known.contains(&w.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hidden card stays hidden for the same account and ways to root,
    /// and comes back for another account or a new way.
    #[test]
    fn the_hidden_card_comes_back_when_it_gets_worse() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve-node-desktop/settings.json");
        assert!(!dismissed(&f, "alex", ""));
        save_appearance(&f, 2).unwrap();
        dismiss(&f, "alex", "docker").unwrap();
        assert!(dismissed(&f, "alex", "docker"));
        assert!(dismissed(&f, "alex", ""), "fewer ways: still hidden");
        assert!(!dismissed(&f, "alex", "docker and sudo"), "a new way");
        assert!(!dismissed(&f, "sam", "docker"), "another account");
        assert_eq!(appearance(&f), 2, "the rest stays");
        dismiss(&f, "alex", "docker, lxd and sudo").unwrap();
        assert!(dismissed(&f, "alex", "lxd and sudo"));
        undismiss(&f).unwrap();
        assert!(!dismissed(&f, "alex", "docker"));
        assert_eq!(appearance(&f), 2);
    }

    #[test]
    fn the_appearance_is_kept_and_the_rest_stays() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve-node-desktop/settings.json");
        assert_eq!(appearance(&f), 0);
        save_appearance(&f, 2).unwrap();
        assert_eq!(appearance(&f), 2);
        std::fs::write(&f, r#"{"appearance": "light", "later": 1}"#).unwrap();
        assert_eq!(appearance(&f), 1);
        save_appearance(&f, 0).unwrap();
        let v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        assert_eq!(v, json!({"appearance": "system", "later": 1}));
        std::fs::write(&f, "not json").unwrap();
        assert_eq!(appearance(&f), 0);
    }
}
