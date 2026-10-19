//! The app's own settings, kept for each user apart from the node's: the
//! appearance the owner chose (system, light or dark). A small JSON file in
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
    let mut v: Value = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    let word = WORDS.get(appearance as usize).copied().unwrap_or("system");
    v["appearance"] = json!(word);
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(path, format!("{v:#}\n")).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
