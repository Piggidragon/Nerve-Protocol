//! The node's secrets in the system keyring (docs/dev/node-link.md): the values
//! of the proxy's header lines, a `Proxy-Authorization` made from a user name
//! and password in the proxy URL among them. `node.toml` names the headers;
//! their values are here and never in a file, a log, an error text or the
//! audit log.
//!
//! There is no fallback. Where the keyring cannot be reached (a headless
//! Linux has no Secret Service), storing fails and `proxy set` refuses, and a
//! link whose proxy needs a value it cannot read fails closed. Tests put an
//! in-memory store in place of the system's; it is compiled into test builds
//! only, so a release never holds a secret anywhere but the keyring.

use std::collections::BTreeMap;
use std::path::Path;

use crate::paths::NodePaths;

/// The keyring service every entry of the node is filed under.
pub const SERVICE: &str = "nerve";

/// One entry of the node in the keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    account: String,
}

impl Entry {
    /// The entry with the proxy's header values. One per node: the account
    /// names the node's config folder after `proxy:`, so two nodes of one
    /// user keep theirs apart.
    pub fn proxy(paths: &NodePaths) -> Entry {
        let dir = absolute(&paths.config_dir);
        Entry {
            account: format!("proxy:{}", dir.display()),
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }
}

/// How errors name the entry: the service, then the account.
impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{SERVICE}/{}", self.account)
    }
}

fn absolute(p: &Path) -> std::path::PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Puts the proxy's header values into the node's keyring entry, replacing
/// what it held.
pub fn store_proxy_headers(paths: &NodePaths, headers: &[(String, String)]) -> Result<(), String> {
    let entry = Entry::proxy(paths);
    let map: BTreeMap<&str, &str> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let text = serde_json::to_string(&map).map_err(|e| e.to_string())?;
    store::set(entry.account(), &text).map_err(|e| {
        format!(
            "cannot store the proxy's header values in the system keyring (entry {entry}): {e}. The node keeps them nowhere else, so nothing was changed; on a machine without a keyring (a Linux without a desktop has no Secret Service) use a proxy that needs no header"
        )
    })
}

/// The proxy's header lines: the names `node.toml` gives, with their values
/// from the keyring. No names, no keyring call. A missing or unreadable entry,
/// or one without a value for a name, is an error that names the entry.
pub fn proxy_headers(paths: &NodePaths, names: &[String]) -> Result<Vec<(String, String)>, String> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let entry = Entry::proxy(paths);
    let again = "run `nerve-node proxy set` again";
    let text = match store::get(entry.account()) {
        Ok(Some(t)) => t,
        Ok(None) => {
            return Err(format!(
                "the system keyring has no entry {entry} with the proxy's header values; {again}"
            ));
        }
        Err(e) => {
            return Err(format!(
                "cannot read the proxy's header values from the system keyring (entry {entry}): {e}"
            ));
        }
    };
    // The parse error is not shown: it could quote the value.
    let mut map: BTreeMap<String, String> = serde_json::from_str(&text)
        .map_err(|_| format!("the keyring entry {entry} is not one nerve-node wrote; {again}"))?;
    names
        .iter()
        .map(|n| match map.remove(n) {
            Some(v) => Ok((n.clone(), v)),
            None => Err(format!(
                "the keyring entry {entry} holds no value for the header {n}; {again}"
            )),
        })
        .collect()
}

/// Deletes the node's proxy entry; `Ok(false)` when there was none.
pub fn remove_proxy_headers(paths: &NodePaths) -> Result<bool, String> {
    let entry = Entry::proxy(paths);
    store::delete(entry.account())
        .map_err(|e| format!("cannot delete the keyring entry {entry}: {e}"))
}

/// The system keyring: Keychain on macOS, Credential Manager on Windows, the
/// Secret Service elsewhere.
#[cfg(not(test))]
mod store {
    use super::SERVICE;

    fn entry(account: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, account).map_err(|e| {
            match (&e, keyring::Entry::store_status()) {
                // The store failed to start; its own error says why.
                (keyring::Error::NoDefaultStore, Err(why)) => why.to_string(),
                _ => e.to_string(),
            }
        })
    }

    pub fn get(account: &str) -> Result<Option<String>, String> {
        match entry(account)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn set(account: &str, value: &str) -> Result<(), String> {
        entry(account)?
            .set_password(value)
            .map_err(|e| e.to_string())
    }

    pub fn delete(account: &str) -> Result<bool, String> {
        match entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The test builds' keyring: a map in memory, shared by every thread of the
/// test process (each test's node has its own config folder, so its own
/// account), and a switch per thread that makes it unreachable, as on a
/// machine without a Secret Service.
#[cfg(test)]
pub(crate) mod store {
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    static ENTRIES: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Mutex::default);

    thread_local! {
        static UNREACHABLE: Cell<bool> = const { Cell::new(false) };
    }

    /// What the Secret Service crate says on a Linux without a desktop session.
    pub const NO_SERVICE: &str =
        "Couldn't access platform storage: SS error: result not returned from SS API";

    /// Makes the keyring unreachable on this thread (`true`) or reachable.
    pub fn set_unreachable(on: bool) {
        UNREACHABLE.with(|u| u.set(on));
    }

    fn reach() -> Result<std::sync::MutexGuard<'static, HashMap<String, String>>, String> {
        if UNREACHABLE.with(Cell::get) {
            return Err(NO_SERVICE.into());
        }
        Ok(ENTRIES.lock().unwrap_or_else(|e| e.into_inner()))
    }

    pub fn get(account: &str) -> Result<Option<String>, String> {
        Ok(reach()?.get(account).cloned())
    }

    pub fn set(account: &str, value: &str) -> Result<(), String> {
        reach()?.insert(account.into(), value.into());
        Ok(())
    }

    pub fn delete(account: &str) -> Result<bool, String> {
        Ok(reach()?.remove(account).is_some())
    }
}
