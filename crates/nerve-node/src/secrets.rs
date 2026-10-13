//! The node's secrets (docs/dev/spec/node-local.md §1 and §2).
//!
//! The values of the proxy's header lines, a `Proxy-Authorization` made from a
//! user name and password in the proxy URL among them, are always in the
//! system keyring: `node.toml` names the headers, and their values are never
//! in a file, a log, an error text or the audit log.
//!
//! The node's own keys, the key of the config's MAC and the node key per
//! center, are where `machine.secret_storage` says: 0600 files (`file`, the
//! default) or the system keyring (`keyring`). A change moves them once,
//! through the settings store ([`NodeSecrets`]): copied, read back, then the
//! old copies go.
//!
//! There is no fallback. Where the keyring cannot be reached (a headless
//! Linux has no Secret Service), storing fails and `proxy set` refuses, a
//! link whose proxy needs a value it cannot read fails closed, and a node
//! whose keys are in the keyring does not start. Tests put an in-memory store
//! in place of the system's; it is compiled into test builds only, so a
//! release never holds a secret anywhere but the keyring.

use std::collections::BTreeMap;
use std::path::Path;

use nerve_policy::NodeConfig;
use nerve_policy::config::SecretStorage;
use nerve_policy::settings::Secrets;
use nerve_transport::keys::{MacKey, NodeKey};

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

    /// The entry with the key of the config's MAC, named after the state
    /// folder that would hold its file.
    pub fn config_key(paths: &NodePaths) -> Entry {
        Entry {
            account: format!("config-key:{}", absolute(&paths.state_dir).display()),
        }
    }

    /// The entry with the node key for `center`, named after the config
    /// folder that would hold its file.
    pub fn center_key(paths: &NodePaths, center: &str) -> Entry {
        Entry {
            account: format!(
                "center-key:{center}:{}",
                absolute(&paths.config_dir).display()
            ),
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

/// One of the node's own keys, in its file or its keyring entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key<'a> {
    /// The key of the config's MAC.
    Config,
    /// The node key for a center.
    Center(&'a str),
}

impl Key<'_> {
    fn file(self, paths: &NodePaths) -> std::path::PathBuf {
        match self {
            Key::Config => paths.config_key(),
            Key::Center(c) => paths.key_file(c),
        }
    }

    fn entry(self, paths: &NodePaths) -> Entry {
        match self {
            Key::Config => Entry::config_key(paths),
            Key::Center(c) => Entry::center_key(paths, c),
        }
    }

    /// How a message names it.
    fn what(self) -> String {
        match self {
            Key::Config => "the key of the config's MAC".into(),
            Key::Center(c) => format!("the node key for center {c}"),
        }
    }
}

/// Every key of the node `cfg` describes: the config's and one per center.
fn keys(cfg: &NodeConfig) -> Vec<Key<'_>> {
    std::iter::once(Key::Config)
        .chain(cfg.centers.iter().map(|c| Key::Center(&c.name)))
        .collect()
}

/// The other place.
fn other(storage: SecretStorage) -> SecretStorage {
    match storage {
        SecretStorage::File => SecretStorage::Keyring,
        SecretStorage::Keyring => SecretStorage::File,
    }
}

/// How a message names a place.
fn place(storage: SecretStorage) -> &'static str {
    match storage {
        SecretStorage::File => "its file",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// The text of `key` in `storage`, trimmed; `None` when it is not there.
/// Errors name the file or the entry, never the text.
fn get(paths: &NodePaths, storage: SecretStorage, key: Key) -> Result<Option<String>, String> {
    match storage {
        SecretStorage::File => {
            let file = key.file(paths);
            match std::fs::read_to_string(&file) {
                Ok(t) => Ok(Some(t.trim().to_string())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!(
                    "cannot read {} {}: {e}",
                    key.what(),
                    file.display()
                )),
            }
        }
        SecretStorage::Keyring => {
            let entry = key.entry(paths);
            store::get(entry.account())
                .map(|t| t.map(|t| t.trim().to_string()))
                .map_err(|e| {
                    format!(
                        "cannot read {} from the system keyring (entry {entry}): {e}",
                        key.what()
                    )
                })
        }
    }
}

/// Keeps `text` as `key` in `storage`, replacing what was there, and reads
/// it back: a copy that does not read back as written is an error.
fn put(paths: &NodePaths, storage: SecretStorage, key: Key, text: &str) -> Result<(), String> {
    match storage {
        SecretStorage::File => {
            let file = key.file(paths);
            if let Some(dir) = file.parent() {
                nerve_transport::files::create_private_dir(dir)
                    .map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            nerve_transport::files::write_private(&file, format!("{text}\n").as_bytes())
                .map_err(|e| format!("cannot write {} {}: {e}", key.what(), file.display()))?;
        }
        SecretStorage::Keyring => {
            let entry = key.entry(paths);
            store::set(entry.account(), text).map_err(|e| {
                format!(
                    "cannot keep {} in the system keyring (entry {entry}): {e}",
                    key.what()
                )
            })?;
        }
    }
    if get(paths, storage, key)?.as_deref() != Some(text) {
        return Err(format!(
            "{} in {} does not read back as it was written",
            key.what(),
            place(storage)
        ));
    }
    Ok(())
}

/// Deletes `key` from `storage`; `Ok(false)` when it was not there.
fn delete(paths: &NodePaths, storage: SecretStorage, key: Key) -> Result<bool, String> {
    match storage {
        SecretStorage::File => {
            let file = key.file(paths);
            match std::fs::remove_file(&file) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(format!("cannot delete {}: {e}", file.display())),
            }
        }
        SecretStorage::Keyring => {
            let entry = key.entry(paths);
            store::delete(entry.account())
                .map_err(|e| format!("cannot delete the keyring entry {entry}: {e}"))
        }
    }
}

/// Where the node's `node.toml` says its keys are, read without checking
/// its MAC: the key that checks it is looked for there. No file, or one
/// that does not parse: `file`.
pub fn stated_storage(paths: &NodePaths) -> SecretStorage {
    std::fs::read_to_string(paths.config_file())
        .map(|t| nerve_policy::settings::stated_storage(&t))
        .unwrap_or_default()
}

/// The node key for `center` from where `storage` keeps it.
pub fn center_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
) -> Result<NodeKey, String> {
    let key = Key::Center(center);
    let text = match storage {
        // As before the keyring: the file and its own messages.
        SecretStorage::File => {
            let path = key.file(paths);
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read the node key {}: {e}", path.display()))?;
            return NodeKey::from_text(text.trim())
                .map_err(|e| format!("bad node key {}: {e}", path.display()));
        }
        SecretStorage::Keyring => match get(paths, storage, key)? {
            Some(t) => t,
            // The keyring answered and holds none: a key whose move has not
            // finished is still in its file. An unreachable keyring is an
            // error above, never a reason to read the file.
            None => get(paths, SecretStorage::File, key)?.ok_or_else(|| {
                format!(
                    "the system keyring has no entry {} with the node key for center {center}; pair the center again",
                    key.entry(paths)
                )
            })?,
        },
    };
    NodeKey::from_text(&text).map_err(|e| {
        format!(
            "bad node key for center {center} in the keyring entry {}: {e}",
            key.entry(paths)
        )
    })
}

/// Keeps a new node key for `center` where `storage` says.
pub fn store_center_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
    key: &NodeKey,
) -> Result<(), String> {
    put(paths, storage, Key::Center(center), key.to_text().trim())
}

/// Deletes the node key for `center`: from where `storage` keeps it, and a
/// file left from before a move.
pub fn remove_center_key(
    paths: &NodePaths,
    storage: SecretStorage,
    center: &str,
) -> Result<(), String> {
    let key = Key::Center(center);
    delete(paths, storage, key)?;
    if storage == SecretStorage::Keyring {
        delete(paths, SecretStorage::File, key)?;
    }
    Ok(())
}

/// The node's own keys where `machine.secret_storage` says, for the
/// settings store: the MAC key, and a move of every key when a saved config
/// names the other place.
///
/// A move writes `keys.moving` in the state folder first, then copies every
/// key and reads each copy back; the config is saved; then the old copies go
/// and so does the mark. Whatever stops it in between, the next start of the
/// node ([`settle`]) finds the mark and finishes or undoes the move by the
/// config in force.
///
/// A running node holds [`KeysLock`]. A CLI that writes `node.toml` itself
/// moves the keys only while it holds that lock too; when a node holds it
/// (on Windows, which has no control socket to ask that node, or one that is
/// starting), the old copies stay for that node to read until its next
/// start, which finishes the move.
pub struct NodeSecrets {
    paths: NodePaths,
    storage: SecretStorage,
    /// Whether a move takes [`KeysLock`] first: the CLI's. The daemon holds
    /// it already.
    locks: bool,
    /// The lock while a move holds it.
    held: Option<KeysLock>,
    /// The move in progress leaves the old copies to the next start.
    defer: bool,
}

impl NodeSecrets {
    /// The keys of the node at `paths`, where its `node.toml` says they are
    /// ([`stated_storage`]). The store checks the file with the key found
    /// there, so a file that names another place than its own key's does
    /// not pass.
    pub fn new(paths: &NodePaths) -> NodeSecrets {
        NodeSecrets {
            paths: paths.clone(),
            storage: stated_storage(paths),
            locks: false,
            held: None,
            defer: false,
        }
    }

    /// For a CLI that writes `node.toml` itself: a move takes [`KeysLock`],
    /// and leaves the old copies to a node that holds it.
    pub fn for_cli(paths: &NodePaths) -> NodeSecrets {
        NodeSecrets {
            locks: true,
            ..NodeSecrets::new(paths)
        }
    }

    /// For `config accept` without a running node: the file was edited, so
    /// its `machine.secret_storage` may not say where the key is. When the
    /// place it names holds no key and the other one does, the keys are
    /// taken to be there, and accepting the file moves them. With `file`
    /// named and its key file there, the keyring is not asked.
    pub fn for_accept(paths: &NodePaths) -> NodeSecrets {
        let mut s = NodeSecrets::for_cli(paths);
        let found = |storage| match storage {
            SecretStorage::File => paths.config_key().exists(),
            SecretStorage::Keyring => {
                matches!(get(paths, SecretStorage::Keyring, Key::Config), Ok(Some(_)))
            }
        };
        if !found(s.storage) && found(other(s.storage)) {
            s.storage = other(s.storage);
        }
        s
    }

    /// Moves every key of `cfg` into `into` from the other place: a key
    /// only there is copied over and read back, and a copy there that
    /// equals the one in `into` is deleted. Says what it could not do.
    fn gather(&self, cfg: &NodeConfig, into: SecretStorage) -> Vec<String> {
        let from = other(into);
        let mut left = Vec::new();
        for key in keys(cfg) {
            let r = (|| {
                let Some(old) = get(&self.paths, from, key)? else {
                    return Ok(());
                };
                match get(&self.paths, into, key)? {
                    None => put(&self.paths, into, key, &old)?,
                    Some(new) if new != old => {
                        return Err(format!(
                            "{} in {} differs from the one in {}, so it was left there",
                            key.what(),
                            place(from),
                            place(into)
                        ));
                    }
                    Some(_) => {}
                }
                delete(&self.paths, from, key).map(drop)
            })();
            if let Err(e) = r {
                left.push(e);
            }
        }
        left
    }

    /// Ends a move: without anything left behind, the mark goes.
    fn finish(&self, left: Vec<String>) {
        for e in &left {
            tracing::warn!("moving the node's keys: {e}");
        }
        if left.is_empty() {
            let _ = std::fs::remove_file(self.paths.keys_moving());
        }
    }
}

impl Secrets for NodeSecrets {
    fn storage(&self) -> SecretStorage {
        self.storage
    }

    fn mac_key(&self) -> Result<Option<MacKey>, String> {
        let file = self.paths.config_key();
        match self.storage {
            SecretStorage::File => MacKey::load(&file),
            SecretStorage::Keyring => {
                let entry = Entry::config_key(&self.paths);
                let text =
                    store::get(entry.account()).map_err(|e| unreachable_keyring(&entry, &e))?;
                match text {
                    Some(t) => MacKey::from_text(&t)
                        .map(Some)
                        .map_err(|e| format!("the keyring entry {entry}: {e}")),
                    // A key whose move has not finished is still in its file.
                    None => MacKey::load(&file),
                }
            }
        }
    }

    fn mac_key_or_new(&self) -> Result<MacKey, String> {
        match self.storage {
            SecretStorage::File => MacKey::load_or_create(&self.paths.config_key()),
            SecretStorage::Keyring => {
                if let Some(k) = self.mac_key()? {
                    return Ok(k);
                }
                let (key, text) = MacKey::generate();
                put(&self.paths, SecretStorage::Keyring, Key::Config, &text)?;
                Ok(key)
            }
        }
    }

    fn copy(&mut self, cfg: &NodeConfig) -> Result<(), String> {
        let to = cfg.machine.secret_storage;
        if self.locks {
            self.held = KeysLock::try_take(&self.paths)?;
            self.defer = self.held.is_none();
        }
        nerve_transport::files::write_private(
            &self.paths.keys_moving(),
            format!("moving the node's keys to {}\n", place(to)).as_bytes(),
        )
        .map_err(|e| format!("{}: {e}", self.paths.keys_moving().display()))?;
        let mut copied = Vec::new();
        for key in keys(cfg) {
            let r = get(&self.paths, self.storage, key).and_then(|text| match text {
                Some(t) => put(&self.paths, to, key, &t).map(|_| copied.push(key)),
                None => Ok(()),
            });
            if let Err(e) = r {
                // Nothing is saved: what was copied goes again.
                for key in copied {
                    let _ = delete(&self.paths, to, key);
                }
                let _ = std::fs::remove_file(self.paths.keys_moving());
                self.held = None;
                let hint = match to {
                    SecretStorage::Keyring => {
                        " (on a Linux without a desktop, `nerve-node setup` can install a keyring)"
                    }
                    SecretStorage::File => "",
                };
                return Err(format!(
                    "{e}; the node's keys stay in {}, and nothing was changed{hint}",
                    match self.storage {
                        SecretStorage::File => "their files",
                        SecretStorage::Keyring => "the system keyring",
                    }
                ));
            }
        }
        Ok(())
    }

    fn moved(&mut self, cfg: &NodeConfig) {
        self.storage = cfg.machine.secret_storage;
        if !self.defer {
            self.finish(self.gather(cfg, self.storage));
        }
        self.held = None;
    }

    fn not_moved(&mut self, cfg: &NodeConfig) {
        self.finish(self.gather(cfg, self.storage));
        self.held = None;
    }
}

/// The refusal of a node whose keys are in a keyring it cannot reach.
fn unreachable_keyring(entry: &Entry, e: &str) -> String {
    format!(
        "machine.secret_storage is \"keyring\", but the system keyring cannot be reached (entry {entry}): {e}. The node keeps its keys nowhere else, so it cannot read its config; start the keyring (on a Linux without a desktop, `nerve-node setup` can install one)"
    )
}

/// At the start of the node, with its config checked and [`KeysLock`]
/// held: finishes a move of its keys that stopped half way, or one a CLI
/// left to this start ([`NodeSecrets::for_cli`]), by the config in force;
/// and with `keyring`, takes into the keyring every key still in a file.
/// With `file` and no move pending, the keyring is not asked. A file that
/// names another place than `cfg` was changed since the node read it; its
/// move is left to the next start.
pub fn settle(paths: &NodePaths, cfg: &NodeConfig) {
    let storage = cfg.machine.secret_storage;
    if storage == SecretStorage::File && !paths.keys_moving().exists() {
        return;
    }
    if stated_storage(paths) != storage {
        return;
    }
    let s = NodeSecrets {
        storage,
        ..NodeSecrets::new(paths)
    };
    s.finish(s.gather(cfg, storage));
}

/// `keys.lock` in the state folder, held by a running node for its life and
/// by a CLI while it moves the keys: a move never runs while a node reads
/// them. It is released when its holder ends, however it ends.
pub struct KeysLock {
    _file: std::fs::File,
}

impl KeysLock {
    /// The lock, when nobody holds it; `None` when someone does.
    pub fn try_take(paths: &NodePaths) -> Result<Option<KeysLock>, String> {
        let path = paths.keys_lock();
        nerve_transport::files::create_private_dir(&paths.state_dir)
            .map_err(|e| format!("{}: {e}", paths.state_dir.display()))?;
        let mut o = std::fs::OpenOptions::new();
        o.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;
            o.mode(0o600);
            let file = o
                .open(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Some(KeysLock { _file: file }));
            }
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            Err(format!("{}: {e}", path.display()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Opened without sharing: nobody else opens it while it is held.
            const SHARING_VIOLATION: i32 = 32;
            match o.share_mode(0).open(&path) {
                Ok(file) => Ok(Some(KeysLock { _file: file })),
                Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => Ok(None),
                Err(e) => Err(format!("{}: {e}", path.display())),
            }
        }
    }

    /// The lock, waiting up to `wait` for a CLI that moves the keys.
    pub async fn take(
        paths: &NodePaths,
        wait: std::time::Duration,
    ) -> Result<Option<KeysLock>, String> {
        let until = tokio::time::Instant::now() + wait;
        loop {
            if let Some(l) = KeysLock::try_take(paths)? {
                return Ok(Some(l));
            }
            if tokio::time::Instant::now() >= until {
                return Ok(None);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

/// The system keyring: Keychain on macOS, Credential Manager on Windows, the
/// Secret Service elsewhere.
#[cfg(not(test))]
pub(crate) mod store {
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
        static CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// How often this thread asked the keyring.
    pub fn calls() -> usize {
        CALLS.with(Cell::get)
    }

    /// What the Secret Service crate says on a Linux without a desktop session.
    pub const NO_SERVICE: &str =
        "Couldn't access platform storage: SS error: result not returned from SS API";

    /// Makes the keyring unreachable on this thread (`true`) or reachable.
    pub fn set_unreachable(on: bool) {
        UNREACHABLE.with(|u| u.set(on));
    }

    fn reach() -> Result<std::sync::MutexGuard<'static, HashMap<String, String>>, String> {
        CALLS.with(|c| c.set(c.get() + 1));
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

#[cfg(test)]
mod tests {
    use super::*;
    use nerve_policy::SettingsStore;
    use nerve_policy::audit::AuditLog;

    fn node() -> (tempfile::TempDir, NodePaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        (d, paths)
    }

    fn in_keyring(paths: &NodePaths, key: Key) -> Option<String> {
        store::get(key.entry(paths).account()).unwrap()
    }

    fn open(paths: &NodePaths) -> Result<SettingsStore, String> {
        SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets::new(paths)),
            AuditLog::new(paths.audit_log()),
        )
    }

    fn peek(paths: &NodePaths) -> Result<NodeConfig, String> {
        SettingsStore::peek_with(&paths.config_file(), &NodeSecrets::new(paths))
    }

    /// A node with `centers` paired (their keys stored) under `storage`.
    fn paired(paths: &NodePaths, storage: SecretStorage, centers: &[&str]) -> SettingsStore {
        let mut s = open(paths).unwrap();
        if storage == SecretStorage::Keyring {
            s.update(|c| {
                c.machine.secret_storage = storage;
                Ok(())
            })
            .unwrap();
        }
        for name in centers {
            let key = NodeKey::generate().unwrap();
            store_center_key(paths, storage, name, &key).unwrap();
            s.update(|c| {
                c.centers.push(nerve_policy::CenterEntry {
                    name: name.to_string(),
                    url: "https://center.example".into(),
                    pin: None,
                    center_id: format!("id-{name}"),
                    node_id: key.node_id(),
                    settings: Default::default(),
                    paused: false,
                    revoked: false,
                    unknown: false,
                    policy: Default::default(),
                });
                Ok(())
            })
            .unwrap();
        }
        s
    }

    fn set_storage(s: &mut SettingsStore, storage: SecretStorage) -> Result<u64, String> {
        s.update(|c| {
            c.machine.secret_storage = storage;
            Ok(())
        })
        .map_err(|e| e.to_string())
    }

    #[test]
    fn each_key_is_stored_read_rotated_and_removed_in_either_place() {
        for storage in [SecretStorage::File, SecretStorage::Keyring] {
            let (_d, paths) = node();
            // The center's key.
            let first = NodeKey::generate().unwrap();
            store_center_key(&paths, storage, "home", &first).unwrap();
            let read = center_key(&paths, storage, "home").unwrap();
            assert_eq!(read.public_key(), first.public_key());
            let second = NodeKey::generate().unwrap();
            store_center_key(&paths, storage, "home", &second).unwrap();
            let read = center_key(&paths, storage, "home").unwrap();
            assert_eq!(read.public_key(), second.public_key());
            remove_center_key(&paths, storage, "home").unwrap();
            assert!(center_key(&paths, storage, "home").is_err());
            // The config's key.
            let secrets = NodeSecrets {
                storage,
                ..NodeSecrets::new(&paths)
            };
            assert!(secrets.mac_key().unwrap().is_none());
            let mac = secrets.mac_key_or_new().unwrap().sign(b"node.toml");
            let again = secrets.mac_key().unwrap().unwrap();
            assert!(again.verify(b"node.toml", &mac));
            // Never replaced by asking again.
            assert!(secrets.mac_key_or_new().unwrap().verify(b"node.toml", &mac));
            let (_, text) = MacKey::generate();
            put(&paths, storage, Key::Config, &text).unwrap();
            let rotated = secrets.mac_key().unwrap().unwrap();
            assert!(!rotated.verify(b"node.toml", &mac));
            assert!(delete(&paths, storage, Key::Config).unwrap());
            assert!(secrets.mac_key().unwrap().is_none());
            // Each place holds only its own: the keyring's keys never touch
            // a file, the files' never the keyring.
            store_center_key(&paths, storage, "lab", &first).unwrap();
            secrets.mac_key_or_new().unwrap();
            let files = paths.config_key().exists() || paths.key_file("lab").exists();
            let keyring = in_keyring(&paths, Key::Config).is_some()
                || in_keyring(&paths, Key::Center("lab")).is_some();
            assert_eq!(files, storage == SecretStorage::File, "{storage:?}");
            assert_eq!(keyring, storage == SecretStorage::Keyring, "{storage:?}");
        }
    }

    #[test]
    fn without_a_keyring_a_node_with_keys_there_refuses_and_reads_no_file() {
        let (_d, paths) = node();
        paired(&paths, SecretStorage::Keyring, &["home"]);
        // Files with the same names, as if left behind: never read instead.
        std::fs::write(paths.config_key(), "00".repeat(32)).unwrap();
        let key = NodeKey::generate().unwrap();
        store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        store::set_unreachable(true);
        let e = open(&paths).err().unwrap();
        assert!(e.contains("machine.secret_storage is \"keyring\""), "{e}");
        assert!(e.contains("cannot be reached"), "{e}");
        assert!(e.contains(store::NO_SERVICE), "{e}");
        assert!(peek(&paths).is_err());
        let e = center_key(&paths, SecretStorage::Keyring, "home")
            .err()
            .unwrap();
        assert!(e.contains("from the system keyring"), "{e}");
        // Nor is a new key written to a file instead.
        let e = store_center_key(&paths, SecretStorage::Keyring, "lab", &key)
            .err()
            .unwrap();
        assert!(e.contains("system keyring"), "{e}");
        assert!(!paths.key_file("lab").exists());
        store::set_unreachable(false);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn keys_move_to_the_keyring_and_back_once() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home", "lab"]);
        let mac_text = get(&paths, SecretStorage::File, Key::Config)
            .unwrap()
            .unwrap();
        let home = center_key(&paths, SecretStorage::File, "home").unwrap();
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        // In the keyring, read back, and the files are gone.
        assert_eq!(in_keyring(&paths, Key::Config), Some(mac_text.clone()));
        assert!(in_keyring(&paths, Key::Center("lab")).is_some());
        assert!(!paths.config_key().exists());
        assert!(!paths.key_file("home").exists() && !paths.key_file("lab").exists());
        assert!(!paths.keys_moving().exists());
        // The node starts on them: the file's MAC checks with the keyring's
        // key, and the center keys are the same.
        drop(s);
        let mut s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::Keyring);
        let back = center_key(&paths, SecretStorage::Keyring, "home").unwrap();
        assert_eq!(back.public_key(), home.public_key());
        // And back to files.
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert_eq!(
            get(&paths, SecretStorage::File, Key::Config).unwrap(),
            Some(mac_text)
        );
        assert!(paths.key_file("lab").exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        assert!(!paths.keys_moving().exists());
        drop(s);
        let s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        let back = center_key(&paths, SecretStorage::File, "home").unwrap();
        assert_eq!(back.public_key(), home.public_key());
        // The change is audited as a setting.
        let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(audit.contains("machine.secret_storage"), "{audit}");
    }

    #[test]
    fn a_move_to_a_keyring_that_does_not_answer_changes_nothing() {
        let (_d, paths) = node();
        let mut s = paired(&paths, SecretStorage::File, &["home"]);
        let before = std::fs::read(paths.config_file()).unwrap();
        store::set_unreachable(true);
        let e = set_storage(&mut s, SecretStorage::Keyring).unwrap_err();
        store::set_unreachable(false);
        assert!(e.contains("cannot keep"), "{e}");
        assert!(
            e.contains("stay in their files, and nothing was changed"),
            "{e}"
        );
        assert!(e.contains("nerve-node setup"), "{e}");
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert!(!paths.keys_moving().exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn a_move_left_to_the_next_start_is_finished_there() {
        let (_d, paths) = node();
        paired(&paths, SecretStorage::File, &["home"]);
        // A running node holds the lock: a CLI that writes the file itself
        // (on Windows, or while the node starts) leaves it the old copies.
        let running = KeysLock::try_take(&paths).unwrap().unwrap();
        assert!(KeysLock::try_take(&paths).unwrap().is_none());
        let mut s = cli_store(&paths);
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(paths.keys_moving().exists());
        let cfg = s.config().clone();
        drop(s);
        // The node reads its key where it was, then its next start takes
        // the config and finishes the move.
        assert!(center_key(&paths, SecretStorage::File, "home").is_ok());
        drop(running);
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert_eq!(cfg.machine.secret_storage, SecretStorage::Keyring);
        assert!(!paths.config_key().exists() && !paths.key_file("home").exists());
        assert!(in_keyring(&paths, Key::Config).is_some());
        assert!(!paths.keys_moving().exists());
    }

    fn cli_store(paths: &NodePaths) -> SettingsStore {
        SettingsStore::open_with(
            paths.config_file(),
            Box::new(NodeSecrets::for_cli(paths)),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap()
    }

    /// A CLI with no node running moves the keys at once, holding the lock
    /// meanwhile; a node that read the config before that, and starts
    /// after it, leaves the keys alone.
    #[test]
    fn a_start_on_a_config_changed_since_it_was_read_moves_nothing() {
        let (_d, paths) = node();
        let s = paired(&paths, SecretStorage::Keyring, &["home"]);
        let read_before = s.config().clone();
        drop(s);
        let mut s = cli_store(&paths);
        set_storage(&mut s, SecretStorage::File).unwrap();
        assert!(!paths.keys_moving().exists());
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        // The lock went with the move.
        assert!(KeysLock::try_take(&paths).unwrap().is_some());
        settle(&paths, &read_before);
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        drop(s);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn copies_of_a_move_that_never_saved_its_config_go_at_the_next_start() {
        let (_d, paths) = node();
        let s = paired(&paths, SecretStorage::File, &["home"]);
        // Copied to the keyring, then stopped before node.toml was saved.
        let mut secrets = NodeSecrets::new(&paths);
        let mut target = s.config().clone();
        target.machine.secret_storage = SecretStorage::Keyring;
        secrets.copy(&target).unwrap();
        assert!(in_keyring(&paths, Key::Config).is_some());
        drop(s);
        let s = open(&paths).unwrap();
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        settle(&paths, s.config());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert_eq!(in_keyring(&paths, Key::Center("home")), None);
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert!(!paths.keys_moving().exists());
    }

    #[test]
    fn a_node_on_the_keyring_takes_keys_still_in_files_at_start() {
        let (_d, paths) = node();
        paired(&paths, SecretStorage::File, &["home"]);
        // Saved with `keyring`, the old copies left, and no mark of it.
        let running = KeysLock::try_take(&paths).unwrap().unwrap();
        let mut s = cli_store(&paths);
        set_storage(&mut s, SecretStorage::Keyring).unwrap();
        drop((s, running));
        std::fs::remove_file(paths.keys_moving()).unwrap();
        store::delete(Entry::center_key(&paths, "home").account()).unwrap();
        // Until the start, the key still in its file is read there.
        assert!(center_key(&paths, SecretStorage::Keyring, "home").is_ok());
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(!paths.config_key().exists() && !paths.key_file("home").exists());
    }

    #[test]
    fn an_edited_file_that_names_the_other_place_moves_the_keys_when_accepted() {
        let (_d, paths) = node();
        drop(paired(&paths, SecretStorage::File, &["home"]));
        let edit = |from: &str, to: &str| {
            let text = std::fs::read_to_string(paths.config_file()).unwrap();
            let line = |s| format!("secret_storage = \"{s}\"");
            assert!(text.contains(&line(from)), "{text}");
            std::fs::write(paths.config_file(), text.replace(&line(from), &line(to))).unwrap();
        };
        let accept = || {
            SettingsStore::open_accepting_with(
                paths.config_file(),
                Box::new(NodeSecrets::for_accept(&paths)),
                AuditLog::new(paths.audit_log()),
            )
            .map(|(s, _)| s.config().machine.secret_storage)
        };
        edit("file", "keyring");
        // Changed by hand, so its MAC no longer checks.
        assert!(open(&paths).is_err());
        assert_eq!(accept(), Ok(SecretStorage::Keyring));
        assert!(in_keyring(&paths, Key::Config).is_some());
        assert!(in_keyring(&paths, Key::Center("home")).is_some());
        assert!(!paths.config_key().exists() && !paths.key_file("home").exists());
        assert!(open(&paths).is_ok());
        // And back: the key is found in the keyring.
        edit("keyring", "file");
        assert_eq!(accept(), Ok(SecretStorage::File));
        assert!(paths.config_key().exists() && paths.key_file("home").exists());
        assert_eq!(in_keyring(&paths, Key::Config), None);
        assert!(open(&paths).is_ok());
    }

    #[test]
    fn with_the_default_the_keyring_is_never_asked() {
        // A keyring that would fail every call: a node with files works on
        // as it did, from its first start to its last key, and never asks
        // it.
        store::set_unreachable(true);
        let asked = store::calls();
        let (_d, paths) = node();
        assert_eq!(stated_storage(&paths), SecretStorage::File);
        let mut s = paired(&paths, SecretStorage::File, &["home"]);
        assert_eq!(s.config().machine.secret_storage, SecretStorage::File);
        s.update(|c| {
            c.node.name = Some("lab-pc".into());
            Ok(())
        })
        .unwrap();
        drop(s);
        let s = open(&paths).unwrap();
        settle(&paths, s.config());
        assert!(center_key(&paths, SecretStorage::File, "home").is_ok());
        remove_center_key(&paths, SecretStorage::File, "home").unwrap();
        assert!(peek(&paths).is_ok());
        // The key file is where it always was.
        assert!(paths.config_key().is_file());
        assert!(!paths.keys_moving().exists());
        assert_eq!(store::calls(), asked);
        // A file that does not parse names the default too.
        std::fs::write(paths.config_file(), "not toml [").unwrap();
        assert_eq!(stated_storage(&paths), SecretStorage::File);
        store::set_unreachable(false);
    }
}
