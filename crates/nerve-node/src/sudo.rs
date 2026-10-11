//! The node's sudo switch (spec/node-local.md §4, spec/protocol.md §7.4.1).
//!
//! The switch is on only while the node holds a sudo password that `sudo -v`
//! accepted. The password lives in memory only: a restarted node starts with
//! the switch off. It is never part of a document, a result or the audit log,
//! and every outgoing frame is scrubbed of it.

use nerve_policy::config::Sudo;
use nerve_policy::{SetError, Writer};

use crate::daemon::{Shared, lock};

/// A password that is overwritten when it is dropped.
pub(crate) struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8.
        unsafe { self.0.as_bytes_mut().fill(0) };
    }
}

/// What stands in for the password where it would have appeared.
pub const REDACTED: &str = "[redacted]";

/// `text` with every copy of `secret`, plain and JSON-escaped, replaced by
/// [`REDACTED`]; `None` when there is none.
pub fn scrub(text: &str, secret: &str) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let quoted = serde_json::to_string(secret).unwrap_or_default();
    let escaped = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(secret)
        .to_string();
    let mut out: Option<String> = None;
    for needle in [secret, escaped.as_str()] {
        let cur = out.as_deref().unwrap_or(text);
        if cur.contains(needle) {
            out = Some(cur.replace(needle, REDACTED));
        }
    }
    out
}

impl Shared {
    /// Whether the switch is on: set in the config and a checked password
    /// held.
    pub fn sudo_on(&self) -> bool {
        // The store is always locked before the password, never after.
        let store = lock(&self.store);
        let held = lock(&self.sudo).is_some();
        held && store.config().machine.sudo == Sudo::On
    }

    /// The password for one permitted sudo command, while the switch is on.
    pub fn sudo_password(&self) -> Option<String> {
        let store = lock(&self.store);
        if store.config().machine.sudo != Sudo::On {
            return None;
        }
        lock(&self.sudo).as_ref().map(|s| s.expose().to_string())
    }

    /// The sudo program (`machine.sudo_path`, else `sudo` from `PATH`).
    pub fn sudo_path(&self) -> String {
        self.config()
            .machine
            .sudo_path
            .unwrap_or_else(|| "sudo".into())
    }

    /// `text` without the sudo password.
    pub fn scrub(&self, text: String) -> String {
        match lock(&self.sudo).as_ref() {
            Some(s) => scrub(&text, s.expose()).unwrap_or(text),
            None => text,
        }
    }

    /// Turns the switch on once `sudo -v` accepts `password`. A wrong
    /// password leaves the switch as it was.
    pub async fn sudo_switch_on(&self, by: Writer<'_>, password: String) -> Result<u64, SetError> {
        let password = Secret::new(password);
        if !cfg!(target_os = "linux") {
            return Err(SetError::Invalid(
                "the sudo switch works on Linux only".into(),
            ));
        }
        if let Writer::Center(c) = by {
            let grant = self.config().center(c).map(|e| e.settings);
            if grant != Some(nerve_policy::config::SettingsGrant::Write) {
                return Err(SetError::Forbidden(
                    "this node does not let this center change its settings".into(),
                ));
            }
        }
        if password.expose().is_empty() || password.expose().contains('\n') {
            return Err(SetError::Invalid(
                "the sudo password is empty or has a line break".into(),
            ));
        }
        crate::exec::sudo_check(&self.sudo_path(), password.expose())
            .await
            .map_err(SetError::Invalid)?;
        // Password and config change together, so `settle_sudo` never sees
        // one without the other.
        let r = {
            let mut store = lock(&self.store);
            *lock(&self.sudo) = Some(password);
            let r = store.set_sudo(by, Sudo::On);
            if r.is_err() {
                *lock(&self.sudo) = None;
            }
            r
        };
        self.bump();
        r
    }

    /// Turns the switch off and drops the password and any open offer.
    pub fn sudo_switch_off(&self, by: Writer<'_>) -> Result<u64, SetError> {
        if let Writer::Center(c) = by {
            let grant = self.config().center(c).map(|e| e.settings);
            if grant != Some(nerve_policy::config::SettingsGrant::Write) {
                return Err(SetError::Forbidden(
                    "this node does not let this center change its settings".into(),
                ));
            }
        }
        let r = {
            let mut store = lock(&self.store);
            *lock(&self.sudo) = None;
            store.set_sudo(by, Sudo::Off)
        };
        lock(&self.sudo_offers).clear();
        self.bump();
        r
    }

    /// Brings the config and the held password in line: a config that says
    /// on without a password (a restart, an edited file) is switched off; a
    /// config that says off drops the password.
    pub fn settle_sudo(&self) {
        let mut store = lock(&self.store);
        let on = store.config().machine.sudo == Sudo::On;
        let mut held = lock(&self.sudo);
        if on && held.is_none() {
            drop(held);
            if let Err(e) = store.set_sudo(Writer::Local, Sudo::Off) {
                tracing::warn!("cannot switch sudo off: {e:?}");
            }
            drop(store);
            self.bump();
        } else if !on && held.is_some() {
            *held = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_plain_and_escaped_copies() {
        assert_eq!(scrub("no secret here", "pw\"1"), None);
        assert_eq!(
            scrub("a pw\"1 b", "pw\"1").as_deref(),
            Some("a [redacted] b")
        );
        let frame = serde_json::json!({"stdout": "pw\"1\n"}).to_string();
        let out = scrub(&frame, "pw\"1").unwrap();
        assert!(!out.contains("pw"), "{out}");
        assert_eq!(scrub("x", ""), None);
    }
}
