//! A call's scope (docs/dev/spec/protocol.md §5.1): the actions a center lets
//! one call do, for instance those of the harness token the call came with.
//!
//! A scope only narrows. The node decides a call by its policy for the
//! calling center as always, and refuses one whose action the scope does not
//! name before it asks the policy. A scope that names an action the policy
//! refuses changes nothing, so a scoped call can never do more than the
//! center's entry allows. A call without a scope is not narrowed.

use serde::{Deserialize, Serialize};

use crate::descriptor::valid_member_name;

/// The most entries a scope holds.
pub const ENTRIES_MAX: usize = 32;
/// The longest capability or action name in an entry, in bytes.
pub const NAME_MAX_BYTES: usize = 64;

/// The actions a call may do: each entry is a capability (`fs`, all of its
/// actions) or one action of it (`fs.read`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(Vec<String>);

impl Scope {
    /// A scope from entries as a person typed them: blank ones are dropped,
    /// the others trimmed and kept once, in their order, and then checked.
    pub fn parse<I, S>(entries: I) -> Result<Scope, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out: Vec<String> = Vec::new();
        for e in entries {
            let e = e.as_ref().trim();
            if !e.is_empty() && !out.iter().any(|o| o == e) {
                out.push(e.to_string());
            }
        }
        let s = Scope(out);
        s.check()?;
        Ok(s)
    }

    /// Checks what serde cannot: 1 to [`ENTRIES_MAX`] entries, each `<cap>`
    /// or `<cap>.<action>` with names of letters, digits and `-` of at most
    /// [`NAME_MAX_BYTES`]. An empty scope is refused rather than read as
    /// "nothing": a center that wants a call to do nothing does not send it.
    pub fn check(&self) -> Result<(), String> {
        if self.0.is_empty() {
            return Err("a scope names at least one capability or action".into());
        }
        if self.0.len() > ENTRIES_MAX {
            return Err(format!("a scope has at most {ENTRIES_MAX} entries"));
        }
        for e in &self.0 {
            let ok = match e.split_once('.') {
                Some((cap, action)) => name_ok(cap) && name_ok(action),
                None => name_ok(e),
            };
            if !ok {
                return Err(format!(
                    "the scope entry {:?} is not <cap> or <cap>.<action> (letters, digits and -, at most {NAME_MAX_BYTES} each)",
                    e.chars().take(80).collect::<String>()
                ));
            }
        }
        Ok(())
    }

    pub fn entries(&self) -> &[String] {
        &self.0
    }

    /// Whether an entry names `cap.action`, or `cap` as a whole.
    pub fn allows(&self, cap: &str, action: &str) -> bool {
        self.0.iter().any(|e| match e.split_once('.') {
            Some((c, a)) => c == cap && a == action,
            None => e == cap,
        })
    }

    /// Whether an entry names `cap` or one of its actions.
    pub fn touches(&self, cap: &str) -> bool {
        self.0
            .iter()
            .any(|e| e.split_once('.').map_or(e.as_str(), |(c, _)| c) == cap)
    }

    /// Why `cap.action` is refused under this scope, or `None` when an entry
    /// names it.
    pub fn refusal(&self, cap: &str, action: &str) -> Option<String> {
        (!self.allows(cap, action)).then(|| {
            format!(
                "{cap}.{action} is outside the scope of this call ({}); the center narrowed it, and no rule or mode on the node widens a scope",
                self
            )
        })
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join(", "))
    }
}

fn name_ok(name: &str) -> bool {
    name.len() <= NAME_MAX_BYTES && valid_member_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_name_a_capability_or_one_action() {
        let s = Scope::parse(["fs.read", " fs.list ", "", "exec", "fs.read"]).unwrap();
        assert_eq!(s.entries(), ["fs.read", "fs.list", "exec"]);
        assert!(s.allows("fs", "read"));
        assert!(s.allows("fs", "list"));
        assert!(!s.allows("fs", "write"));
        assert!(s.allows("exec", "run"));
        assert!(s.allows("exec", "signal"));
        assert!(!s.allows("settings", "set"));
        // A capability entry is not a prefix: `fs` does not name `fs2`.
        let fs = Scope::parse(["fs"]).unwrap();
        assert!(!fs.allows("fs2", "read"));
        assert!(fs.touches("fs") && !fs.touches("fs2"));
        assert!(s.touches("exec") && !s.touches("settings"));
    }

    #[test]
    fn a_refusal_names_the_action_and_the_scope() {
        let s = Scope::parse(["fs.read"]).unwrap();
        assert_eq!(s.refusal("fs", "read"), None);
        let why = s.refusal("fs", "write").unwrap();
        assert!(why.starts_with("fs.write is outside the scope"), "{why}");
        assert!(why.contains("(fs.read)"), "{why}");
    }

    #[test]
    fn malformed_scopes_are_refused() {
        for bad in [
            vec![],
            vec!["fs_read"],
            vec!["fs.read.x"],
            vec!["fs."],
            vec![".read"],
            vec!["*"],
            vec!["fs.*"],
            vec!["fs read"],
        ] {
            assert!(Scope::parse(bad.clone()).is_err(), "{bad:?}");
        }
        let long = "a".repeat(NAME_MAX_BYTES + 1);
        assert!(Scope::parse([long.as_str()]).is_err());
        assert!(Scope::parse([format!("fs.{long}")]).is_err());
        assert!(Scope::parse(["a".repeat(NAME_MAX_BYTES)]).is_ok());
        let many: Vec<String> = (0..=ENTRIES_MAX).map(|i| format!("c{i}")).collect();
        assert!(Scope::parse(&many).is_err());
        assert!(Scope::parse(&many[..ENTRIES_MAX]).is_ok());
        // Serde takes any list; `check` is what refuses.
        let s: Scope = serde_json::from_value(serde_json::json!([])).unwrap();
        assert!(s.check().is_err());
    }
}
