//! Conformance runner of the Nerve Protocol (docs/dev/spec/conformance.md).
//!
//! Four parts, each a library call that returns a [`Report`]:
//!
//! - [`center_part`] checks a center over the wire, acting as a node (the
//!   [`echo`] node).
//! - [`node_part`] checks a node, acting as a center ([`fake_center`]).
//! - [`harness_part`] will check the MCP server surface a harness sees; it
//!   is a skeleton.
//! - [`provider_part`] checks a node's capability provider attach, acting
//!   as a center and as a provider on the node's control socket (Unix).
//!
//! There is no runner binary (the workspace ships exactly
//! `nerve-center` and `nerve-node`); the parts run from `cargo test` in this
//! crate, against the echo node, the fake center and the real binaries.

pub mod center_part;
pub mod echo;
pub mod fake_center;
pub mod harness_part;
pub mod node_part;
#[cfg(unix)]
pub mod provider_part;
pub mod wire;

use std::fmt;

/// The result of one check.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The section of docs/dev/spec/protocol.md the check tests, like "4.2".
    pub section: &'static str,
    pub name: &'static str,
    pub result: Result<(), String>,
}

/// What a part found.
#[derive(Debug, Clone)]
pub struct Report {
    pub part: &'static str,
    pub outcomes: Vec<Outcome>,
}

impl Report {
    pub fn new(part: &'static str) -> Report {
        Report {
            part,
            outcomes: Vec::new(),
        }
    }

    pub fn check(&mut self, section: &'static str, name: &'static str, result: Result<(), String>) {
        self.outcomes.push(Outcome {
            section,
            name,
            result,
        });
    }

    /// Records a check that could not run because an earlier step failed.
    pub fn skip(&mut self, section: &'static str, name: &'static str, why: &str) {
        self.check(section, name, Err(format!("not run: {why}")));
    }

    pub fn failed(&self) -> Vec<&Outcome> {
        self.outcomes.iter().filter(|o| o.result.is_err()).collect()
    }

    pub fn ok(&self) -> bool {
        self.failed().is_empty() && !self.outcomes.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let failed = self.failed().len();
        writeln!(
            f,
            "{} part: {} checks, {} passed, {} failed",
            self.part,
            self.outcomes.len(),
            self.outcomes.len() - failed,
            failed
        )?;
        for o in &self.outcomes {
            match &o.result {
                Ok(()) => writeln!(f, "  ok   §{} {}", o.section, o.name)?,
                Err(e) => writeln!(f, "  FAIL §{} {}: {e}", o.section, o.name)?,
            }
        }
        Ok(())
    }
}

/// `Err(msg)` unless `cond`.
pub(crate) fn ensure(cond: bool, msg: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg.into()) }
}
