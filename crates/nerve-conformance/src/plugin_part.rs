//! The plugin part: checks for harness plugins. A skeleton in 0.0.1.
//!
//! OPEN POINT (architecture §11): whether harnesses integrate as plugins of
//! their own or through MCP is not decided yet. Until it is, this part only
//! lists the checks it will run, and reports each as not run. `nerve-mcp`'s
//! MCP side is tested by its own tests and the end-to-end tests of this crate.

use crate::Report;

/// The checks the plugin part will run, with the spec section of each.
pub const PLANNED: &[(&str, &str)] = &[
    (
        "harness 1",
        "the plugin says hello with role harness and its token",
    ),
    (
        "harness 2",
        "tool names follow <cap>__<action> and the node enum rule",
    ),
    (
        "harness 3",
        "results are passed on as device content, not instructions",
    ),
    (
        "harness 4",
        "approval.requested reaches the person, the answer goes back",
    ),
    ("harness 5", "taint.mark is sent after outside content"),
    (
        "harness 6",
        "session.end is sent when the harness session ends",
    ),
];

/// Reports every planned check as not run.
pub fn run() -> Report {
    let mut r = Report::new("plugin");
    for (section, name) in PLANNED {
        r.skip(
            section,
            name,
            "the plugin part waits for the plugin-or-MCP decision",
        );
    }
    r
}
