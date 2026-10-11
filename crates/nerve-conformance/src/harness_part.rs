//! The harness part: checks the MCP server surface a harness sees. A skeleton
//! in 0.0.1.
//!
//! Harnesses integrate through MCP only (spec/harness.md); native plugins are
//! a backlog item. This part only lists the checks it will run, and reports
//! each as not run. `nerve-center`'s MCP side is tested by its own tests and the
//! end-to-end tests of this crate.

use crate::Report;

/// The checks the harness part will run, with the spec section of each.
pub const PLANNED: &[(&str, &str)] = &[
    (
        "harness 1",
        "the MCP session says hello with role harness and its token",
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
    let mut r = Report::new("harness");
    for (section, name) in PLANNED {
        r.skip(section, name, "the harness part is a skeleton in 0.0.1");
    }
    r
}
