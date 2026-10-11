//! The Nerve center as an MCP server (spec/harness.md).
//!
//! `nerve-center` is started by a harness like any MCP server. It pairs nodes,
//! holds their links, maps their capabilities to MCP tools and serves the
//! center web UI. It has no subcommands: everything is set by flags or
//! `NERVE_*` variables in the harness's MCP entry, or in the web UI.
//
// Harnesses get Nerve through MCP only: this MCP server is the whole
// integration surface in 0.0.1. Native plugins are a backlog item.

pub mod attach;
pub mod center;
pub mod config;
pub mod link;
pub mod listen;
pub mod mcp;
pub mod pairing;
pub mod server;
pub mod store;
pub mod tools;
pub mod ui;
pub mod util;
