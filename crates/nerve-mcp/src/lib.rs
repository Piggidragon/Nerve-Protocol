//! The Nerve center as an MCP server (spec/harness.md).
//!
//! `nerve-mcp` is started by a harness like any MCP server. It pairs nodes,
//! holds their links, maps their capabilities to MCP tools and serves the
//! center web UI. It has no subcommands: everything is set by flags or
//! `NERVE_*` variables in the harness's MCP entry, or in the web UI.
//
// OPEN POINT: whether harnesses get Nerve through a plugin or through MCP is
// not decided. 0.0.1 ships the MCP server only; the Pithagoras adapter and a
// generic MCP example adapter are left out.

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
