//! The node's desktop app: a window that drives `nerve-node`. Every action
//! runs the CLI (the same program, [`runner`]) and shows its JSON answer
//! ([`view`]), so the app has the CLI's checks and audit records and keeps
//! no settings of its own.

slint::include_modules!();

pub mod app;
pub mod broker;
#[cfg(windows)]
pub mod console;
pub mod deps;
pub mod dialog;
pub mod headless;
pub mod instance;
pub mod parts;
pub mod runner;
pub mod settings;
pub mod view;
