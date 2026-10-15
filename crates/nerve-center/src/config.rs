//! Flags and `NERVE_*` variables. A harness starts `nerve-center` from its MCP
//! entry, so every setting is a flag or a variable there. The only
//! subcommands are `backup` and `restore`, which the owner runs by hand on a
//! center that is not running (`restore`) or may be (`backup`).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use nerve_transport::log::Level;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum McpMode {
    /// MCP over this process's stdin and stdout.
    Stdio,
    /// MCP over Streamable HTTP at `--mcp-listen`.
    Http,
    /// No MCP of its own: the center only, for harnesses that attach.
    None,
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "nerve-center",
    version,
    about = "The Nerve center as an MCP server. Start it from a harness's MCP configuration."
)]
pub struct Args {
    /// The state folder (identity, paired nodes, statistics).
    #[arg(long, env = "NERVE_STATE_DIR", global = true)]
    pub state_dir: Option<PathBuf>,
    /// The center name shown to nodes and in the web UI.
    #[arg(long, env = "NERVE_NAME")]
    pub name: Option<String>,
    /// Where nodes reach the center.
    #[arg(long, env = "NERVE_LISTEN", default_value = "0.0.0.0:7443")]
    pub listen: String,
    /// The URL put into pairing links; https://<host name>:<port> by default.
    #[arg(long, env = "NERVE_PUBLIC_URL")]
    pub public_url: Option<String>,
    /// Serve nodes over plain HTTP; only on a loopback `--listen`, for tests
    /// and nodes on the same machine.
    #[arg(long, env = "NERVE_PLAIN_LOOPBACK")]
    pub plain_loopback: bool,
    /// The web UI address, or `off`.
    #[arg(long, env = "NERVE_UI", default_value = "127.0.0.1:7480")]
    pub ui: String,
    /// Let the web UI in without a login. It logs in with a harness token
    /// otherwise; only for a UI on loopback, a UI beyond it always needs one.
    #[arg(long, env = "NERVE_UI_NO_LOGIN")]
    pub ui_no_login: bool,
    /// How harnesses talk to the center.
    #[arg(long, env = "NERVE_MCP", value_enum, default_value = "stdio")]
    pub mcp: McpMode,
    /// The HTTP MCP address (with `--mcp http`).
    #[arg(long, env = "NERVE_MCP_LISTEN", default_value = "127.0.0.1:7481")]
    pub mcp_listen: String,
    /// A harness token: the bearer token of the HTTP MCP endpoint and the
    /// secret that logs in to the web UI, besides tokens made in the web UI.
    #[arg(long, env = "NERVE_HARNESS_TOKEN", hide_env_values = true)]
    pub harness_token: Option<String>,
    /// The log level (error, warn, info, debug). Without it the level set in
    /// the web UI holds, info at first; with it this level holds for this run.
    #[arg(long, env = "NERVE_LOG")]
    pub log: Option<Level>,
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

/// What the owner runs by hand; a harness never does.
#[derive(Debug, Clone, Subcommand)]
pub enum Cmd {
    /// Write the center's identity and state (its certificate and key, the paired nodes, the harness tokens' hashes and the statistics) to a file that a passphrase protects, to keep or to move the center to another machine.
    Backup {
        /// The file to write. It is private to you (mode 0600).
        file: PathBuf,
        /// Replace the file when it exists.
        #[arg(long)]
        overwrite: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Put the identity and state of a backup in place of this center's. No center may run on the state folder.
    Restore {
        /// The backup file.
        file: PathBuf,
        /// Replace a center here that is not the one the backup is of.
        #[arg(long)]
        replace: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
}

impl Args {
    pub fn state_dir(&self) -> PathBuf {
        self.state_dir.clone().unwrap_or_else(default_state_dir)
    }

    pub fn ui_off(&self) -> bool {
        self.ui.eq_ignore_ascii_case("off")
    }

    /// The public URL, from the flag or from the host name and the port.
    pub fn public_url(&self, port: u16) -> String {
        if let Some(u) = &self.public_url {
            return u.clone();
        }
        if self.plain_loopback {
            return format!("http://127.0.0.1:{port}");
        }
        format!("https://{}:{port}", crate::center::host_name())
    }
}

/// `$XDG_STATE_HOME/nerve-center`, `~/.local/state/nerve-center`, or on Windows
/// `%LOCALAPPDATA%\nerve-center`.
pub fn default_state_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(d) = std::env::var_os("LOCALAPPDATA")
    {
        return PathBuf::from(d).join("nerve-center");
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("nerve-center");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/state/nerve-center")
}

/// Whether an address like `127.0.0.1:7480` or `[::1]:7480` is loopback.
pub fn is_loopback(addr: &str) -> bool {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a.ip().is_loopback(),
        Err(_) => addr.starts_with("localhost:"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_defaults() {
        let a = Args::try_parse_from(["nerve-center"]).unwrap();
        assert_eq!(a.mcp, McpMode::Stdio);
        assert_eq!(a.listen, "0.0.0.0:7443");
        assert!(!a.ui_off());
        let a = Args::try_parse_from([
            "nerve-center",
            "--plain-loopback",
            "--ui",
            "off",
            "--mcp",
            "none",
        ])
        .unwrap();
        assert_eq!(a.public_url(9), "http://127.0.0.1:9");
        assert!(a.ui_off());
        // The web UI logs in with the harness token; there is no password of
        // its own, and the login is switched off by a flag alone.
        assert!(!a.ui_no_login);
        assert!(Args::try_parse_from(["nerve-center", "--ui-password", "x"]).is_err());
        let a = Args::try_parse_from(["nerve-center", "--ui-no-login"]).unwrap();
        assert!(a.ui_no_login);
        // The level comes from the flag, or else from the settings.
        assert_eq!(a.log, None);
        let a = Args::try_parse_from(["nerve-center", "--log", "Debug"]).unwrap();
        assert_eq!(a.log, Some(Level::Debug));
        assert!(Args::try_parse_from(["nerve-center", "--log", "loud"]).is_err());
        // The only subcommands are backup and restore: anything else
        // positional is refused.
        assert!(Args::try_parse_from(["nerve-center", "pair"]).is_err());
        assert!(a.cmd.is_none());
        assert!(
            is_loopback("127.0.0.1:7480") && is_loopback("[::1]:1") && !is_loopback("0.0.0.0:7480")
        );
    }
}
