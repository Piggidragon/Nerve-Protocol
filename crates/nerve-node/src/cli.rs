//! The `nerve-node` command line (architecture §8). Commands talk to the
//! running daemon over the control socket; when none runs they edit the
//! config file directly through the same [`SettingsStore`], which signs it.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use nerve_policy::audit::AuditLog;
use nerve_policy::config::{Access, CapSetting, Folder, SettingsGrant, USER_MAX_MS};
use nerve_policy::{Mode, NodeConfig, SetError, SettingsStore, rules, sudo_command};
use nerve_proto::link::PairLink;
use nerve_sandbox::stubs::NOT_DONE;

use crate::daemon::{Daemon, NodeOptions};
use crate::paths::NodePaths;

#[derive(Debug, Parser)]
#[command(
    name = "nerve-node",
    version,
    about = "Links this machine to its Nerve centers."
)]
pub struct Cli {
    /// Where node.toml and the keys live [env: NERVE_CONFIG_DIR] [default: ~/.config/nerve]
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    /// Where the control socket and the audit log live [env: NERVE_STATE_DIR] [default: ~/.local/state/nerve]
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Picks one paired center; required when several are paired.
#[derive(Debug, Args, Clone, Default)]
pub struct CenterArg {
    /// The paired center this is about (needed when several are paired).
    #[arg(long)]
    pub center: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the node daemon.
    Run,
    /// Pair with a center from its pairing link.
    Pair {
        /// The pairing link the center showed.
        link: String,
        /// The local name for the center (default: the center's own name).
        #[arg(long)]
        name: Option<String>,
        /// Confirm without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Forget a center and its key.
    Unpair(CenterArg),
    /// List the paired centers.
    Centers,
    /// Show the daemon and its links.
    Status,
    /// Set a center's mode: allowlist, folder or user (user ends after
    /// --hours, at most 8).
    Mode {
        /// `allowlist` (only allow rules let a call through), `folder` (full
        /// access in its folders) or `user` (full access as the user).
        mode: String,
        /// How long user mode lasts, in hours (default and maximum: 8).
        #[arg(long)]
        hours: Option<u64>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Add or remove a folder a center may use.
    #[command(subcommand)]
    Folder(FolderCmd),
    /// Set a capability or action (`fs`, `exec.run`) to on, off or hidden.
    Caps {
        /// The capability (`fs`) or action (`exec.run`).
        cap: String,
        /// `on`, `off` or `hidden`.
        setting: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Let a center change settings (`settings off|write`).
    Grant {
        /// What to grant; only `settings` exists.
        what: String,
        /// `off` or `write`.
        value: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Read or change node.toml by dotted key (`center.<name>.policy.mode`).
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Add a deny rule for a command (`deny <command> [--wildcard]`). It
    /// refuses in every mode and wins over any allow rule.
    Deny {
        /// The command line to forbid.
        command: String,
        /// Match every command that starts with the same program.
        #[arg(long)]
        wildcard: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Add an allow rule for a command (`allow <command> [--wildcard]`); a
    /// `sudo` command goes on the sudo allow list. Allow rules count in
    /// allowlist mode only. Rules for files and other actions go in with
    /// `config add center.<name>.policy.allow <rule>`.
    Allow {
        /// The command line to allow.
        command: String,
        /// Match every command that starts with the same program.
        #[arg(long)]
        wildcard: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Stop everything: every link ends, nothing runs until `unlock`.
    Panic,
    /// Undo `panic`.
    Unlock,
    /// Show the local audit log.
    Audit {
        /// Keep running and print new entries as they arrive.
        #[arg(long)]
        follow: bool,
        /// Only denied and forbidden calls.
        #[arg(long)]
        denied: bool,
    },
    /// Set or clear the HTTP proxy used to reach centers.
    #[command(subcommand)]
    Proxy(ProxyCmd),
    /// Install as a service (not done in 0.0.1).
    Install,
    /// Set up the machine (not done in 0.0.1).
    Setup {
        /// Create a dedicated user for the node.
        #[arg(long)]
        create_user: bool,
    },
    /// The sudo switch: whether commands on the sudo allow list may run.
    #[command(subcommand)]
    Sudo(SudoCmd),
    /// Update the node (not done in 0.0.1).
    Update,
    /// Remove the node (not done in 0.0.1).
    Uninstall,
}

#[derive(Debug, Subcommand)]
pub enum SudoCmd {
    /// Turn sudo on: asks for the sudo password, which the node checks with
    /// `sudo -v` and keeps in memory only. Only commands the sudo allow list
    /// names run with sudo.
    On,
    /// Turn sudo off and drop the password.
    Off,
    /// Show whether sudo is on.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum FolderCmd {
    /// Let a center use a folder (read-only unless `--rw`).
    Add {
        /// The folder.
        path: PathBuf,
        /// Allow writing, not only reading.
        #[arg(long)]
        rw: bool,
        /// Allow running programs from the folder.
        #[arg(long)]
        execute: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Take a folder away from a center.
    Remove {
        /// The folder.
        path: PathBuf,
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print one setting.
    Get {
        /// The dotted key, for example `center.<name>.policy.mode`.
        key: String,
    },
    /// Change one setting.
    Set {
        /// The dotted key.
        key: String,
        /// The new value.
        value: String,
    },
    /// Remove one setting (its default applies again).
    Unset {
        /// The dotted key.
        key: String,
    },
    /// Append a value to a list.
    Add {
        /// The dotted key of the list.
        key: String,
        /// The value to append.
        value: String,
    },
    /// Remove a value from a list.
    Remove {
        /// The dotted key of the list.
        key: String,
        /// The value to remove.
        value: String,
    },
    /// Take node.toml as it is now, after the node refused it because it was
    /// changed outside nerve-node. Look at the file first: whatever changed
    /// it gets its way.
    Accept,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCmd {
    /// Reach centers through this HTTP proxy.
    Set {
        /// The proxy URL.
        url: String,
        /// A header for the CONNECT request, `Name: value`.
        #[arg(long = "header")]
        headers: Vec<String>,
    },
    /// Reach centers directly again.
    Clear,
}

/// The command list as `nerve-node --help` has it, for anything that shows
/// the commands elsewhere (the center's help page). It is read from the
/// [`Cli`] definition above, so a new command or flag shows up there by
/// being written once.
#[derive(Debug, Clone, Serialize)]
pub struct Help {
    /// What the node is.
    pub about: String,
    /// Options every command takes.
    pub global: Vec<ArgHelp>,
    /// Every command and sub-command, in the order `--help` lists them.
    pub commands: Vec<CommandHelp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandHelp {
    /// The words after `nerve-node`: `status`, `folder add`.
    pub name: String,
    /// The usage line, for example `nerve-node folder add [OPTIONS] <PATH>`.
    pub usage: String,
    /// The explanation: the doc comment of the command.
    pub about: String,
    /// Its own arguments and flags, without the global ones.
    pub args: Vec<ArgHelp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArgHelp {
    /// How it is written: `--hours <HOURS>`, `<PATH>`, `--rw`.
    pub name: String,
    /// The explanation; empty when the argument has none.
    pub about: String,
}

/// Reads [`Help`] from the [`Cli`] definition.
pub fn help() -> Help {
    let mut root = Cli::command();
    root.build();
    let mut commands = Vec::new();
    collect_help(&root, "", &mut commands);
    Help {
        about: root
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default(),
        global: root
            .get_arguments()
            .filter(|a| a.is_global_set())
            .map(arg_help)
            .collect(),
        commands,
    }
}

fn collect_help(parent: &clap::Command, prefix: &str, out: &mut Vec<CommandHelp>) {
    for sub in parent.get_subcommands() {
        // clap adds a `help` sub-command of its own to every level.
        if sub.get_name() == "help" || sub.is_hide_set() {
            continue;
        }
        let name = if prefix.is_empty() {
            sub.get_name().to_string()
        } else {
            format!("{prefix} {}", sub.get_name())
        };
        let usage = sub.clone().render_usage().to_string();
        out.push(CommandHelp {
            usage: usage.strip_prefix("Usage: ").unwrap_or(&usage).to_string(),
            about: sub.get_about().map(ToString::to_string).unwrap_or_default(),
            args: sub
                .get_arguments()
                .filter(|a| {
                    !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version")
                })
                .map(arg_help)
                .collect(),
            name: name.clone(),
        });
        collect_help(sub, &name, out);
    }
}

fn arg_help(a: &clap::Arg) -> ArgHelp {
    let value = a
        .get_value_names()
        .and_then(|v| v.first())
        .map_or_else(|| a.get_id().as_str().to_uppercase(), ToString::to_string);
    let name = match a.get_long() {
        Some(long) if a.get_action().takes_values() => format!("--{long} <{value}>"),
        Some(long) => format!("--{long}"),
        None => format!("<{value}>"),
    };
    ArgHelp {
        name,
        about: a.get_help().map(ToString::to_string).unwrap_or_default(),
    }
}

/// Reads the config: from the daemon when it runs, else from the file.
/// The version is the daemon's (`None` when read from the file).
pub async fn read_config(paths: &NodePaths) -> Result<(NodeConfig, Option<u64>), String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "config.read", json!({})).await {
        Ok(v) => {
            let text = v["config"].as_str().unwrap_or_default();
            return Ok((NodeConfig::parse(text)?, v["version"].as_u64()));
        }
        Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
        Err(_) => {}
    }
    Ok((
        SettingsStore::peek(&paths.config_file(), &paths.config_key())?,
        None,
    ))
}

/// Changes the config: through the daemon (retrying when someone else wrote
/// meanwhile), or directly in the file when no daemon runs.
pub async fn edit(
    paths: &NodePaths,
    f: impl Fn(&mut NodeConfig) -> Result<(), String>,
) -> Result<NodeConfig, String> {
    #[cfg(unix)]
    for _ in 0..5 {
        let sock = paths.ctl_socket();
        let read = match nerve_transport::ctl::call(&sock, "config.read", json!({})).await {
            Ok(v) => v,
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => break,
            Err(e) => return Err(e),
        };
        let mut cfg = NodeConfig::parse(read["config"].as_str().unwrap_or_default())?;
        f(&mut cfg)?;
        let params = json!({"config": cfg.to_toml(), "if_version": read["version"]});
        match nerve_transport::ctl::call(&sock, "config.write", params).await {
            Ok(_) => return Ok(cfg),
            Err(e) if e.starts_with("conflict") => continue,
            Err(e) => return Err(e),
        }
    }
    let mut store = SettingsStore::open(
        paths.config_file(),
        paths.config_key(),
        AuditLog::new(paths.audit_log()),
    )?;
    match store.update(f) {
        Ok(_) => Ok(store.config().clone()),
        Err(SetError::Conflict { .. }) => Err("the config changed meanwhile; try again".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The center a per-center command means: the one named, or the only one.
pub fn pick_center(cfg: &NodeConfig, given: &CenterArg) -> Result<String, String> {
    if let Some(n) = &given.center {
        return cfg
            .center(n)
            .map(|c| c.name.clone())
            .ok_or_else(|| format!("no center named {n}"));
    }
    match cfg.centers.as_slice() {
        [] => Err("no center is paired".into()),
        [one] => Ok(one.name.clone()),
        many => Err(format!(
            "several centers are paired; pick one with --center ({})",
            many.iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Changes one center's entry.
async fn edit_center(
    paths: &NodePaths,
    center: &CenterArg,
    f: impl Fn(&mut nerve_policy::CenterEntry) -> Result<(), String>,
) -> Result<String, String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    edit(paths, |c| {
        let e = c
            .center_mut(&name)
            .ok_or_else(|| format!("no center named {name}"))?;
        f(e)
    })
    .await?;
    Ok(name)
}

fn push_unique(list: &mut Vec<String>, rule: &str) {
    if !list.iter().any(|r| r == rule) {
        list.push(rule.to_string());
    }
}

/// Runs one command line, writing what it shows to `out`.
pub async fn execute(cli: Cli, out: &mut dyn Write) -> Result<(), String> {
    let paths = NodePaths::from_args(cli.config_dir, cli.state_dir);
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    match cli.cmd {
        Cmd::Run => {
            let mut opts = NodeOptions::new(paths);
            opts.exe = std::env::current_exe().ok();
            Daemon::run(opts).await
        }
        Cmd::Pair { link, name, yes } => {
            let link = PairLink::parse(&link)?;
            w(out, crate::pair::preview(&link, name.as_deref()));
            if !yes && !confirm(out)? {
                return Err("not paired".into());
            }
            let e = crate::pair::pair(&paths, &link, name.as_deref()).await?;
            w(out, format!("paired with {} as {}", e.url, e.name));
            Ok(())
        }
        Cmd::Unpair(center) => {
            let (cfg, _) = read_config(&paths).await?;
            let name = pick_center(&cfg, &center)?;
            edit(&paths, |c| {
                c.centers.retain(|e| e.name != name);
                Ok(())
            })
            .await?;
            let _ = std::fs::remove_file(paths.key_file(&name));
            w(out, format!("unpaired {name}"));
            Ok(())
        }
        Cmd::Centers => {
            let (cfg, _) = read_config(&paths).await?;
            if cfg.centers.is_empty() {
                w(out, "no center is paired".into());
            }
            let now = crate::now_ms();
            for c in &cfg.centers {
                let mut flags = Vec::new();
                for (on, f) in [
                    (c.paused, "paused"),
                    (c.revoked, "revoked"),
                    (c.unknown, "unknown"),
                ] {
                    if on {
                        flags.push(f);
                    }
                }
                w(
                    out,
                    format!(
                        "{}  {}  mode {}  settings {}{}",
                        c.name,
                        c.url,
                        c.policy.mode_at(now).as_str(),
                        enum_str(&c.settings),
                        if flags.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", flags.join(", "))
                        }
                    ),
                );
            }
            Ok(())
        }
        Cmd::Status => {
            #[cfg(unix)]
            match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
                Ok(v) => {
                    w(
                        out,
                        format!(
                            "daemon: running (confinement {})",
                            v["confinement"].as_str().unwrap_or("?")
                        ),
                    );
                    if v["locked"] == true {
                        w(
                            out,
                            "LOCKED (panic): nothing runs until `nerve-node unlock`".into(),
                        );
                    }
                    for c in v["centers"].as_array().into_iter().flatten() {
                        w(
                            out,
                            format!(
                                "{}  {}  mode {}",
                                c["name"].as_str().unwrap_or_default(),
                                c["status"].as_str().unwrap_or_default(),
                                c["mode"].as_str().unwrap_or_default(),
                            ),
                        );
                    }
                    return Ok(());
                }
                Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
                Err(_) => {}
            }
            let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key())?;
            w(out, "daemon: not running".into());
            if cfg.locked {
                w(
                    out,
                    "LOCKED (panic): nothing runs until `nerve-node unlock`".into(),
                );
            }
            for c in &cfg.centers {
                w(out, format!("{}  {}", c.name, c.url));
            }
            Ok(())
        }
        Cmd::Mode {
            mode,
            hours,
            center,
        } => {
            let m = match mode.as_str() {
                "allowlist" => Mode::Allowlist,
                "folder" => Mode::Folder,
                "user" => Mode::User,
                other => {
                    return Err(format!("unknown mode {other} (allowlist, folder or user)"));
                }
            };
            if hours.is_some() && m != Mode::User {
                return Err("--hours only goes with user".into());
            }
            let until = (m == Mode::User).then(|| {
                let ms = hours.map_or(USER_MAX_MS, |h| h.saturating_mul(3_600_000));
                crate::now_ms() + ms
            });
            if hours.is_some_and(|h| h.saturating_mul(3_600_000) > USER_MAX_MS) {
                return Err("user mode lasts at most 8 hours".into());
            }
            let name = edit_center(&paths, &center, |e| {
                e.policy.mode = m;
                e.policy.user_until = until;
                Ok(())
            })
            .await?;
            w(out, format!("{name}: mode {}", m.as_str()));
            Ok(())
        }
        Cmd::Folder(FolderCmd::Add {
            path,
            rw,
            execute,
            center,
        }) => {
            let real = resolve_folder(&path)?;
            let mode = std::cell::Cell::new(Mode::Folder);
            let name = edit_center(&paths, &center, |e| {
                e.policy.folders.retain(|f| f.path != real);
                e.policy.folders.push(Folder {
                    path: real.clone(),
                    access: if rw { Access::Rw } else { Access::Ro },
                    execute,
                });
                mode.set(e.policy.mode);
                Ok(())
            })
            .await?;
            w(out, format!("{name}: folder {}", resolve_folder(&path)?));
            let mode = mode.get();
            if mode != Mode::Folder {
                w(
                    out,
                    format!(
                        "note: folders count in folder mode; {name} is in {} mode (`nerve-node mode folder`)",
                        mode.as_str()
                    ),
                );
            }
            Ok(())
        }
        Cmd::Folder(FolderCmd::Remove { path, center }) => {
            let real = resolve_folder(&path)?;
            let given = path.display().to_string();
            let name = edit_center(&paths, &center, |e| {
                let before = e.policy.folders.len();
                e.policy
                    .folders
                    .retain(|f| f.path != real && f.path != given);
                if e.policy.folders.len() == before {
                    return Err(format!("{real} is not a folder of this center"));
                }
                Ok(())
            })
            .await?;
            w(out, format!("{name}: removed {real}"));
            Ok(())
        }
        Cmd::Caps {
            cap,
            setting,
            center,
        } => {
            let s = CapSetting::parse(&setting)
                .ok_or_else(|| format!("unknown setting {setting} (on, off or hidden)"))?;
            let name = edit_center(&paths, &center, |e| {
                e.policy.caps.insert(cap.clone(), s);
                Ok(())
            })
            .await?;
            w(out, format!("{name}: {cap} {setting}"));
            Ok(())
        }
        Cmd::Grant {
            what,
            value,
            center,
        } => {
            let name = match what.as_str() {
                "settings" => {
                    let g: SettingsGrant = parse_enum(&value, "off or write")?;
                    edit_center(&paths, &center, |e| {
                        e.settings = g;
                        Ok(())
                    })
                    .await?
                }
                other => return Err(format!("unknown grant {other} (settings)")),
            };
            w(out, format!("{name}: {what} {value}"));
            Ok(())
        }
        Cmd::Config(c) => config_cmd(&paths, c, out).await,
        Cmd::Deny {
            command,
            wildcard,
            center,
        } => {
            let rule = rules::rule_for("exec", "run", &command, wildcard)?;
            let name = edit_center(&paths, &center, |e| {
                push_unique(&mut e.policy.deny, &rule);
                Ok(())
            })
            .await?;
            w(
                out,
                format!("{name}: deny rule {rule:?}; commands it matches are forbidden"),
            );
            Ok(())
        }
        Cmd::Allow {
            command,
            wildcard,
            center,
        } => {
            // A sudo command has its own list, whatever the mode.
            let sudo = sudo_command(&command).is_some();
            let rule = if sudo {
                rules::sudo_rule_for(&command, wildcard)?
            } else {
                rules::rule_for("exec", "run", &command, wildcard)?
            };
            let name = edit_center(&paths, &center, |e| {
                let list = if sudo {
                    &mut e.policy.sudo_allow
                } else {
                    &mut e.policy.allow
                };
                push_unique(list, &rule);
                Ok(())
            })
            .await?;
            let list = if sudo {
                "sudo allow list"
            } else {
                "allow rule (allowlist mode)"
            };
            w(out, format!("{name}: {list} {rule:?}"));
            Ok(())
        }
        Cmd::Panic => {
            edit(&paths, |c| {
                c.locked = true;
                Ok(())
            })
            .await?;
            w(
                out,
                "locked: every link ends and nothing runs until `nerve-node unlock`".into(),
            );
            Ok(())
        }
        Cmd::Unlock => {
            edit(&paths, |c| {
                c.locked = false;
                Ok(())
            })
            .await?;
            w(out, "unlocked".into());
            Ok(())
        }
        Cmd::Audit { follow, denied } => audit(&paths, follow, denied, out).await,
        Cmd::Proxy(ProxyCmd::Set { url, headers }) => {
            let mut hs = Vec::new();
            for h in &headers {
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("header {h:?} is not `Name: value`"))?;
                hs.push((k.trim().to_string(), v.trim().to_string()));
            }
            nerve_transport::net::Proxy::parse(&url, hs.clone())?;
            edit(&paths, |c| {
                c.connection.proxy = Some(url.clone());
                c.connection.headers = hs.iter().cloned().collect();
                Ok(())
            })
            .await?;
            w(out, format!("proxy {url}"));
            Ok(())
        }
        Cmd::Proxy(ProxyCmd::Clear) => {
            edit(&paths, |c| {
                c.connection.proxy = None;
                c.connection.headers.clear();
                Ok(())
            })
            .await?;
            w(out, "no proxy".into());
            Ok(())
        }
        Cmd::Sudo(c) => sudo_cmd(&paths, c, out).await,
        // Not done in 0.0.1: service install, a dedicated user, self-update
        // and removal (architecture §6, §8).
        Cmd::Install => Err(format!("install: {NOT_DONE}")),
        Cmd::Setup { .. } => Err(format!("setup: {NOT_DONE}")),
        Cmd::Update => Err(format!("update: {NOT_DONE}")),
        Cmd::Uninstall => Err(format!("uninstall: {NOT_DONE}")),
    }
}

/// `nerve-node sudo on|off|status`. The password lives in the running
/// daemon only, so `on` needs one; `off` without a daemon edits the file.
async fn sudo_cmd(paths: &NodePaths, c: SudoCmd, out: &mut dyn Write) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: &str| {
        let _ = writeln!(out, "{s}");
    };
    #[cfg(unix)]
    {
        use nerve_transport::ctl::{NOT_RUNNING, call};
        let sock = paths.ctl_socket();
        match c {
            SudoCmd::On => {
                // Fail before asking for the password when nothing can take it.
                match call(&sock, "status", json!({})).await {
                    Ok(_) => {}
                    Err(e) if e == NOT_RUNNING => {
                        return Err(
                            "sudo on needs the running daemon: it keeps the password in memory only"
                                .into(),
                        );
                    }
                    Err(e) => return Err(e),
                }
                let password = read_password(out, "sudo password: ")?;
                call(&sock, "sudo.on", json!({"password": password})).await?;
                w(
                    out,
                    "sudo: on (only commands the sudo allow list names run with sudo)",
                );
            }
            SudoCmd::Off => {
                match call(&sock, "sudo.off", json!({})).await {
                    Ok(_) => {}
                    Err(e) if e == NOT_RUNNING => {
                        edit(paths, |c| {
                            c.machine.sudo = nerve_policy::config::Sudo::Off;
                            Ok(())
                        })
                        .await?;
                    }
                    Err(e) => return Err(e),
                }
                w(out, "sudo: off");
            }
            SudoCmd::Status => {
                let on = match call(&sock, "sudo.status", json!({})).await {
                    Ok(v) => v["sudo"] == "on",
                    // A node that does not run holds no password.
                    Err(e) if e == NOT_RUNNING => false,
                    Err(e) => return Err(e),
                };
                w(out, if on { "sudo: on" } else { "sudo: off" });
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, out, w);
        match c {
            SudoCmd::Status => Ok(()),
            _ => Err("the sudo switch works on Linux only".into()),
        }
    }
}

/// Reads a password: from the terminal without echo, else one line of stdin.
#[cfg(unix)]
fn read_password(out: &mut dyn Write, prompt: &str) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    // SAFETY: plain termios calls on stdin with a zeroed struct to fill.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::isatty(fd) == 1 && libc::tcgetattr(fd, &mut old) == 0 };
    if tty {
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: as above; restored below.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let r = stdin.lock().read_line(&mut line);
    if tty {
        // SAFETY: restores what tcgetattr returned.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        let _ = writeln!(out);
    }
    r.map_err(|e| e.to_string())?;
    let password = line.strip_suffix('\n').unwrap_or(&line);
    let password = password.strip_suffix('\r').unwrap_or(password).to_string();
    line.clear();
    if password.is_empty() {
        return Err("no password given".into());
    }
    Ok(password)
}

fn confirm(out: &mut dyn Write) -> Result<bool, String> {
    let _ = write!(out, "Pair with this center? [y/N] ");
    let _ = out.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn parse_enum<T: serde::de::DeserializeOwned>(s: &str, choices: &str) -> Result<T, String> {
    serde_json::from_value(json!(s)).map_err(|_| format!("{s:?}: expected {choices}"))
}

/// Folders are stored resolved (symlinks followed), the way the policy
/// compares them.
fn resolve_folder(p: &Path) -> Result<String, String> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    let real = nerve_policy::paths::resolve(&abs).map_err(|e| e.to_string())?;
    Ok(real.display().to_string())
}

fn audit_line(v: &Value) -> String {
    let s = |k: &str| match &v[k] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if v.get("changes").is_some() {
        return format!("{}  settings v{} by {}", s("ts"), s("version"), s("by"));
    }
    if v["kind"] == "config" {
        return format!(
            "{}  config {}  {}: {}",
            s("ts"),
            s("event"),
            s("file"),
            s("reason")
        );
    }
    format!(
        "{}  {}  {}.{}  {}  {}",
        s("ts"),
        s("center"),
        s("cap"),
        s("action"),
        s("target"),
        s("decision")
    )
}

async fn audit(
    paths: &NodePaths,
    follow: bool,
    denied: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let path = paths.audit_log();
    let mut done = 0usize;
    loop {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        // Only whole lines; a line still being written waits for the next look.
        let whole = text.rfind('\n').map_or(0, |i| i + 1);
        if whole < done {
            done = 0;
        }
        for line in text[done..whole].lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let refused = v["decision"].as_str() == Some("forbidden")
                || v["event"].as_str() == Some("refused");
            if denied && !refused {
                continue;
            }
            let _ = writeln!(out, "{}", audit_line(&v));
        }
        done = whole;
        if !follow {
            return Ok(());
        }
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// `config get|set|unset|add|remove` on dotted keys. `center.<name>` picks
/// a `[[center]]` entry by its name.
async fn config_cmd(paths: &NodePaths, c: ConfigCmd, out: &mut dyn Write) -> Result<(), String> {
    if let ConfigCmd::Accept = c {
        let v = accept(paths).await?;
        let _ = writeln!(out, "accepted node.toml as version {v}");
        return Ok(());
    }
    if let ConfigCmd::Get { key } = &c {
        let (cfg, _) = read_config(paths).await?;
        let doc = as_table(&cfg)?;
        let v = lookup(&toml::Value::Table(doc), &segments(key))
            .ok_or_else(|| format!("{key} is not set"))?;
        let _ = writeln!(out, "{}", show(&v));
        return Ok(());
    }
    edit(paths, |cfg| {
        let mut doc = toml::Value::Table(as_table(cfg)?);
        match &c {
            ConfigCmd::Get { .. } | ConfigCmd::Accept => {}
            ConfigCmd::Set { key, value } => {
                let (parent, last) = split_key(key)?;
                table_at(&mut doc, &parent, true)?.insert(last, literal(value));
            }
            ConfigCmd::Unset { key } => {
                let (parent, last) = split_key(key)?;
                table_at(&mut doc, &parent, false)?
                    .remove(&last)
                    .ok_or_else(|| format!("{key} is not set"))?;
            }
            ConfigCmd::Add { key, value } => {
                let (parent, last) = split_key(key)?;
                let t = table_at(&mut doc, &parent, true)?;
                let list = t
                    .entry(last)
                    .or_insert_with(|| toml::Value::Array(Vec::new()));
                let toml::Value::Array(a) = list else {
                    return Err(format!("{key} is not a list"));
                };
                a.push(literal(value));
            }
            ConfigCmd::Remove { key, value } => {
                let (parent, last) = split_key(key)?;
                let t = table_at(&mut doc, &parent, false)?;
                let Some(toml::Value::Array(a)) = t.get_mut(&last) else {
                    return Err(format!("{key} is not a list"));
                };
                let v = literal(value);
                let before = a.len();
                a.retain(|x| x != &v);
                if a.len() == before {
                    return Err(format!("{value} is not in {key}"));
                }
            }
        }
        let text = toml::to_string(&doc).map_err(|e| e.to_string())?;
        let mut new = NodeConfig::parse(&text)?;
        new.version = cfg.version;
        *cfg = new;
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "saved");
    Ok(())
}

/// `config accept`: the running daemon takes the file, or, when none runs,
/// the file is signed here.
async fn accept(paths: &NodePaths) -> Result<u64, String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "config.accept", json!({})).await {
        Ok(v) => return Ok(v["version"].as_u64().unwrap_or_default()),
        Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
        Err(_) => {}
    }
    let (_, v) = SettingsStore::open_accepting(
        paths.config_file(),
        paths.config_key(),
        AuditLog::new(paths.audit_log()),
    )?;
    Ok(v)
}

fn as_table(cfg: &NodeConfig) -> Result<toml::Table, String> {
    toml::from_str(&cfg.to_toml()).map_err(|e| e.to_string())
}

fn segments(key: &str) -> Vec<String> {
    key.split('.').map(str::to_string).collect()
}

fn split_key(key: &str) -> Result<(Vec<String>, String), String> {
    let mut s = segments(key);
    let last = s.pop().filter(|l| !l.is_empty()).ok_or("empty key")?;
    Ok((s, last))
}

/// A value as TOML reads it (`true`, `3`, `["a"]`), else as a string.
fn literal(s: &str) -> toml::Value {
    toml::from_str::<toml::Table>(&format!("v = {s}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(s.to_string()))
}

fn show(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => toml::to_string(t).unwrap_or_default(),
        other => other.to_string(),
    }
}

fn lookup(v: &toml::Value, key: &[String]) -> Option<toml::Value> {
    let Some((first, rest)) = key.split_first() else {
        return Some(v.clone());
    };
    if first == "center" && !rest.is_empty() {
        let list = v.get("center")?.as_array()?;
        let entry = list
            .iter()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(rest[0].as_str()))?;
        return lookup(entry, &rest[1..]);
    }
    lookup(v.get(first.as_str())?, rest)
}

fn table_at<'a>(
    v: &'a mut toml::Value,
    key: &[String],
    create: bool,
) -> Result<&'a mut toml::Table, String> {
    let Some((first, rest)) = key.split_first() else {
        return v.as_table_mut().ok_or_else(|| "not a table".to_string());
    };
    let t = v
        .as_table_mut()
        .ok_or_else(|| format!("{first}: not a table"))?;
    if first == "center" && !rest.is_empty() {
        let list = t
            .get_mut("center")
            .and_then(toml::Value::as_array_mut)
            .ok_or("no center is paired")?;
        let entry = list
            .iter_mut()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(rest[0].as_str()))
            .ok_or_else(|| format!("no center named {}", rest[0]))?;
        return table_at(entry, &rest[1..], create);
    }
    if !t.contains_key(first.as_str()) {
        if !create {
            return Err(format!("{first} is not set"));
        }
        t.insert(first.clone(), toml::Value::Table(toml::Table::new()));
    }
    table_at(t.get_mut(first.as_str()).expect("present"), rest, create)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(paths: &NodePaths, args: &[&str]) -> Result<String, String> {
        let mut argv = vec![
            "nerve-node".to_string(),
            "--config-dir".into(),
            paths.config_dir.display().to_string(),
            "--state-dir".into(),
            paths.state_dir.display().to_string(),
        ];
        argv.extend(args.iter().map(|s| s.to_string()));
        let cli = Cli::try_parse_from(argv).map_err(|e| e.to_string())?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut out = Vec::new();
        rt.block_on(execute(cli, &mut out))?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn entry(name: &str) -> nerve_policy::CenterEntry {
        nerve_policy::CenterEntry {
            name: name.into(),
            url: "http://127.0.0.1:1".into(),
            pin: None,
            center_id: format!("id-{name}"),
            node_id: "n".into(),
            settings: SettingsGrant::Off,
            paused: false,
            revoked: false,
            unknown: false,
            policy: Default::default(),
        }
    }

    fn setup(names: &[&str]) -> (tempfile::TempDir, NodePaths) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let mut cfg = NodeConfig::default();
        for n in names {
            cfg.centers.push(entry(n));
        }
        cfg.save(&paths.config_file()).unwrap();
        (d, paths)
    }

    fn load(paths: &NodePaths) -> NodeConfig {
        NodeConfig::load(&paths.config_file()).unwrap()
    }

    #[test]
    fn per_center_commands_refuse_to_guess() {
        let (_d, paths) = setup(&["a", "b"]);
        let e = run(&paths, &["mode", "user"]).unwrap_err();
        assert!(e.contains("--center"), "{e}");
        run(&paths, &["mode", "user", "--center", "b"]).unwrap();
        assert_eq!(load(&paths).center("b").unwrap().policy.mode, Mode::User);
        // A new center is in default deny.
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        run(&paths, &["mode", "folder", "--center", "a"]).unwrap();
        assert_eq!(load(&paths).center("a").unwrap().policy.mode, Mode::Folder);
        run(&paths, &["mode", "allowlist", "--center", "a"]).unwrap();
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        let e = run(&paths, &["mode", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown mode"), "{e}");
        let e = run(&paths, &["caps", "fs", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown setting"), "{e}");
    }

    #[test]
    fn edits_without_a_daemon_land_in_the_file_and_the_audit_log() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        let note = run(&paths, &["folder", "add", folder.to_str().unwrap(), "--rw"]).unwrap();
        assert!(note.contains("folders count in folder mode"), "{note}");
        run(&paths, &["caps", "exec.run", "off"]).unwrap();
        run(&paths, &["grant", "settings", "write"]).unwrap();
        run(&paths, &["allow", "git status --short", "--wildcard"]).unwrap();
        run(&paths, &["allow", "sudo apt update"]).unwrap();
        run(&paths, &["deny", "rm -rf /"]).unwrap();
        run(&paths, &["deny", "rm -rf /"]).unwrap();
        run(&paths, &["mode", "user", "--hours", "2"]).unwrap();
        assert!(run(&paths, &["mode", "user", "--hours", "9"]).is_err());
        let cfg = load(&paths);
        let c = cfg.center("home").unwrap();
        let real = nerve_policy::paths::resolve(&folder).unwrap();
        assert_eq!(c.policy.folders[0].path, real.display().to_string());
        assert_eq!(c.policy.folders[0].access, Access::Rw);
        assert_eq!(c.policy.caps["exec.run"], CapSetting::Off);
        assert_eq!(c.settings, SettingsGrant::Write);
        assert_eq!(c.policy.allow, vec!["exec.run:git *".to_string()]);
        assert_eq!(c.policy.sudo_allow, vec!["sudo apt update".to_string()]);
        assert_eq!(c.policy.deny, vec!["exec.run:rm -rf /".to_string()]);
        assert_eq!(c.policy.mode, Mode::User);
        assert!(c.policy.user_until.is_some());
        let log = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(log.contains("local"), "{log}");
        run(&paths, &["panic"]).unwrap();
        assert!(load(&paths).locked);
        run(&paths, &["unlock"]).unwrap();
        assert!(!load(&paths).locked);
    }

    #[test]
    fn config_get_set_by_dotted_key() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["config", "set", "limits.max_running", "4"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 4);
        run(
            &paths,
            &["config", "set", "center.home.policy.user_until", "30"],
        )
        .unwrap();
        assert_eq!(
            run(&paths, &["config", "get", "center.home.policy.user_until"]).unwrap(),
            "30\n"
        );
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "fs:~/secret/*"],
        )
        .unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            vec!["fs:~/secret/*".to_string()]
        );
        run(
            &paths,
            &[
                "config",
                "remove",
                "center.home.policy.deny",
                "fs:~/secret/*",
            ],
        )
        .unwrap();
        assert!(load(&paths).centers[0].policy.deny.is_empty());
        // Unknown keys fail validation and change nothing.
        assert!(run(&paths, &["config", "set", "limits.bogus", "1"]).is_err());
        run(&paths, &["config", "unset", "limits.max_running"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 16);
    }

    #[test]
    fn stubs_say_not_done() {
        let (_d, paths) = setup(&[]);
        for cmd in [
            &["install"][..],
            &["setup", "--create-user"],
            &["update"],
            &["uninstall"],
        ] {
            let e = run(&paths, cmd).unwrap_err();
            assert!(e.contains("not done in 0.0.1"), "{e}");
        }
    }

    #[test]
    fn allow_and_deny_only_add_a_rule() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["allow", "git status"]).unwrap();
        run(&paths, &["deny", "git status"]).unwrap();
        run(&paths, &["deny", "rm *", "--wildcard"]).unwrap();
        run(&paths, &["allow", "sudo apt update", "--wildcard"]).unwrap();
        let p = &load(&paths).centers[0].policy;
        // Neither list loses a rule to the other; deny wins when they meet.
        assert_eq!(p.allow, ["exec.run:git status"]);
        assert_eq!(p.deny, ["exec.run:git status", "exec.run:rm *"]);
        assert_eq!(p.sudo_allow, ["sudo apt *"]);
        assert!(run(&paths, &["allow", "  "]).is_err());
        // A command with a glob character in it is allowed as itself.
        run(&paths, &["allow", "rm *"]).unwrap();
        assert!(load(&paths).centers[0].policy.allow[1].contains("[*]"));
        // Rules for other actions go in through `config add`.
        run(
            &paths,
            &[
                "config",
                "add",
                "center.home.policy.allow",
                "fs.read:~/notes/*",
            ],
        )
        .unwrap();
        assert!(
            run(
                &paths,
                &["config", "add", "center.home.policy.allow", "~/notes"]
            )
            .is_err()
        );
    }

    /// Every command and sub-command name of the clap definition, walked
    /// here on its own so the test does not trust [`help`] to find them.
    fn all_names(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" {
                continue;
            }
            let name = format!("{prefix}{}", sub.get_name());
            all_names(sub, &format!("{name} "), out);
            out.push(name);
        }
    }

    #[test]
    fn help_lists_every_command_with_an_explanation() {
        let mut names = Vec::new();
        all_names(&Cli::command(), "", &mut names);
        assert!(names.len() > 20, "{names:?}");
        let h = help();
        for name in &names {
            let c = h
                .commands
                .iter()
                .find(|c| &c.name == name)
                .unwrap_or_else(|| panic!("`{name}` is missing from the help"));
            assert!(!c.about.is_empty(), "`{name}` has no explanation");
            assert!(
                c.usage.starts_with(&format!("nerve-node {name}")),
                "{}",
                c.usage
            );
        }
        assert_eq!(h.commands.len(), names.len());
        let add = h.commands.iter().find(|c| c.name == "folder add").unwrap();
        assert!(
            add.args
                .iter()
                .any(|a| a.name == "--rw" && !a.about.is_empty())
        );
        assert!(add.args.iter().any(|a| a.name == "<PATH>"));
        // The options every command takes are listed once, not per command.
        assert!(h.global.iter().any(|a| a.name.starts_with("--config-dir")));
        assert!(add.args.iter().all(|a| !a.name.starts_with("--config-dir")));
    }

    #[test]
    fn every_argument_is_explained() {
        for c in help().commands {
            for a in c.args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    c.name,
                    a.name
                );
            }
        }
    }

    #[test]
    fn the_shim_is_not_a_command() {
        let e = Cli::try_parse_from(["nerve-node", "__exec-shim"]).unwrap_err();
        assert!(e.to_string().contains("__exec-shim"));
    }
}
