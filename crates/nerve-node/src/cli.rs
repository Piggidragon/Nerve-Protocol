//! The `nerve-node` command line (architecture §8). Commands talk to the
//! running daemon over the control socket; when none runs they edit the
//! config file directly through the same [`SettingsStore`].

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

use nerve_policy::audit::AuditLog;
use nerve_policy::config::{
    Access, ApprovalsGrant, CapSetting, FULL_MAX_MS, Folder, SettingsGrant,
};
use nerve_policy::{Mode, NodeConfig, SetError, SettingsStore};
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
    #[arg(long)]
    pub center: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the node daemon.
    Run,
    /// Pair with a center from its pairing link.
    Pair {
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
    /// Set a center's mode: ask, folders or full (full ends after --hours, at most 8).
    Mode {
        mode: String,
        #[arg(long)]
        hours: Option<u64>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Add or remove a folder a center may use.
    #[command(subcommand)]
    Folder(FolderCmd),
    /// Set a capability or action (`fs`, `exec.run`) to on, ask, off or hidden.
    Caps {
        cap: String,
        setting: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Let a center change settings (`settings off|write`) or answer approvals (`approvals both|local`).
    Grant {
        what: String,
        value: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Read or change node.toml by dotted key (`center.<name>.policy.mode`).
    #[command(subcommand)]
    Config(ConfigCmd),
    /// List open approvals.
    Approvals {
        #[arg(long)]
        follow: bool,
    },
    /// Allow an open approval (once, for the session, or for some minutes).
    Approve {
        id: String,
        #[arg(long, conflicts_with = "minutes")]
        session: bool,
        #[arg(long)]
        minutes: Option<u32>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Deny an open approval, or forbid a command (`deny <command> [--wildcard]`).
    Deny {
        what: String,
        /// Treat `what` as a command even if it looks like an approval id.
        #[arg(long)]
        command: bool,
        /// Match every command that starts with the same program.
        #[arg(long)]
        wildcard: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Let a command run without asking.
    Allow {
        command: String,
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
        #[arg(long)]
        create_user: bool,
    },
    /// Elevation rules (not done in 0.0.1).
    Sudo {
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Update the node (not done in 0.0.1).
    Update,
    /// Remove the node (not done in 0.0.1).
    Uninstall,
}

#[derive(Debug, Subcommand)]
pub enum FolderCmd {
    Add {
        path: PathBuf,
        #[arg(long)]
        rw: bool,
        #[arg(long)]
        execute: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    Remove {
        path: PathBuf,
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
    },
    Unset {
        key: String,
    },
    /// Append a value to a list.
    Add {
        key: String,
        value: String,
    },
    /// Remove a value from a list.
    Remove {
        key: String,
        value: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProxyCmd {
    Set {
        url: String,
        /// A header for the CONNECT request, `Name: value`.
        #[arg(long = "header")]
        headers: Vec<String>,
    },
    Clear,
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
    Ok((NodeConfig::load(&paths.config_file())?, None))
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
    let mut store = SettingsStore::open(paths.config_file(), AuditLog::new(paths.audit_log()))?;
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

/// Whether `s` looks like an approval id (`a<n>-<4 chars>`).
fn is_approval_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('a') else {
        return false;
    };
    let Some((n, tail)) = rest.split_once('-') else {
        return false;
    };
    !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
        && tail.len() == 4
        && tail.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A command rule: the command itself, or with `--wildcard` its program
/// followed by anything.
fn command_rule(command: &str, wildcard: bool) -> Result<String, String> {
    let command = command.trim();
    if command.is_empty() {
        return Err("the command is empty".into());
    }
    if wildcard {
        let program = command.split_whitespace().next().unwrap_or(command);
        Ok(format!("{program} *"))
    } else {
        Ok(command.to_string())
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
                        "{}  {}  mode {}  settings {}  approvals {}{}",
                        c.name,
                        c.url,
                        c.policy.mode_at(now).as_str(),
                        enum_str(&c.settings),
                        enum_str(&c.approvals),
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
                                "{}  {}  mode {}  {} open approvals",
                                c["name"].as_str().unwrap_or_default(),
                                c["status"].as_str().unwrap_or_default(),
                                c["mode"].as_str().unwrap_or_default(),
                                c["open_approvals"]
                            ),
                        );
                    }
                    return Ok(());
                }
                Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
                Err(_) => {}
            }
            let cfg = NodeConfig::load(&paths.config_file())?;
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
                "ask" => Mode::Ask,
                "folders" => Mode::Folders,
                "full" => Mode::Full,
                other => return Err(format!("unknown mode {other} (ask, folders or full)")),
            };
            if hours.is_some() && m != Mode::Full {
                return Err("--hours only goes with full".into());
            }
            let until = (m == Mode::Full).then(|| {
                let ms = hours.map_or(FULL_MAX_MS, |h| h.saturating_mul(3_600_000));
                crate::now_ms() + ms
            });
            if hours.is_some_and(|h| h.saturating_mul(3_600_000) > FULL_MAX_MS) {
                return Err("full mode lasts at most 8 hours".into());
            }
            let name = edit_center(&paths, &center, |e| {
                e.policy.mode = m;
                e.policy.full_until = until;
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
            let name = edit_center(&paths, &center, |e| {
                e.policy.folders.retain(|f| f.path != real);
                e.policy.folders.push(Folder {
                    path: real.clone(),
                    access: if rw { Access::Rw } else { Access::Ro },
                    execute,
                });
                Ok(())
            })
            .await?;
            w(out, format!("{name}: folder {}", resolve_folder(&path)?));
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
                .ok_or_else(|| format!("unknown setting {setting} (on, ask, off or hidden)"))?;
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
                "approvals" => {
                    let g: ApprovalsGrant = parse_enum(&value, "both or local")?;
                    edit_center(&paths, &center, |e| {
                        e.approvals = g;
                        Ok(())
                    })
                    .await?
                }
                other => return Err(format!("unknown grant {other} (settings or approvals)")),
            };
            w(out, format!("{name}: {what} {value}"));
            Ok(())
        }
        Cmd::Config(c) => config_cmd(&paths, c, out).await,
        Cmd::Approvals { follow } => approvals(&paths, follow, out).await,
        Cmd::Approve {
            id,
            session,
            minutes,
            center,
        } => {
            let answer = if session {
                "session"
            } else if minutes.is_some() {
                "time"
            } else {
                "once"
            };
            answer_approval(&paths, &center, &id, answer, minutes).await?;
            w(out, format!("{id}: allowed ({answer})"));
            Ok(())
        }
        Cmd::Deny {
            what,
            command,
            wildcard,
            center,
        } => {
            if !command && !wildcard && is_approval_id(&what) {
                answer_approval(&paths, &center, &what, "deny", None).await?;
                w(out, format!("{what}: denied"));
                return Ok(());
            }
            let rule = command_rule(&what, wildcard)?;
            let name = edit_center(&paths, &center, |e| {
                let r = &mut e.policy.commands;
                r.never_ask.retain(|c| c != &rule);
                if !r.deny.contains(&rule) {
                    r.deny.push(rule.clone());
                }
                Ok(())
            })
            .await?;
            w(
                out,
                format!("{name}: commands matching {rule:?} are forbidden"),
            );
            Ok(())
        }
        Cmd::Allow {
            command,
            wildcard,
            center,
        } => {
            let rule = command_rule(&command, wildcard)?;
            let name = edit_center(&paths, &center, |e| {
                let r = &mut e.policy.commands;
                r.deny.retain(|c| c != &rule);
                if !r.never_ask.contains(&rule) {
                    r.never_ask.push(rule.clone());
                }
                Ok(())
            })
            .await?;
            w(
                out,
                format!("{name}: commands matching {rule:?} run without asking"),
            );
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
        // Not done in 0.0.1: service install, a dedicated user, elevation,
        // self-update and removal (architecture §6, §8).
        Cmd::Install => Err(format!("install: {NOT_DONE}")),
        Cmd::Setup { .. } => Err(format!("setup: {NOT_DONE}")),
        Cmd::Sudo { .. } => Err(format!("sudo: {NOT_DONE}")),
        Cmd::Update => Err(format!("update: {NOT_DONE}")),
        Cmd::Uninstall => Err(format!("uninstall: {NOT_DONE}")),
    }
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

async fn answer_approval(
    paths: &NodePaths,
    center: &CenterArg,
    id: &str,
    answer: &str,
    minutes: Option<u32>,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        let params =
            json!({"center": center.center, "id": id, "answer": answer, "minutes": minutes});
        match nerve_transport::ctl::call(&paths.ctl_socket(), "approvals.answer", params).await {
            Ok(_) => Ok(()),
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {
                Err("no node daemon runs, so no approval is open".into())
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, center, id, answer, minutes);
        Err(format!(
            "answering from the CLI on this platform: {NOT_DONE}"
        ))
    }
}

fn approval_line(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let reasons: Vec<&str> = v["reasons"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let choices: Vec<&str> = v["choices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    format!(
        "{}  {}  {}.{}  {}  ({})  choices: {}",
        s("id"),
        s("center"),
        s("cap"),
        s("action"),
        s("target"),
        reasons.join("; "),
        choices.join(", ")
    )
}

async fn approvals(paths: &NodePaths, follow: bool, out: &mut dyn Write) -> Result<(), String> {
    #[cfg(unix)]
    {
        let sock = paths.ctl_socket();
        let list = match nerve_transport::ctl::call(&sock, "approvals.list", json!({})).await {
            Ok(v) => v,
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {
                let _ = writeln!(out, "no node daemon runs; no approvals are open");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let open = list["approvals"].as_array().cloned().unwrap_or_default();
        if open.is_empty() && !follow {
            let _ = writeln!(out, "no open approvals");
        }
        for a in &open {
            let _ = writeln!(out, "{}", approval_line(a));
        }
        if follow {
            nerve_transport::ctl::follow(&sock, "approvals.follow", json!({}), |v| {
                let data = &v["data"];
                let line = match v["name"].as_str() {
                    Some("requested") => {
                        let mut d = data.clone();
                        d["center"] = v["center"].clone();
                        format!("requested  {}", approval_line(&d))
                    }
                    _ => format!(
                        "resolved   {}  {} by {}",
                        data["id"].as_str().unwrap_or_default(),
                        data["answer"].as_str().unwrap_or_default(),
                        data["by"].as_str().unwrap_or_default()
                    ),
                };
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            })
            .await?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (paths, follow, out);
        Err(format!(
            "approvals from the CLI on this platform: {NOT_DONE}"
        ))
    }
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
    let mut line = format!(
        "{}  {}  {}.{}  {}  {}",
        s("ts"),
        s("center"),
        s("cap"),
        s("action"),
        s("target"),
        s("decision")
    );
    if !s("by").is_empty() {
        line.push_str(&format!(" by {}", s("by")));
    }
    line
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
            let refused = matches!(v["decision"].as_str(), Some("denied" | "forbidden"));
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
            ConfigCmd::Get { .. } => {}
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
            approvals: ApprovalsGrant::Both,
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
        let e = run(&paths, &["mode", "folders"]).unwrap_err();
        assert!(e.contains("--center"), "{e}");
        run(&paths, &["mode", "folders", "--center", "b"]).unwrap();
        assert_eq!(load(&paths).center("b").unwrap().policy.mode, Mode::Folders);
        assert_eq!(load(&paths).center("a").unwrap().policy.mode, Mode::Ask);
    }

    #[test]
    fn edits_without_a_daemon_land_in_the_file_and_the_audit_log() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        run(&paths, &["folder", "add", folder.to_str().unwrap(), "--rw"]).unwrap();
        run(&paths, &["caps", "exec.run", "off"]).unwrap();
        run(&paths, &["grant", "settings", "write"]).unwrap();
        run(&paths, &["allow", "git status --short", "--wildcard"]).unwrap();
        run(&paths, &["deny", "rm -rf /"]).unwrap();
        run(&paths, &["mode", "full", "--hours", "2"]).unwrap();
        assert!(run(&paths, &["mode", "full", "--hours", "9"]).is_err());
        let cfg = load(&paths);
        let c = cfg.center("home").unwrap();
        let real = std::fs::canonicalize(&folder).unwrap();
        assert_eq!(c.policy.folders[0].path, real.display().to_string());
        assert_eq!(c.policy.folders[0].access, Access::Rw);
        assert_eq!(c.policy.caps["exec.run"], CapSetting::Off);
        assert_eq!(c.settings, SettingsGrant::Write);
        assert_eq!(c.policy.commands.never_ask, vec!["git *".to_string()]);
        assert_eq!(c.policy.commands.deny, vec!["rm -rf /".to_string()]);
        assert_eq!(c.policy.mode, Mode::Full);
        assert!(c.policy.full_until.is_some());
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
            &[
                "config",
                "set",
                "center.home.policy.approvals.timeout_s",
                "30",
            ],
        )
        .unwrap();
        assert_eq!(
            run(
                &paths,
                &["config", "get", "center.home.policy.approvals.timeout_s"]
            )
            .unwrap(),
            "30\n"
        );
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "~/secret"],
        )
        .unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            vec!["~/secret".to_string()]
        );
        run(
            &paths,
            &["config", "remove", "center.home.policy.deny", "~/secret"],
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
            &["sudo", "x"],
            &["update"],
            &["uninstall"],
        ] {
            let e = run(&paths, cmd).unwrap_err();
            assert!(e.contains("not done in 0.0.1"), "{e}");
        }
    }

    #[test]
    fn approval_ids_and_rules() {
        assert!(is_approval_id("a12-x9kq"));
        assert!(!is_approval_id("apt-get"));
        assert!(!is_approval_id("a1-toolong"));
        assert_eq!(command_rule("git push origin", true).unwrap(), "git *");
        assert_eq!(command_rule(" ls ", false).unwrap(), "ls");
    }

    #[test]
    fn the_shim_is_not_a_command() {
        let e = Cli::try_parse_from(["nerve-node", "__exec-shim"]).unwrap_err();
        assert!(e.to_string().contains("__exec-shim"));
    }
}
