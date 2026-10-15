//! The `nerve-node` command line (docs/dev/settings-and-config.md). Commands talk to the
//! running daemon over the control socket (on Windows the folder changes
//! over its control pipe, crate::pipe); when none runs they edit the config
//! file directly through the same [`SettingsStore`], which signs it.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, CommandFactory, Parser, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};

use nerve_policy::audit::AuditLog;
use nerve_policy::config::{Access, CapSetting, Folder, SecretStorage, SettingsGrant};
use nerve_policy::{Mode, NodeConfig, SetError, SettingsStore, rules, sudo_command};
use nerve_proto::link::PairLink;

use crate::daemon::{Daemon, NodeOptions};
use crate::folder_change::{Applied, FolderChange};
use crate::paths::NodePaths;
use crate::service::{Host, Layout};

#[derive(Debug, Parser)]
#[command(
    name = "nerve-node",
    version,
    about = "Links this machine to its Nerve centers."
)]
pub struct Cli {
    /// Where node.toml and the keys live [env: NERVE_CONFIG_DIR] [default: ~/.config/nerve, or /etc/nerve when installed as a service]
    #[arg(long, global = true)]
    pub config_dir: Option<PathBuf>,
    /// Where the control socket and the audit log live [env: NERVE_STATE_DIR] [default: ~/.local/state/nerve, or /var/lib/nerve/state when installed as a service]
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// Picks one paired center; required when several are paired.
#[derive(Debug, Args, Clone, Default)]
pub struct CenterArg {
    /// Which center, when more than one is paired.
    #[arg(long)]
    pub center: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Pair this machine with centers and decide what each one may change.
    #[command(subcommand)]
    Center(CenterCmd),
    /// Choose the folders a center may use and what it may do in each.
    #[command(subcommand)]
    Folder(FolderCmd),
    /// Choose how much a center may do: only what allow rules name, what each folder allows, or all you can do.
    #[command(subcommand)]
    Mode(ModeCmd),
    /// Keep the lists of commands that are allowed, forbidden or run with sudo.
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Turn capabilities and single actions on or off.
    #[command(subcommand)]
    Cap(CapCmd),
    /// Use sudo for the commands on the sudo list.
    #[command(subcommand)]
    Sudo(SudoCmd),
    /// Choose the proxy the node uses to reach centers.
    #[command(subcommand)]
    Proxy(ProxyCmd),
    /// Let nodes that cannot reach a center themselves reach this node's centers through it.
    #[command(subcommand)]
    Relay(RelayCmd),
    /// Read or change any setting in node.toml by its name.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Run the node in the foreground.
    Run,
    /// Show whether the node runs and which centers it is paired with.
    Status,
    /// Show what the node allowed and refused.
    Audit {
        /// Keep running and print new entries as they arrive.
        #[arg(long)]
        follow: bool,
        /// Show only the calls that were refused.
        #[arg(long)]
        denied: bool,
    },
    /// Stop everything at once; nothing runs until `unlock`.
    Panic,
    /// Let the node work again after `panic`.
    Unlock,
    /// Install the node as a service that starts with the machine and runs under a user of its own (Linux as root, Windows as administrator).
    Install,
    /// Name the node, choose the account commands run as (installed node), choose where the node keeps its keys, pair the first center and choose its mode, one question at a time.
    Setup {
        /// Run commands as this account instead of asking, and make it if it is not there: a group and a home (/home/NAME) of its own, no login (installed node).
        #[arg(long, value_name = "NAME")]
        create_user: Option<String>,
    },
    /// Replace the installed program with the latest release and restart the service; config, keys and audit log stay.
    Update {
        /// Take the new program from this file instead of downloading the latest release.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
    },
    /// Stop and remove the service, its user and the program; the config and state folders stay.
    Uninstall {
        /// Delete the config and state folders too: the keys, the pairings and the audit log.
        #[arg(long)]
        purge: bool,
    },
    /// Write the config and the keys to a file that a passphrase protects, to keep or to move the node to another machine.
    Backup {
        /// The file to write. It is private to you (mode 0600).
        file: PathBuf,
        /// Also take the keys that are in the system keyring into the file; without it they stay there and are left out.
        #[arg(long)]
        include_keyring: bool,
        /// Replace the file when it exists.
        #[arg(long)]
        overwrite: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Put the config and keys of a backup in place of this node's. The node must not run.
    Restore {
        /// The backup file.
        file: PathBuf,
        /// Replace a node here that is not the one the backup is of.
        #[arg(long)]
        replace: bool,
        /// Keep the keys in `file` or in the system `keyring` here, whatever the backup's config says.
        #[arg(long, value_name = "file|keyring")]
        secret_storage: Option<String>,
        /// Leave the proxy out of the restored config, with its password and header values; set it again on this machine.
        #[arg(long)]
        without_proxy: bool,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CenterCmd {
    /// Pair this machine with a center, using the pairing link it showed.
    Add {
        /// The pairing link.
        link: String,
        /// The name to use for the center here (the center's own name if left out).
        #[arg(long)]
        name: Option<String>,
        /// Do not ask before pairing.
        #[arg(long)]
        yes: bool,
    },
    /// Forget a center and delete its key.
    Rm(CenterArg),
    /// List the paired centers and how they are set.
    Ls,
    /// Stop the link to a center until you resume it.
    Pause(CenterArg),
    /// Link to a paused center again.
    Resume(CenterArg),
    /// Let a center change its own rights on this machine, up to user mode and sudo, or take that right away.
    Grant {
        /// What to grant; only `settings` exists.
        what: String,
        /// `off`, or `write`: the center may then set everything this machine lets it do.
        value: String,
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum ModeCmd {
    /// Pick allowlist, folder or user mode.
    Set {
        /// `allowlist` (only what an allow rule names), `folder` (what each
        /// folder's rights allow) or `user` (anything you could do yourself,
        /// protected files aside).
        mode: String,
        /// Go back to allowlist after this many hours (folder and user mode
        /// otherwise stay until you change them).
        #[arg(long = "for", value_name = "HOURS")]
        for_hours: Option<u64>,
        #[command(flatten)]
        center: CenterArg,
    },
}

/// The three lists of commands in a center's policy.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum List {
    Allow,
    Deny,
    Sudo,
}

#[derive(Debug, Subcommand)]
pub enum RuleCmd {
    /// Put a command on a list.
    Add {
        /// The list: `allow` (may run in allowlist mode), `deny` (a command
        /// line that matches never runs, in any mode) or `sudo` (may run with
        /// sudo while sudo is on).
        list: List,
        /// The command line.
        command: String,
        /// Cover every command that starts with the same program.
        #[arg(long)]
        wildcard: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Take a command off a list.
    Rm {
        /// The list: `allow`, `deny` or `sudo`.
        list: List,
        /// The command line, or an entry as `ls` shows it.
        command: String,
        /// The entry was added with --wildcard.
        #[arg(long)]
        wildcard: bool,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show one list, or all three.
    Ls {
        /// The list; all three if left out.
        list: Option<List>,
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum CapCmd {
    /// Set a capability (`fs`) or one action (`exec.run`) to on, off or hidden.
    Set {
        /// The capability (`fs`) or action (`exec.run`).
        cap: String,
        /// `on`, `off` or `hidden`.
        setting: String,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show the capabilities and actions you set.
    Ls {
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum SudoCmd {
    /// Turn sudo on; asks for your sudo password and keeps it in memory only (on Windows the password of the account commands run as, kept with DPAPI).
    On,
    /// Turn sudo off and forget the password.
    Off,
    /// Show whether sudo is on.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum FolderCmd {
    /// Let a center use a folder; name at least one right: +r, +w or +x.
    Add {
        /// The folder.
        path: PathBuf,
        /// The rights: +r reads, +w writes, +x runs commands (`+r +x`, `+rw`).
        #[arg(value_name = "+r|+w|+x", required = true, num_args = 1..)]
        rights: Vec<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Change what a center may do in a folder it already has.
    Set {
        /// The folder.
        path: PathBuf,
        /// The changes, applied left to right: `=rwx` sets exactly these
        /// rights, `+x` adds one, `-w` takes one away.
        #[arg(
            value_name = "=rwx|+x|-w",
            required = true,
            num_args = 1..,
            allow_hyphen_values = true
        )]
        changes: Vec<String>,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Take a folder away from a center.
    Rm {
        /// The folder.
        path: PathBuf,
        #[command(flatten)]
        center: CenterArg,
    },
    /// Show a center's folders and their rights.
    Ls {
        #[command(flatten)]
        center: CenterArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print one setting.
    Get {
        /// The dotted key of the setting, like `center.<name>.policy.mode`.
        key: String,
    },
    /// Change one setting.
    Set {
        /// The dotted key of the setting, like `center.<name>.policy.mode`.
        key: String,
        /// The new value.
        value: String,
    },
    /// Remove one setting (its default applies again).
    Unset {
        /// The dotted key of the setting, like `center.<name>.policy.mode`.
        key: String,
    },
    /// Append a value to a list.
    Add {
        /// The dotted key of a list, like `center.<name>.policy.allow`.
        key: String,
        /// The value to append.
        value: String,
    },
    /// Remove a value from a list.
    Remove {
        /// The dotted key of a list, like `center.<name>.policy.allow`.
        key: String,
        /// The value to remove.
        value: String,
    },
    /// Trust node.toml as it is now, after the node refused it for a change
    /// made outside nerve-node. Read the file first.
    Accept,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCmd {
    /// Reach centers through an HTTP proxy. Header values and a password are kept in the system keyring, never in node.toml; the installed node on Windows takes neither.
    Set {
        /// The proxy, http://host:port, or http://user:password@host:port when it wants a login; https://... for a relay or another proxy reached over TLS.
        url: String,
        /// The pin of an https:// proxy's certificate (a relay's: `nerve-node relay ls` there shows it); without it the system's roots check it.
        #[arg(long)]
        pin: Option<String>,
        /// A header for the proxy, `Name: value`; can be given more than once. The value goes into the system keyring.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
    },
    /// Reach centers directly again, and delete the proxy's values from the system keyring.
    Rm,
    /// Show the proxy that is set and the names of its headers, never their values.
    Ls,
}

#[derive(Debug, Subcommand)]
pub enum RelayCmd {
    /// Turn the relay on: listen for other nodes at ADDRESS, like 0.0.0.0:7490. A node reaches only this node's own https centers through it.
    Set {
        /// The address and port to listen on, like 0.0.0.0:7490 or [::]:7490.
        address: String,
        /// Tunnels at once, over every relayed node (16 unless set).
        #[arg(long, value_name = "N")]
        max_links: Option<u32>,
        /// Tunnels at once of one relayed node (4 unless set).
        #[arg(long, value_name = "N")]
        max_links_per_node: Option<u32>,
        /// Tunnels one relayed node may open a minute, every node alike (30 unless set; for a relay behind this one, use `relay set-limits <name>`).
        #[arg(long, value_name = "N")]
        max_opens_per_minute: Option<u32>,
    },
    /// Turn the relay off: stop listening and end every tunnel. The nodes and their tokens stay.
    Off,
    /// Let a node use the relay: makes its token and shows it once. Without --center its tunnels may go to every https center of this node.
    Add {
        /// The relayed node's name here, 1 to 32 of a-z, 0-9 and -.
        name: String,
        /// A center of this node the relayed node may reach; can be given more than once. Without it, every one.
        #[arg(long = "center", value_name = "CENTER")]
        centers: Vec<String>,
    },
    /// Change which centers of this node a relayed node may reach; without --center, every one. Its tunnels to others end.
    SetCenters {
        /// The relayed node's name.
        name: String,
        /// A center of this node the relayed node may reach; can be given more than once.
        #[arg(long = "center", value_name = "CENTER")]
        centers: Vec<String>,
    },
    /// Give a relayed node limits of its own, in place of the relay's --max-links-per-node and --max-opens-per-minute: for a relay behind this one, which carries many nodes. A flag not given keeps that limit; without either flag, the relay's limits again.
    SetLimits {
        /// The relayed node's name.
        name: String,
        /// Its tunnels at once.
        #[arg(long, value_name = "N")]
        max_links: Option<u32>,
        /// The tunnels it may open a minute.
        #[arg(long, value_name = "N")]
        max_opens_per_minute: Option<u32>,
    },
    /// Give a relayed node a new token and end the tunnels of the old one; its centers and limits stay. Shows the token once.
    Token {
        /// The relayed node's name.
        name: String,
    },
    /// Take a node's token away and end its tunnels.
    Rm {
        /// The relayed node's name.
        name: String,
    },
    /// Show the relay, the nodes that may use it and, on a running node, who is connected.
    Ls,
}

/// The command list as `nerve-node --help` has it, for anything that shows
/// the commands elsewhere (the center's help page). It is read from the
/// [`Cli`] definition above, so a new command or flag shows up there by
/// being written once; [`SECTIONS`] only says where on the page it goes.
#[derive(Debug, Clone, Serialize)]
pub struct Help {
    /// What the node is.
    pub about: String,
    /// Options every command takes.
    pub global: Vec<ArgHelp>,
    /// Arguments that cards on different places take alike (`--center`),
    /// said once here and left out of the cards.
    pub common: Vec<ArgHelp>,
    /// The cards, grouped by what a person wants to do, in reading order.
    pub sections: Vec<Section>,
}

/// Where each command stands on the help page: the heading, the sentence
/// under it, and the cards. A card is the commands named in one slice: a
/// noun with its verbs (`["folder"]`), or loose commands that belong
/// together (`["panic", "unlock"]`). A command missing here still shows up,
/// in a section of its own, and a test fails until it is placed.
const SECTIONS: &[(&str, &str, &[&[&str]])] = &[
    (
        "Install and set up",
        "Run the node as a service under a user of its own (Linux with sudo, Windows as administrator), set it up, keep it current, and back it up or move it.",
        &[
            &["install", "uninstall"],
            &["setup"],
            &["update"],
            &["backup", "restore"],
        ],
    ),
    (
        "Pair and connect",
        "Link this machine to centers and choose how it reaches them.",
        &[&["center"], &["proxy"], &["relay"]],
    ),
    (
        "What a center may do",
        "Every center has its own rights on this machine. `config` reaches any setting by its name.",
        &[
            &["mode"],
            &["folder"],
            &["rule"],
            &["cap"],
            &["sudo"],
            &["config"],
        ],
    ),
    (
        "Run and watch",
        "Start the node, see what it did, and stop it.",
        &[&["run"], &["status"], &["audit"], &["panic", "unlock"]],
    ),
];

/// A heading with its sentence, and the cards below it.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    /// What the section is for, said once for all its cards.
    pub about: String,
    pub cards: Vec<Card>,
}

/// One thing a person looks up: a noun with its verbs, or loose commands
/// that go together.
#[derive(Debug, Clone, Serialize)]
pub struct Card {
    /// `folder`, `panic / unlock`.
    pub name: String,
    /// What it is for; empty when its commands say it themselves.
    pub about: String,
    /// The commands that only hold more commands (`folder`), which the card
    /// covers without a line of their own.
    pub holds: Vec<String>,
    /// Arguments that two or more verbs take in the same way, said once.
    pub shared_args: Vec<ArgHelp>,
    pub verbs: Vec<Verb>,
}

/// A command that does something.
#[derive(Debug, Clone, Serialize)]
pub struct Verb {
    /// The words after `nerve-node`: `status`, `folder add`.
    pub name: String,
    /// The usage line, for example `nerve-node folder add [OPTIONS] <PATH>`.
    pub usage: String,
    /// The explanation: the doc comment of the command.
    pub about: String,
    /// Its own arguments and flags, without the global and the shared ones.
    pub args: Vec<ArgHelp>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ArgHelp {
    /// How it is written: `--for <HOURS>`, `<PATH>`, `--wildcard`.
    pub name: String,
    /// The explanation; empty when the argument has none.
    pub about: String,
    /// Whether it can be left out.
    pub optional: bool,
}

impl Help {
    /// Every verb, card by card.
    pub fn verbs(&self) -> impl Iterator<Item = &Verb> {
        self.sections
            .iter()
            .flat_map(|s| &s.cards)
            .flat_map(|c| &c.verbs)
    }

    /// Every command the page covers: the verbs and the commands that only
    /// hold more commands.
    pub fn command_names(&self) -> Vec<&str> {
        let cards = self.sections.iter().flat_map(|s| &s.cards);
        let holds = cards.clone().flat_map(|c| &c.holds).map(String::as_str);
        let verbs = self.verbs().map(|v| v.name.as_str());
        holds.chain(verbs).collect()
    }
}

fn visible(c: &clap::Command) -> bool {
    // clap adds a `help` sub-command of its own to every level.
    c.get_name() != "help" && !c.is_hide_set()
}

/// Reads [`Help`] from the [`Cli`] definition.
pub fn help() -> Help {
    let mut root = Cli::command();
    root.build();
    let mut left: Vec<&clap::Command> = root.get_subcommands().filter(|c| visible(c)).collect();
    let mut sections = Vec::new();
    for (name, about, cards) in SECTIONS {
        let mut out = Vec::new();
        for names in *cards {
            let cmds: Vec<&clap::Command> = names
                .iter()
                .filter_map(|n| root.find_subcommand(n))
                .collect();
            left.retain(|c| !names.contains(&c.get_name()));
            out.extend(cards_of(&cmds));
        }
        sections.push(Section {
            name: (*name).into(),
            about: (*about).into(),
            cards: out,
        });
    }
    if !left.is_empty() {
        sections.push(Section {
            name: "Other commands".into(),
            about: String::new(),
            cards: left.into_iter().flat_map(|c| cards_of(&[c])).collect(),
        });
    }
    let common = hoist_common(&mut sections);
    Help {
        about: about_of(&root),
        global: root
            .get_arguments()
            .filter(|a| a.is_global_set())
            .map(arg_help)
            .collect(),
        common,
        sections,
    }
}

/// Takes the arguments that two or more cards have alike out of the cards.
fn hoist_common(sections: &mut [Section]) -> Vec<ArgHelp> {
    let args_of = |c: &Card| -> Vec<ArgHelp> {
        let own = c.verbs.iter().flat_map(|v| &v.args);
        c.shared_args.iter().chain(own).cloned().collect()
    };
    let mut common: Vec<ArgHelp> = Vec::new();
    for a in sections.iter().flat_map(|s| &s.cards).flat_map(args_of) {
        let on = sections
            .iter()
            .flat_map(|s| &s.cards)
            .filter(|c| args_of(c).contains(&a))
            .count();
        if on > 1 && !common.contains(&a) {
            common.push(a);
        }
    }
    for c in sections.iter_mut().flat_map(|s| &mut s.cards) {
        c.shared_args.retain(|a| !common.contains(a));
        for v in &mut c.verbs {
            v.args.retain(|a| !common.contains(a));
        }
    }
    common
}

fn about_of(c: &clap::Command) -> String {
    c.get_about().map(ToString::to_string).unwrap_or_default()
}

fn cards_of(cmds: &[&clap::Command]) -> Vec<Card> {
    if let [one] = cmds
        && one.has_subcommands()
    {
        return noun_cards(one, one.get_name());
    }
    let verbs = cmds.iter().map(|c| verb(c, c.get_name())).collect();
    let names: Vec<&str> = cmds.iter().map(|c| c.get_name()).collect();
    vec![card(&names.join(" / "), String::new(), Vec::new(), verbs)]
}

fn card(name: &str, about: String, holds: Vec<String>, mut verbs: Vec<Verb>) -> Card {
    // An argument that two verbs take alike is said once, on the card.
    let mut shared: Vec<ArgHelp> = Vec::new();
    for a in verbs.iter().flat_map(|v| &v.args) {
        if !shared.contains(a) && verbs.iter().filter(|v| v.args.contains(a)).count() > 1 {
            shared.push(a.clone());
        }
    }
    for v in &mut verbs {
        v.args.retain(|a| !shared.contains(a));
    }
    Card {
        name: name.into(),
        about,
        holds,
        shared_args: shared,
        verbs,
    }
}

/// The cards of a noun (`folder`): its verbs on one card, and a card for
/// each sub-noun below it.
fn noun_cards(noun: &clap::Command, name: &str) -> Vec<Card> {
    let (holders, leaves): (Vec<_>, Vec<_>) = noun
        .get_subcommands()
        .filter(|c| visible(c))
        .partition(|c| c.has_subcommands());
    let mut out = Vec::new();
    if !leaves.is_empty() {
        let verbs = leaves
            .iter()
            .map(|c| verb(c, &format!("{name} {}", c.get_name())))
            .collect();
        out.push(card(name, about_of(noun), vec![name.into()], verbs));
    }
    for h in &holders {
        out.extend(noun_cards(h, &format!("{name} {}", h.get_name())));
    }
    if !out.iter().any(|c| c.holds.iter().any(|h| h == name))
        && let Some(first) = out.first_mut()
    {
        first.holds.insert(0, name.into());
    }
    out
}

fn verb(sub: &clap::Command, name: &str) -> Verb {
    let usage = sub.clone().render_usage().to_string();
    Verb {
        name: name.into(),
        usage: usage.strip_prefix("Usage: ").unwrap_or(&usage).to_string(),
        about: about_of(sub),
        args: sub
            .get_arguments()
            .filter(|a| !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
            .map(arg_help)
            .collect(),
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
        optional: !a.is_required_set(),
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
        SettingsStore::peek_with(
            &paths.config_file(),
            &crate::secrets::NodeSecrets::for_cli(paths),
        )?,
        None,
    ))
}

/// Changes the config: through the daemon (retrying when someone else wrote
/// meanwhile), or directly in the file when no daemon runs. An error also
/// when the config is saved but the folder grants do not follow it.
pub async fn edit(
    paths: &NodePaths,
    f: impl Fn(&mut NodeConfig) -> Result<(), String>,
) -> Result<NodeConfig, String> {
    let saved = edit_saved(paths, f).await?;
    match grants_failed(&saved.grants) {
        Some(e) => Err(e),
        None => Ok(saved.cfg),
    }
}

/// The config [`edit_saved`] saved, and what the folder grants did when no
/// daemon took the change (nothing when one did).
pub struct Saved {
    pub cfg: NodeConfig,
    pub grants: crate::grants::Synced,
}

/// Why the folder grants do not follow a saved config, if they do not.
fn grants_failed(s: &crate::grants::Synced) -> Option<String> {
    s.errors
        .first()
        .map(|e| format!("the config is saved, but the folder grants do not follow it: {e}"))
}

/// [`edit`], which is also done when the folder grants do not follow.
pub async fn edit_saved(
    paths: &NodePaths,
    f: impl Fn(&mut NodeConfig) -> Result<(), String>,
) -> Result<Saved, String> {
    #[cfg(unix)]
    {
        let sock = paths.ctl_socket();
        let mut conflicts = 0;
        loop {
            let read = match nerve_transport::ctl::call(&sock, "config.read", json!({})).await {
                Ok(v) => v,
                // Only a node that is not there leaves the file to the CLI.
                Err(e) if e == nerve_transport::ctl::NOT_RUNNING => break,
                Err(e) => return Err(e),
            };
            let mut cfg = NodeConfig::parse(read["config"].as_str().unwrap_or_default())?;
            f(&mut cfg)?;
            let params = json!({"config": cfg.to_toml(), "if_version": read["version"]});
            match nerve_transport::ctl::call(&sock, "config.write", params).await {
                Ok(_) => {
                    return Ok(Saved {
                        cfg,
                        grants: Default::default(),
                    });
                }
                Err(e) if e.starts_with("conflict") => {
                    conflicts += 1;
                    // A node that answered has the file: writing it here
                    // would be undone by its next write, and the change
                    // reported as made.
                    if conflicts == 5 {
                        return Err("the config keeps changing; try again".into());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    let mut store = SettingsStore::open_with(
        paths.config_file(),
        Box::new(crate::secrets::NodeSecrets::for_cli(paths)),
        AuditLog::new(paths.audit_log()),
    )?;
    match store.update(f) {
        Ok(_) => {
            let cfg = store.config().clone();
            // No daemon took the change, so the folder grants of Windows
            // folder mode follow it here (crate::grants); a running node
            // brings them in line with its own config again before a
            // command. A change that takes long says how far it is here.
            let grants =
                crate::grants::apply_outside(paths, &cfg, &crate::paths::home_dir(), &mut |m| {
                    eprintln!("{m}")
                });
            Ok(Saved { cfg, grants })
        }
        Err(SetError::Conflict { .. }) => Err("the config changed meanwhile; try again".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The center a per-center command means: the one named, or the only one.
pub fn pick_center(cfg: &NodeConfig, given: &CenterArg) -> Result<String, String> {
    crate::folder_change::pick_center(cfg, given.center.as_deref())
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

/// `folder set` takes changes that start with `-`, so clap hands it every
/// word after the path, `--center` included. This takes the flag out again.
fn take_center_flag(
    words: Vec<String>,
    mut center: CenterArg,
) -> Result<(Vec<String>, CenterArg), String> {
    let mut changes = Vec::new();
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        let given = if word == "--center" {
            Some(words.next().ok_or("--center needs a name")?)
        } else {
            word.strip_prefix("--center=").map(str::to_string)
        };
        match given {
            Some(name) if center.center.is_none() => center.center = Some(name),
            Some(_) => return Err("--center is given twice".into()),
            None if word.starts_with("--") => return Err(format!("unknown option {word}")),
            None => changes.push(word),
        }
    }
    if changes.is_empty() {
        return Err("name what to change: =rwx, +x or -w".into());
    }
    Ok((changes, center))
}

fn push_unique(list: &mut Vec<String>, rule: &str) {
    if !list.iter().any(|r| r == rule) {
        list.push(rule.to_string());
    }
}

/// `center pause` and `center resume`: the owner's switch, the only way a
/// pause ends (a center can pause itself, never unpause).
async fn pause_center(
    paths: &NodePaths,
    center: &CenterArg,
    pause: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let name = edit_center(paths, center, |e| {
        e.paused = pause;
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "{name}: {}", if pause { "paused" } else { "resumed" });
    Ok(())
}

impl List {
    fn of(self, p: &mut nerve_policy::CenterPolicy) -> &mut Vec<String> {
        match self {
            List::Allow => &mut p.allow,
            List::Deny => &mut p.deny,
            List::Sudo => &mut p.sudo_allow,
        }
    }

    fn word(self) -> &'static str {
        match self {
            List::Allow => "allow",
            List::Deny => "deny",
            List::Sudo => "sudo",
        }
    }

    fn label(self) -> &'static str {
        match self {
            List::Allow => "allow rule (allowlist mode)",
            List::Deny => "deny rule",
            List::Sudo => "sudo allow list",
        }
    }

    /// The entry a command line stands for, for `rule add`: the same as
    /// [`List::command_rule`], but a line in the pattern form of `config add`
    /// (`fs.read:~/notes/*`, `fs:~/private/*`) is refused. As a command it
    /// would become a rule that never matches. A single letter before the `:`
    /// is a drive (`C:\tools\x.exe`), not a capability.
    fn entry(self, command: &str, wildcard: bool) -> Result<String, String> {
        if matches!(self, List::Allow | List::Deny)
            && let Some((scope, _)) = command.trim().split_once(':')
            && (scope.contains('.') || scope.len() > 1)
            && rules::valid_scope(scope)
        {
            return Err(format!(
                "`{scope}:` is the pattern form for files and other actions, not a command: add it with `nerve-node config add center.<name>.policy.{}`",
                self.word()
            ));
        }
        self.command_rule(command, wildcard)
    }

    /// The rule a command line stands for. The allow and deny lists hold
    /// `exec.run` rules; the sudo list holds the sudo command lines, and takes
    /// the command with or without the `sudo` in front. `rule rm` uses it
    /// as it is, so the rules an older `rule add` made from the pattern form
    /// can be removed with the arguments that made them.
    fn command_rule(self, command: &str, wildcard: bool) -> Result<String, String> {
        match self {
            List::Allow if sudo_command(command).is_some() => {
                Err("a sudo command goes on the sudo list: `nerve-node rule add sudo`".into())
            }
            List::Allow | List::Deny => rules::rule_for("exec", "run", command, wildcard),
            List::Sudo if sudo_command(command).is_some() => {
                rules::sudo_rule_for(command, wildcard)
            }
            List::Sudo => rules::sudo_rule_for(&format!("sudo {}", command.trim()), wildcard),
        }
    }
}

/// `rule add|rm|ls`.
async fn rule_cmd(paths: &NodePaths, c: RuleCmd, out: &mut dyn Write) -> Result<(), String> {
    match c {
        RuleCmd::Add {
            list,
            command,
            wildcard,
            center,
        } => {
            let rule = list.entry(&command, wildcard)?;
            let name = edit_center(paths, &center, |e| {
                push_unique(list.of(&mut e.policy), &rule);
                Ok(())
            })
            .await?;
            let note = match list {
                List::Deny => "; commands it matches are forbidden",
                _ => "",
            };
            let _ = writeln!(out, "{name}: {} {rule:?}{note}", list.label());
        }
        RuleCmd::Rm {
            list,
            command,
            wildcard,
            center,
        } => {
            let removed = std::sync::Mutex::new(String::new());
            let name = edit_center(paths, &center, |e| {
                let name = e.name.clone();
                let l = list.of(&mut e.policy);
                // An entry copied from `ls` goes as it is, so rules for
                // files and other actions can be removed too. The arguments
                // of `add` stand for the command rule they made.
                let made = list.command_rule(&command, wildcard);
                let rule = match made {
                    Ok(made) if made != command && l.contains(&command) && l.contains(&made) => {
                        return Err(format!(
                            "both {command:?} and {made:?} are on the {}: remove {made:?} first with `nerve-node rule rm {word} '{made}' --center {center}`, and then {command:?} with `nerve-node rule rm {word} '{command}' --center {center}`",
                            list.label(),
                            word = list.word(),
                            center = name
                        ));
                    }
                    _ if l.contains(&command) => command.clone(),
                    made => made?,
                };
                let before = l.len();
                l.retain(|r| *r != rule);
                if l.len() == before {
                    return Err(format!("{rule:?} is not on the {}", list.label()));
                }
                *removed.lock().unwrap() = rule;
                Ok(())
            })
            .await?;
            let removed = removed.into_inner().unwrap();
            let _ = writeln!(out, "{name}: removed {removed:?} from the {}", list.label());
        }
        RuleCmd::Ls { list, center } => {
            let (cfg, _) = read_config(paths).await?;
            let name = pick_center(&cfg, &center)?;
            let mut policy = cfg.center(&name).expect("picked").policy.clone();
            if let Some(list) = list {
                let entries = list.of(&mut policy);
                if entries.is_empty() {
                    let _ = writeln!(out, "{name}: nothing on the {}", list.label());
                }
                for r in entries.iter() {
                    let _ = writeln!(out, "{r}");
                }
            } else {
                // All three: each line says which list it is on.
                let mut any = false;
                for list in [List::Allow, List::Deny, List::Sudo] {
                    for r in list.of(&mut policy).iter() {
                        any = true;
                        let _ = writeln!(out, "{}  {r}", list.word());
                    }
                }
                if !any {
                    let _ = writeln!(out, "{name}: nothing on any rule list");
                }
            }
        }
    }
    Ok(())
}

/// When a change that only the file holds counts.
const NEXT_START: &str = "takes effect at the next start of the node";

/// Runs one command line, writing what it shows to `out`. A change made
/// while no daemon answers on the control socket (none runs, or Windows,
/// whose pipe takes folder changes only) is only in the file, so the output
/// says when it counts.
pub async fn execute(cli: Cli, out: &mut dyn Write) -> Result<(), String> {
    let service = cli.cmd.is_service();
    if service && (cli.config_dir.is_some() || cli.state_dir.is_some()) {
        let l = Layout::system();
        return Err(format!(
            "install, update and uninstall keep the node's files in {} and {}; --config-dir and --state-dir do not go with them",
            l.paths.config_dir.display(),
            l.paths.state_dir.display()
        ));
    }
    let paths = NodePaths::from_args(cli.config_dir, cli.state_dir);
    if !service {
        crate::service::check_access(&paths)?;
    }
    // The daemon writes the file itself while it runs; the service commands
    // leave it alone (or delete it with the rest). Sudo on Windows says
    // itself when its change counts (crate::winsudo).
    // A restore says itself what comes next.
    let own_say = (cfg!(windows) && matches!(cli.cmd, Cmd::Sudo(_)))
        || matches!(cli.cmd, Cmd::Restore { .. });
    let before = (!matches!(cli.cmd, Cmd::Run) && !service && !own_say)
        .then(|| std::fs::read(paths.config_file()).ok());
    // On Windows the running node takes folder changes over its pipe, and
    // nothing else yet.
    let folders = matches!(
        cli.cmd,
        Cmd::Folder(FolderCmd::Add { .. } | FolderCmd::Set { .. } | FolderCmd::Rm { .. })
    );
    let r = command(paths.clone(), cli.cmd, out).await;
    if r.is_ok()
        && let Some(before) = before
        && std::fs::read(paths.config_file()).ok() != before
        && !daemon_answers(&paths, folders).await
    {
        let _ = writeln!(out, "the change is in node.toml; it {NEXT_START}");
    }
    r
}

impl Cmd {
    /// install, update and uninstall: they work on the installed node, as
    /// root.
    fn is_service(&self) -> bool {
        matches!(
            self,
            Cmd::Install | Cmd::Update { .. } | Cmd::Uninstall { .. }
        )
    }
}

/// Run first in `main`, while the process has one thread: a command that
/// root runs on a node whose folders belong to another user, as the
/// installed node's belong to `nerve`, runs as that user
/// ([`crate::service::become_owner`]), so that what it writes stays the
/// node's. install, update and uninstall keep root; setup keeps it as its
/// saved id, to make the account of the commands when the owner asks.
pub fn settle_user(cli: &Cli) -> Result<(), String> {
    if cli.cmd.is_service() {
        return Ok(());
    }
    crate::service::become_owner(
        &NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone()),
        matches!(cli.cmd, Cmd::Setup { .. }),
    )
}

/// The account that ran this command through sudo, else root. On Windows
/// the account this command runs as.
fn invoker() -> String {
    #[cfg(windows)]
    if let Ok(me) = crate::win_user::current_user() {
        return me;
    }
    std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "root".into())
}

/// On Windows, `run` on the installed node's folders runs under the service
/// control manager (crate::win_service): the node's log file, where a start
/// that fails is said. `None` for any other command.
pub fn service_log(cli: &Cli) -> Option<PathBuf> {
    if !matches!(cli.cmd, Cmd::Run) {
        return None;
    }
    let paths = NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
    crate::service::is_service_node(&paths).then(|| paths.log_file())
}

/// The rule of the other owner commands (docs/dev/spec/node-local.md §5):
/// nothing a command of a center starts may install, set up, update or
/// remove the node, nor back it up or restore it. The node that runs knows
/// its commands, so it is asked over its control socket, and refuses a
/// caller below one of them.
async fn owner_check(paths: &[&NodePaths]) -> Result<(), String> {
    #[cfg(unix)]
    for p in paths {
        match nerve_transport::ctl::call(&p.ctl_socket(), "owner.check", json!({})).await {
            Ok(_) => {}
            // No node runs, so no command of one does.
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
            // A node that does not know the method cannot answer it. It is let
            // through.
            Err(e) if e.starts_with("unknown method") => {}
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(unix))]
    let _ = paths;
    Ok(())
}

/// Whether a daemon runs on the control socket; it then took every change
/// at once. One that takes no connection now runs all the same; a socket
/// that cannot be reached at all is none. On Windows it takes only `folders`
/// changes over its pipe, so only those count as taken when it answers.
async fn daemon_answers(paths: &NodePaths, folders: bool) -> bool {
    #[cfg(unix)]
    {
        let _ = folders;
        let outcome = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await;
        nerve_transport::ctl::node_is_there(&outcome).unwrap_or(false)
    }
    #[cfg(windows)]
    {
        folders && crate::pipe::call(paths, "status", json!({})).await.is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (paths, folders);
        false
    }
}

/// What `status` says of the limits per command (crate::cgroup::status):
/// what a command gets and may ask for, then where they hold or why not.
fn limits_lines(v: &Value) -> Vec<String> {
    let n = |k: &str| v[k].as_u64().unwrap_or_default();
    let mut lines = vec![format!(
        "limits per command: memory {} MiB, CPU {} %, {} processes; a call may ask for up to {} MiB, {} %, {} processes",
        n("memory_mb"),
        n("cpu_percent"),
        n("processes"),
        n("memory_max_mb"),
        n("cpu_max_percent"),
        n("processes_max"),
    )];
    let list = |k: &str| -> Vec<&str> {
        v[k].as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect()
    };
    let (enforced, lost) = (list("enforced"), list("lost"));
    if let Some(cgroup) = v["cgroup"].as_str() {
        let not: Vec<&str> = ["memory", "cpu", "processes"]
            .into_iter()
            .filter(|l| !enforced.contains(l) && !lost.contains(l))
            .collect();
        let mut line = match enforced.is_empty() {
            true => format!("limits held by the cgroup {cgroup}: none"),
            false => format!(
                "limits held by the cgroup {cgroup}: {}",
                enforced.join(", ")
            ),
        };
        if !not.is_empty() {
            line.push_str(&format!(
                "; not {} (the cgroup has no controller for it)",
                not.join(", ")
            ));
        }
        lines.push(line);
        // Turned off while the node ran: no command runs (crate::cgroup).
        if !lost.is_empty() {
            lines.push(format!(
                "NO COMMAND RUNS: {} turned off in the cgroup since the node started; start the node again",
                lost.join(", ")
            ));
        }
    } else if let Some(why) = v["off"].as_str() {
        lines.push(format!("commands run WITHOUT these limits: {why}"));
    }
    lines
}

/// What `status` says when no daemon answered. With a control socket
/// (Unix) that means none runs; without one a running node cannot be told
/// apart from a stopped one.
fn no_daemon_status(socket: bool) -> String {
    if socket {
        "daemon: not running".into()
    } else {
        format!("daemon: not known (no control socket on Windows); a change {NEXT_START}")
    }
}

async fn command(paths: NodePaths, cmd: Cmd, out: &mut dyn Write) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    match cmd {
        Cmd::Run => {
            let mut opts = NodeOptions::new(paths);
            opts.exe = std::env::current_exe().ok();
            Daemon::run(opts).await
        }
        Cmd::Center(CenterCmd::Add { link, name, yes }) => {
            let link = PairLink::parse(&link)?;
            w(out, crate::pair::preview(&link, name.as_deref()));
            if !yes && !confirm(&mut std::io::stdin().lock(), out)? {
                return Err("not paired".into());
            }
            let e = crate::pair::pair(&paths, &link, name.as_deref()).await?;
            w(out, format!("paired with {} as {}", e.url, e.name));
            Ok(())
        }
        Cmd::Center(CenterCmd::Rm(center)) => {
            let (cfg, _) = read_config(&paths).await?;
            let name = pick_center(&cfg, &center)?;
            let gone = std::sync::Mutex::new(Vec::new());
            // Saved also when the folder grants of the other pairings do not
            // follow: the pairing is gone then, so its key and profile go
            // now, or nothing names them later.
            let saved = edit_saved(&paths, |c| {
                let mut g = gone.lock().unwrap_or_else(|p| p.into_inner());
                g.clear();
                g.extend(
                    c.centers
                        .iter()
                        .filter(|e| e.name == name)
                        .map(|e| e.node_id.clone()),
                );
                c.centers.retain(|e| e.name != name);
                Ok(())
            })
            .await?;
            let cfg = &saved.cfg;
            // The center is gone either way; a key that stays behind is
            // said, not hidden.
            if let Err(e) =
                crate::secrets::remove_center_key(&paths, cfg.machine.secret_storage, &name)
            {
                w(out, format!("the node key for {name} was not deleted: {e}"));
            }
            // So is the profile of its container on Windows (crate::grants):
            // with its last grant when the record names it, else found by
            // the pairing. A node that runs still serves the center until it
            // starts again, so there it stays.
            let mut p = saved.grants.profiles.clone();
            let mut ours = Vec::new();
            for id in gone.into_inner().unwrap_or_else(|p| p.into_inner()) {
                if cfg.centers.iter().any(|c| c.node_id == id) {
                    continue;
                }
                ours.extend(crate::grants::containers(&paths, &id));
                p.merge(crate::grants::forget(&paths, &id));
            }
            let of = |n: &String| {
                if ours.contains(n) {
                    format!("{n} of {name}")
                } else {
                    n.clone()
                }
            };
            for n in &p.removed {
                w(out, format!("removed the AppContainer profile {}", of(n)));
            }
            if let Some(why) = &p.why {
                for n in &p.kept {
                    w(
                        out,
                        format!(
                            "the AppContainer profile {} stays, since {why}: once the node stopped, remove it by hand (docs/user/modes.md)",
                            of(n)
                        ),
                    );
                }
            }
            for e in &p.errors {
                w(
                    out,
                    format!("the AppContainer profile of {name} was not removed: {e}"),
                );
            }
            w(out, format!("unpaired {name}"));
            match grants_failed(&saved.grants) {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        Cmd::Center(CenterCmd::Ls) => {
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
                // Which `nerve.*` profile is this pairing's: the others
                // belong to other nodes or are left over (docs/user/modes.md).
                if cfg!(windows) {
                    w(
                        out,
                        format!(
                            "  AppContainer {}",
                            crate::grants::profile_name(&paths, &c.node_id)
                        ),
                    );
                }
            }
            Ok(())
        }
        Cmd::Center(CenterCmd::Pause(center)) => pause_center(&paths, &center, true, out).await,
        Cmd::Center(CenterCmd::Resume(center)) => pause_center(&paths, &center, false, out).await,
        Cmd::Center(CenterCmd::Grant {
            what,
            value,
            center,
        }) => {
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
                    if let Some(why) = v["folder_commands_off"].as_str() {
                        w(out, format!("folder mode runs no command: {why}"));
                    }
                    for line in limits_lines(&v["command_limits"]) {
                        w(out, line);
                    }
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
                    for p in v["providers"].as_array().into_iter().flatten() {
                        let caps: Vec<&str> = p["capabilities"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect();
                        w(
                            out,
                            format!(
                                "provider {} attached: {}",
                                p["name"].as_str().unwrap_or_default(),
                                caps.join(", ")
                            ),
                        );
                    }
                    let relay = &v["relay"];
                    if relay["listen"].is_string() {
                        let tunnels = relay["tunnels"].as_array().map_or(0, Vec::len);
                        w(
                            out,
                            format!(
                                "relay: {}, {tunnels} tunnels open (`nerve-node relay ls` names them)",
                                relay["status"].as_str().unwrap_or_default()
                            ),
                        );
                    }
                    return Ok(());
                }
                Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
                Err(_) => {}
            }
            let cfg = SettingsStore::peek_with(
                &paths.config_file(),
                &crate::secrets::NodeSecrets::for_cli(&paths),
            )?;
            w(out, no_daemon_status(cfg!(unix)));
            let limits =
                crate::cgroup::status(&cfg.limits.command, &Err("the node does not run".into()));
            if let Some(line) = limits_lines(&limits).first() {
                w(out, line.clone());
            }
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
        Cmd::Mode(ModeCmd::Set {
            mode,
            for_hours,
            center,
        }) => set_mode(&paths, &mode, for_hours, &center, out).await,
        Cmd::Folder(FolderCmd::Add {
            path,
            rights,
            center,
        }) => add_folder(&paths, &path, &rights, &center, out).await,
        Cmd::Folder(FolderCmd::Set {
            path,
            changes,
            center,
        }) => {
            let (changes, center) = take_center_flag(changes, center)?;
            let a = change_stored_folder(&paths, &center, &path, |at| FolderChange::Set {
                path: at.clone(),
                given: at,
                changes: changes.clone(),
            })
            .await?;
            let access = a.access.unwrap_or(Access::NONE);
            w(
                out,
                format!("{}: folder {} {}", a.center, a.path, access.to_chmod()),
            );
            if access.is_none() {
                w(
                    out,
                    "note: the folder grants nothing now (`nerve-node folder rm` removes it)"
                        .into(),
                );
            }
            Ok(())
        }
        Cmd::Folder(FolderCmd::Rm { path, center }) => {
            let a = change_stored_folder(&paths, &center, &path, |at| FolderChange::Rm {
                path: at.clone(),
                given: at,
            })
            .await?;
            w(out, format!("{}: removed {}", a.center, a.path));
            Ok(())
        }
        Cmd::Folder(FolderCmd::Ls { center }) => {
            let (cfg, _) = read_config(&paths).await?;
            let name = pick_center(&cfg, &center)?;
            let folders = &cfg.center(&name).expect("picked").policy.folders;
            if folders.is_empty() {
                w(out, format!("{name}: no folders"));
            }
            for f in folders {
                w(out, format!("{}  {}", f.access.to_chmod(), f.path));
            }
            Ok(())
        }
        Cmd::Cap(CapCmd::Set {
            cap,
            setting,
            center,
        }) => {
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
        Cmd::Cap(CapCmd::Ls { center }) => {
            let (cfg, _) = read_config(&paths).await?;
            let name = pick_center(&cfg, &center)?;
            let caps = &cfg.center(&name).expect("picked").policy.caps;
            if caps.is_empty() {
                w(out, format!("{name}: no capability was set"));
            }
            for (cap, setting) in caps {
                w(out, format!("{cap}  {}", enum_str(setting)));
            }
            Ok(())
        }
        Cmd::Config(c) => config_cmd(&paths, c, out).await,
        Cmd::Rule(c) => rule_cmd(&paths, c, out).await,
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
        Cmd::Proxy(c) => proxy_cmd(&paths, c, out).await,
        Cmd::Relay(c) => relay_cmd(&paths, c, out).await,
        Cmd::Sudo(c) => sudo_cmd(&paths, c, out).await,
        Cmd::Backup {
            file,
            include_keyring,
            overwrite,
            passphrase_file,
        } => {
            // A command of a center must not take the node's keys out under a
            // passphrase of its own.
            owner_check(&[&paths]).await?;
            let (cfg, _) = read_config(&paths).await?;
            let pass = crate::prompt::passphrase(passphrase_file.as_deref(), out, true)?;
            let opts = crate::backup::BackupOpts {
                include_keyring,
                overwrite,
                rounds: nerve_transport::backup::ITERATIONS,
            };
            let r = crate::backup::backup(&paths, &cfg, &file, &pass, &opts)?;
            crate::backup::print_backup(&r, &file, out);
            Ok(())
        }
        Cmd::Restore {
            file,
            replace,
            secret_storage,
            without_proxy,
            passphrase_file,
        } => {
            owner_check(&[&paths]).await?;
            let bytes = nerve_transport::backup::read_file(&file)?;
            let kind = nerve_transport::backup::kind_of(&bytes)?;
            if kind != nerve_transport::backup::Kind::Node {
                return Err(format!(
                    "this is the backup of a {}, not of a node: restore it with `nerve-center restore`",
                    kind.word()
                ));
            }
            let storage = secret_storage
                .map(|s| parse_enum::<SecretStorage>(&s, "file or keyring"))
                .transpose()?;
            let pass = crate::prompt::passphrase(passphrase_file.as_deref(), out, false)?;
            let parsed = crate::backup::open(&bytes, &pass)?;
            let opts = crate::backup::RestoreOpts {
                replace,
                secret_storage: storage,
                without_proxy,
            };
            let r = crate::backup::restore(&paths, &parsed, &opts)?;
            crate::backup::print_restore(&r, &parsed, out);
            Ok(())
        }
        Cmd::Install => {
            let layout = Layout::system();
            owner_check(&[&paths, &layout.paths]).await?;
            let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
            #[cfg(windows)]
            return crate::winsvc::install(
                &layout,
                &crate::win_host::WinHost,
                &exe,
                &invoker(),
                out,
            );
            #[cfg(not(windows))]
            {
                // Asked only in a terminal: a script that installs gets the
                // refusal instead of a question.
                use std::io::IsTerminal;
                let stdin = std::io::stdin();
                let mut input = std::io::BufReader::new(stdin.lock());
                let terminal = stdin.is_terminal();
                let keyring = crate::keyring_setup::HostKeyring {
                    exe: layout.bin.clone(),
                };
                crate::service::install_asking(
                    &layout,
                    &Host,
                    &keyring,
                    terminal.then_some(&mut input as &mut dyn BufRead),
                    &exe,
                    &invoker(),
                    out,
                )
            }
        }
        Cmd::Setup { create_user } => {
            owner_check(&[&paths]).await?;
            // Windows takes the account of the commands, and its password,
            // at install.
            if cfg!(windows) && create_user.is_some() {
                return Err(
                    "on Windows the account commands run as is the one that runs `nerve-node install`, which asks for its password; --create-user does not go with it".into(),
                );
            }
            let mut input = std::io::BufReader::new(std::io::stdin());
            let layout = Layout::system();
            let machine = (!cfg!(windows) && layout.installed() && paths == layout.paths)
                .then_some(&Host as &dyn crate::service::System);
            // The installed program, which the node's user can run, asks
            // its keyring.
            let keyring = match machine {
                Some(_) => crate::keyring_setup::HostKeyring {
                    exe: layout.bin.clone(),
                },
                None => crate::keyring_setup::HostKeyring::this_program(),
            };
            setup(
                &paths,
                machine,
                create_user.as_deref(),
                &keyring,
                &mut input,
                out,
            )
            .await
        }
        Cmd::Update { from } => {
            let layout = Layout::system();
            owner_check(&[&layout.paths]).await?;
            #[cfg(windows)]
            return crate::winsvc::update(&layout, &crate::win_host::WinHost, from.as_deref(), out)
                .await;
            #[cfg(not(windows))]
            crate::service::update(&layout, &Host, from.as_deref(), out).await
        }
        Cmd::Uninstall { purge } => {
            let layout = Layout::system();
            owner_check(&[&layout.paths]).await?;
            // The node run by hand: the one named, or the one in this
            // user's default folders.
            #[cfg(windows)]
            let by_hand = if paths == layout.paths {
                NodePaths::by_hand()
            } else {
                paths
            };
            #[cfg(windows)]
            return crate::winsvc::uninstall(
                &layout,
                &by_hand,
                &crate::win_host::WinHost,
                purge,
                out,
            );
            #[cfg(not(windows))]
            crate::service::uninstall(&layout, &Host, purge, out)
        }
    }
}

/// `setup`: the first-run steps in the terminal: the node's name, where it
/// keeps its keys, its first center and that center's mode. Each answer is
/// saved when it is given,
/// through the same owner path as the other commands (the running node, or
/// the signed `node.toml`), so setup can stop anywhere and run again; Enter
/// keeps what is there. The steps done are audited. `machine` is there on
/// the installed node, where setup also chooses the account of the
/// commands: `create_user` names it (and makes it) instead of asking. Keys
/// in the system keyring need one that answers; `keyring` checks it, and
/// installs one when the owner says so ([`crate::keyring_setup`]).
pub async fn setup(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    create_user: Option<&str>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<(), String> {
    let mut steps = Vec::new();
    let r = setup_steps(paths, machine, create_user, keyring, input, out, &mut steps).await;
    let log = AuditLog::new(paths.audit_log());
    if let Err(e) = log.node("setup", &steps, r.as_ref().err().map(String::as_str)) {
        let _ = writeln!(out, "the audit log cannot be written: {e}");
    }
    r
}

/// Once the keyring answers setup, whether setup installed it or it came some
/// other way: a node that runs and found none before does not look again
/// (`keyring_failed` in its status, [`crate::secrets::store::failed`]), so it
/// would refuse the move. The installed node is restarted; a node run by hand
/// is left to its owner.
async fn after_keyring_answers(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    out: &mut dyn Write,
) -> Result<(), String> {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(status) => return restart_for_keyring(&status, paths, machine, out),
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
        Err(e) => {
            let _ = writeln!(
                out,
                "the running node was not asked whether it found a keyring ({e}); restart it if it did not"
            );
            return Ok(());
        }
    }
    #[cfg(not(unix))]
    let _ = (paths, machine, out);
    Ok(())
}

/// What [`after_keyring_answers`] does with the running node's `status`.
#[cfg_attr(not(unix), allow(dead_code))]
fn restart_for_keyring(
    status: &Value,
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    out: &mut dyn Write,
) -> Result<(), String> {
    if status["keyring_failed"] != true {
        return Ok(());
    }
    let Some(sys) = machine else {
        return Err("the system keyring answers now, but the node that runs for this folder found none before and does not look again until it is restarted; restart it, then run `nerve-node setup` again".into());
    };
    sys.systemctl(&["restart", crate::service::UNIT_NAME])?;
    sys.wait_running(paths)?;
    let _ = writeln!(
        out,
        "restarted the node, which had found no keyring before this one answered"
    );
    Ok(())
}

/// Saves the account setup chose for the commands, if it chose one.
async fn account_chosen(
    paths: &NodePaths,
    chosen: Option<crate::service::Chosen>,
    out: &mut dyn Write,
    steps: &mut Vec<String>,
) -> Result<(), String> {
    let Some(c) = chosen else {
        return Ok(());
    };
    if c.made {
        steps.push(format!("made the account {}", c.name));
    }
    edit(paths, |cfg| {
        cfg.machine.user = Some(c.name.clone());
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "commands run as {}", c.name);
    steps.push(format!("commands run as {}", c.name));
    Ok(())
}

async fn setup_steps(
    paths: &NodePaths,
    machine: Option<&dyn crate::service::System>,
    create_user: Option<&str>,
    keyring: &dyn crate::keyring_setup::Keyring,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    steps: &mut Vec<String>,
) -> Result<(), String> {
    if create_user.is_some() && machine.is_none() {
        return Err(
            "--create-user chooses the account commands run as on a node installed as a service (`sudo nerve-node install`); this node runs them as its own user".into(),
        );
    }
    // Keys in a keyring that does not answer: nothing can be read, so that
    // comes first, also where the keys may not stay there, so that they can go
    // into files below. The installed node on Windows asks none: the keyring
    // setup reaches is not the service's.
    let no_keyring = crate::secrets::no_keyring(paths);
    if crate::secrets::stated_storage(paths) == SecretStorage::Keyring
        && no_keyring != Some(crate::secrets::NoKeyring::WindowsService)
    {
        let me = crate::keyring_setup::me()?;
        crate::keyring_setup::ensure(keyring, &me, Some(input), out)?;
        after_keyring_answers(paths, machine, out).await?;
    }
    let (cfg, _) = read_config(paths).await?;
    if let (Some(sys), Some(name)) = (machine, create_user) {
        let c = crate::service::create_account(sys, paths, name, &invoker(), out)?;
        let chosen = (c.made || cfg.machine.user.as_deref() != Some(name)).then_some(c);
        account_chosen(paths, chosen, out, steps).await?;
    }
    let _ = writeln!(out, "Set up this node. Enter keeps what is in [brackets].");
    let current = crate::descriptor::node_name(&cfg);
    let name = ask(
        input,
        out,
        &format!("Name of this node, as centers show it [{current}]: "),
    )?;
    if !name.is_empty() && name != current {
        if !nerve_proto::valid_node_name(&name) {
            return Err(format!(
                "{name:?} is not a node name: 1 to 32 characters of a-z, 0-9 and -"
            ));
        }
        edit(paths, |c| {
            c.node.name = Some(name.clone());
            Ok(())
        })
        .await?;
        steps.push(format!("named the node {name}"));
    }

    // The account of the commands, where the node can switch to one: the
    // installed service. Named on the command line, it was chosen first.
    if let Some(sys) = machine
        && create_user.is_none()
    {
        let who = invoker();
        let suggested = Some(who.as_str()).filter(|u| *u != "root");
        let chosen = crate::service::choose_account(
            sys,
            paths,
            cfg.machine.user.as_deref(),
            suggested,
            &who,
            input,
            out,
        )?;
        account_chosen(paths, chosen, out, steps).await?;
    }

    // Where the keys go, before pairing makes one. Where they may not be in
    // the keyring (the installed node on Windows, an old Landlock), setup
    // does not ask; it says why.
    let now = read_config(paths).await?.0.machine.secret_storage;
    let storage = if let Some(n) = no_keyring {
        let _ = writeln!(out, "Warning: {}.", n.why());
        SecretStorage::File
    } else {
        if crate::secrets::landlock(paths) == crate::secrets::Landlock::Unknown {
            let _ = writeln!(out, "{LANDLOCK_UNKNOWN}");
        }
        let answer = ask(
            input,
            out,
            &format!(
                "Where the node keeps its keys: file (files only the node's user can read) or keyring (the system keyring) [{}]: ",
                enum_str(&now)
            ),
        )?;
        match answer.as_str() {
            "" => now,
            a => parse_enum::<SecretStorage>(a, "file or keyring")?,
        }
    };
    if storage != now {
        if storage == SecretStorage::Keyring {
            let me = crate::keyring_setup::me()?;
            crate::keyring_setup::ensure(keyring, &me, Some(input), out)?;
            after_keyring_answers(paths, machine, out).await?;
        }
        let cfg = edit(paths, |c| {
            c.machine.secret_storage = storage;
            Ok(())
        })
        .await?;
        let step = format!("the node's keys are in {} now", storage_place(storage));
        let _ = writeln!(out, "{step}");
        steps.push(step);
        if storage == SecretStorage::Keyring {
            tell_folder_commands(paths, &cfg, out).await;
        }
    }

    let link = ask(
        input,
        out,
        "Pairing link from the center's web UI (Enter to skip): ",
    )?;
    let mut center = None;
    if !link.is_empty() {
        let link = PairLink::parse(&link)?;
        let _ = writeln!(out, "{}", crate::pair::preview(&link, None));
        if confirm(input, out)? {
            let e = crate::pair::pair(paths, &link, None).await?;
            let _ = writeln!(out, "paired with {} as {}", e.url, e.name);
            steps.push(format!("paired with {} as {}", e.url, e.name));
            center = Some(e.name);
        } else {
            let _ = writeln!(out, "not paired");
        }
    }
    let center = match center {
        Some(c) => c,
        None => match read_config(paths).await?.0.centers.as_slice() {
            [one] => one.name.clone(),
            [] => {
                let _ = writeln!(
                    out,
                    "No center is paired; `nerve-node center add '<link>'` pairs one."
                );
                return Ok(());
            }
            _ => {
                let _ = writeln!(
                    out,
                    "Several centers are paired; `nerve-node mode set <mode> --center <name>` sets the mode of each."
                );
                return Ok(());
            }
        },
    };

    let (cfg, _) = read_config(paths).await?;
    let entry = cfg
        .center(&center)
        .ok_or_else(|| format!("no center named {center}"))?;
    let now = entry.policy.mode_at(crate::now_ms()).as_str().to_string();
    let mode = ask(
        input,
        out,
        &format!(
            "Mode for {center}: allowlist (only what allow rules name), folder (the folders you give it) or user (all you may do) [{now}]: "
        ),
    )?;
    let mode = if mode.is_empty() { now.clone() } else { mode };
    let which = CenterArg {
        center: Some(center.clone()),
    };
    if mode != now {
        set_mode(paths, &mode, None, &which, out).await?;
        steps.push(format!("{center}: mode {mode}"));
    }
    if mode == "folder" {
        let folder = ask(
            input,
            out,
            &format!("A folder {center} may use (Enter to skip): "),
        )?;
        if !folder.is_empty() {
            let rights = ask(
                input,
                out,
                "What it may do there: +r reads, +w writes, +x runs commands, as in `+r +x` [+r]: ",
            )?;
            let rights: Vec<String> = if rights.is_empty() {
                vec!["+r".into()]
            } else {
                rights.split_whitespace().map(str::to_string).collect()
            };
            add_folder(paths, Path::new(&folder), &rights, &which, out).await?;
            steps.push(format!("{center}: folder {folder} {}", rights.join(" ")));
        }
    }
    let _ = writeln!(
        out,
        "Done. `nerve-node rule add allow '<command>'` allows one command; `nerve-node --help` lists the rest."
    );
    Ok(())
}

/// Setup's warning where the kernel's Landlock ABI cannot be read: below
/// ABI 9 the keys would not be allowed in the keyring
/// (crate::secrets::keyring_old_landlock), and here nobody can tell.
const LANDLOCK_UNKNOWN: &str = "Warning: the Landlock ABI of this kernel cannot be read (Landlock is missing or off), so setup cannot tell whether the node's keys may be in the system keyring. On a kernel below Landlock ABI 9 a folder mode command cannot run programs from its folders while the keys are in the keyring: the sandbox cannot grant the keyring's access and execute together. Unless you know this kernel has ABI 9 or later, keep the keys in files (file).";

/// How setup names where the keys are.
fn storage_place(s: SecretStorage) -> &'static str {
    match s {
        SecretStorage::File => "files",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// Asks one question; the answer without the line break and the spaces
/// around it. The end of the input is an error, so setup never loops on it.
pub(crate) fn ask(
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    question: &str,
) -> Result<String, String> {
    let _ = write!(out, "{question}");
    let _ = out.flush();
    let mut line = String::new();
    if input.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        let _ = writeln!(out);
        return Err("stopped: the input ended before every question was answered".into());
    }
    Ok(line.trim().to_string())
}

/// `mode set`, and the mode step of `setup`.
async fn set_mode(
    paths: &NodePaths,
    mode: &str,
    for_hours: Option<u64>,
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    let m = match mode {
        "allowlist" => Mode::Allowlist,
        "folder" => Mode::Folder,
        "user" => Mode::User,
        other => {
            return Err(format!("unknown mode {other} (allowlist, folder or user)"));
        }
    };
    if for_hours.is_some() && m == Mode::Allowlist {
        return Err("--for only goes with folder or user".into());
    }
    // No --for: no limit, and an old one is cleared. The end is a
    // millisecond count that the config file (a TOML integer) holds.
    let until = for_hours
        .map(|h| {
            if h == 0 {
                return Err("--for must be at least 1 hour".to_string());
            }
            h.checked_mul(3_600_000)
                .and_then(|ms| crate::now_ms().checked_add(ms))
                .filter(|t| i64::try_from(*t).is_ok())
                .ok_or_else(|| "--for is too large".to_string())
        })
        .transpose()?;
    let name = edit_center(paths, center, |e| {
        e.policy.mode = m;
        e.policy.until = until;
        Ok(())
    })
    .await?;
    w(out, format!("{name}: mode {}", m.as_str()));
    Ok(())
}

/// `folder add`, and the folder step of `setup`.
async fn add_folder(
    paths: &NodePaths,
    path: &Path,
    rights: &[String],
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    // The rights are checked before the folder is looked at.
    let access = FolderChange::new_rights(rights)?;
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let given = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let given = nerve_policy::paths::normal_folder(&given.display().to_string())?;
    // A running node judges the path as the account the commands run as,
    // which this command may not be (the installed node's CLI runs as the
    // node's own user): it follows the links on the path a link at a time,
    // refuses one a command may have put inside a `w` folder, and stores and
    // records the real place, all in one step.
    #[cfg(unix)]
    let asked = {
        let params = json!({"center": name, "path": given, "access": access.to_string()});
        match nerve_transport::ctl::call(&paths.ctl_socket(), "folder.add", params).await {
            Ok(v) => Some((
                v["stored"].as_str().unwrap_or(&given).to_string(),
                v["recorded"] == true,
                v["mode"].as_str().map(str::to_string),
            )),
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
            Err(e) => return Err(e),
        }
    };
    #[cfg(not(unix))]
    let asked: Option<(String, bool, Option<String>)> = None;
    let (stored, recorded, mode) = match asked {
        Some(a) => a,
        None => {
            // No node to ask (on Windows the node's pipe takes the change but
            // not the judging): judge the path here, as this process sees it.
            let settled = crate::exec::settle(&cfg, &crate::paths::home_dir(), Path::new(&given));
            let (stored, recorded) = match settled {
                crate::exec::Settled::Refused(why) => {
                    return Err(crate::daemon::refusal(&given, &why));
                }
                crate::exec::Settled::At(place) => (place.display().to_string(), true),
                crate::exec::Settled::Unknown => (given.clone(), false),
            };
            let change = FolderChange::Add {
                path: stored.clone(),
                access,
                recorded,
            };
            let a = change_folder(paths, center, &change).await?;
            (stored, recorded, Some(a.mode.as_str().to_string()))
        }
    };
    w(
        out,
        format!("{name}: folder {stored} {}", access.to_chmod()),
    );
    if !recorded {
        w(
            out,
            format!(
                "note: {stored} is stored as given and not recorded at its real place, since this command cannot tell where its path leads (the installed node's CLI may not look into the account's home) and no running node could: a link that replaces the folder later is followed once no `w` folder shows it, see modes.md \"A folder keeps the place you added\"; start the node and add the folder again"
            ),
        );
    } else if !same_folder(&stored, &given) {
        w(
            out,
            format!("note: {given} leads to {stored}; the folder is stored there"),
        );
    }
    if let Some(mode) = mode.filter(|m| m != Mode::Folder.as_str()) {
        w(
            out,
            format!(
                "note: folders count in folder mode; {name} is in {mode} mode (`nerve-node mode set folder`)"
            ),
        );
    }
    Ok(())
}

/// Whether two folder paths name one place.
fn same_folder(a: &str, b: &str) -> bool {
    use nerve_policy::paths::within;
    within(Path::new(a), Path::new(b)) && within(Path::new(b), Path::new(a))
}

/// `folder set` and `folder rm`: the change `make` builds for the stored
/// folder `path` means ([`stored_folder`]), made as [`change_folder`] makes
/// it. The folder is looked up on the config as the CLI reads it, then named
/// by its stored path, so that a change to the file in between ends in "not
/// a folder of this center" and never in another folder.
async fn change_stored_folder(
    paths: &NodePaths,
    center: &CenterArg,
    path: &Path,
    make: impl FnOnce(String) -> FolderChange,
) -> Result<Applied, String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let folders = &cfg.center(&name).expect("picked above").policy.folders;
    let at = stored_folder(folders, path)?;
    change_folder(paths, center, &make(at)).await
}

/// Changes a center's folders. On Windows a running node takes the change
/// over its control pipe and makes it itself, folder grants included
/// (crate::pipe); a node that does not run, and the other platforms, take
/// it as every other change ([`edit`]).
async fn change_folder(
    paths: &NodePaths,
    center: &CenterArg,
    change: &FolderChange,
) -> Result<Applied, String> {
    #[cfg(windows)]
    match crate::pipe::call(
        paths,
        change.method(),
        change.params(center.center.as_deref()),
    )
    .await
    {
        Ok(v) => {
            return serde_json::from_value(v)
                .map_err(|e| format!("the node's answer is not understood: {e}"));
        }
        // A node that runs holds the keys' lock.
        Err(e)
            if crate::pipe::file_instead(&e, || {
                !matches!(crate::secrets::KeysLock::try_take(paths), Ok(Some(_)))
            }) => {}
        Err(e) => return Err(e),
    }
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let applied = std::cell::RefCell::new(None);
    edit(paths, |c| {
        *applied.borrow_mut() = Some(crate::folder_change::apply_to(c, Some(&name), change)?);
        Ok(())
    })
    .await?;
    Ok(applied.into_inner().expect("applied when edit succeeds"))
}

/// `nerve-node sudo on|off|status`. The password lives in the running
/// daemon only, so `on` needs one; `off` without a daemon edits the file.
/// Windows has no control socket: there the password is kept with DPAPI
/// for the service (crate::winsudo).
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
    #[cfg(windows)]
    {
        use crate::win_host::WinHost;
        match c {
            SudoCmd::On => {
                let installed = crate::service::is_service_node(paths);
                crate::winsudo::on(paths, &WinHost, installed, out).await
            }
            SudoCmd::Off => crate::winsudo::off(paths, &WinHost, out).await,
            SudoCmd::Status => {
                let on = crate::winsudo::status(paths)?;
                w(out, if on { "sudo: on" } else { "sudo: off" });
                Ok(())
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (paths, out, w);
        match c {
            SudoCmd::Status => Ok(()),
            _ => Err("the sudo switch works on Linux and Windows only".into()),
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

fn confirm(input: &mut dyn BufRead, out: &mut dyn Write) -> Result<bool, String> {
    let _ = write!(out, "Pair with this center? [y/N] ");
    let _ = out.flush();
    let mut line = String::new();
    input.read_line(&mut line).map_err(|e| e.to_string())?;
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

/// The path of the stored folder `folder set` and `folder rm` mean by `path`,
/// found before the path is resolved, which fails where a dangling link or a
/// loop of links stands now. In this order: the folder the path is spelled as
/// (made absolute and tidy, no link followed); the folder its resolution lands
/// at, a link at a time (`folder add` stored the real place of a path through
/// a link of the owner's, and a link may have replaced that place since); the
/// folder at the real place the path leads to.
fn stored_folder(folders: &[Folder], path: &Path) -> Result<String, String> {
    use nerve_policy::paths::within;
    let same = |a: &Path, b: &Path| within(a, b) && within(b, a);
    let stored = |p: &Path| {
        folders
            .iter()
            .find(|f| same(p, Path::new(&f.path)))
            .map(|f| f.path.clone())
    };
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let spelled = nerve_policy::paths::normal_folder(&abs.display().to_string()).ok();
    if let Some(f) = spelled.and_then(|s| stored(Path::new(&s))) {
        return Ok(f);
    }
    if let Some(f) = crate::exec::lands_at(&abs, |p| stored(p).is_some()).and_then(|p| stored(&p)) {
        return Ok(f);
    }
    let real = resolve_folder(path)?;
    stored(Path::new(&real)).ok_or_else(|| crate::folder_change::not_a_folder(&real, folders))
}

/// Folders are stored resolved (symlinks followed), the way the policy
/// compares them.
fn resolve_folder(p: &Path) -> Result<String, String> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    match nerve_policy::paths::resolve(&abs) {
        Ok(real) => Ok(real.display().to_string()),
        // On the installed node this command runs as `nerve`, which may not
        // look into the account's home; the folder is kept as given, and the
        // node looks at it as the account when a call comes.
        Err(nerve_policy::paths::PathError::Io(e))
            if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            nerve_policy::paths::normal_folder(&abs.display().to_string())
        }
        Err(e) => Err(e.to_string()),
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
    if v["kind"] == "node" {
        let steps: Vec<String> = v["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_string))
            .collect();
        let mut line = format!("{}  {}: {}", s("ts"), s("event"), steps.join("; "));
        if let Some(e) = v["error"].as_str() {
            line.push_str(&format!(" (failed: {e})"));
        }
        return line;
    }
    if v["kind"] == "relay" {
        return format!(
            "{}  relay  {} from {} to center {}: {} after {} ({} bytes up, {} down)",
            s("ts"),
            s("node"),
            s("from"),
            s("center"),
            s("reason"),
            nerve_transport::log::span(Duration::from_millis(
                v["end"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_sub(v["start"].as_u64().unwrap_or(0))
            )),
            s("up"),
            s("down"),
        );
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
    let line = format!(
        "{}  {}  {}.{}  {}  {}",
        s("ts"),
        s("center"),
        s("cap"),
        s("action"),
        s("target"),
        s("decision")
    );
    match v["reason"].as_str() {
        Some(reason) => format!("{line}: {reason}"),
        None => line,
    }
}

/// `audit`: the log through [`AuditLog::lines`], the rotated file first.
/// `--follow` looks again every 500 ms and shows the lines after the last one
/// it showed, wherever that line is now: in `audit.jsonl.1` after a rotation,
/// so the old file is finished before the new one, or further up after the
/// log dropped old refusals.
async fn audit(
    paths: &NodePaths,
    follow: bool,
    denied: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    let log = AuditLog::new(paths.audit_log());
    let mut shown = Shown::default();
    let mut stamp = None;
    loop {
        // Both files as they are now; the same as at the last look is
        // nothing new, and is not read again.
        let now = [log.path().to_path_buf(), log.old_path()].map(|p| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (m.len(), m.modified().ok()))
        });
        if stamp.as_ref() == Some(&now) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        }
        stamp = Some(now);
        let lines = log
            .lines()
            .map_err(|e| format!("{}: {e}", log.path().display()))?;
        for line in &lines[shown.next(&lines)..] {
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
        shown.saw(&lines);
        if !follow {
            return Ok(());
        }
        let _ = out.flush();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Where `audit --follow` is: the last line it looked at, how many copies
/// of it ended what it saw, and its time.
#[derive(Default)]
struct Shown {
    last: Option<(String, usize, u64)>,
}

impl Shown {
    /// The index in `lines` of the first line not looked at yet.
    fn next(&self, lines: &[String]) -> usize {
        let Some((last, copies, ts)) = &self.last else {
            return 0;
        };
        match lines.iter().rposition(|l| l == last) {
            Some(end) => {
                let run = lines[..=end]
                    .iter()
                    .rev()
                    .take_while(|l| *l == last)
                    .count();
                // The copies seen began the run; the rest are new.
                if run > *copies {
                    end + 1 - run + copies
                } else {
                    end + 1
                }
            }
            // The log dropped that line meanwhile (a refusal, or two
            // rotations): what came after it is newer.
            None => lines
                .iter()
                .position(|l| line_ts(l) > *ts)
                .unwrap_or(lines.len()),
        }
    }

    fn saw(&mut self, lines: &[String]) {
        if let Some(last) = lines.last() {
            let copies = lines.iter().rev().take_while(|l| *l == last).count();
            self.last = Some((last.clone(), copies, line_ts(last)));
        }
    }
}

fn line_ts(line: &str) -> u64 {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v["ts"].as_u64())
        .unwrap_or(0)
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
    let before = std::cell::Cell::new(SecretStorage::File);
    let cfg = edit(paths, |cfg| {
        before.set(cfg.machine.secret_storage);
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
    if before.get() != SecretStorage::Keyring
        && cfg.machine.secret_storage == SecretStorage::Keyring
    {
        tell_folder_commands(paths, &cfg, out).await;
    }
    Ok(())
}

/// Says, once the keys went into the keyring, that folder mode now runs no
/// command where Landlock cannot keep a command off the session bus
/// (crate::daemon::KEYRING_NOT_CONFINED). The running node knows; without one,
/// the kernel here and the account `cfg` runs commands as tell.
async fn tell_folder_commands(paths: &NodePaths, cfg: &NodeConfig, out: &mut dyn Write) {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(v) => {
            if v["folder_commands_off"] == crate::daemon::KEYRING_NOT_CONFINED {
                let _ = writeln!(out, "{}", folder_commands_off());
            }
            return;
        }
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
        // The node that runs knows, and was not asked.
        Err(e) => {
            let _ = writeln!(
                out,
                "the running node was not asked whether folder mode still runs commands ({e}); `nerve-node status` shows it"
            );
            return;
        }
    }
    if keyring_turns_commands_off(nerve_sandbox::Confinement::detect(), || {
        node_command_account(paths, cfg)
    }) {
        let _ = writeln!(out, "{}", folder_commands_off());
    }
}

/// The account the node at `paths` runs commands as with `cfg`, looked up as
/// that node does (crate::account::for_commands), for a CLI that finds no
/// node to ask: the installed node runs as its own user and can switch, a
/// node run by hand as this CLI's user. `None` for the node's own user, and
/// where no command runs.
fn node_command_account(paths: &NodePaths, cfg: &NodeConfig) -> Option<crate::service::Account> {
    let me = nerve_transport::net::euid();
    let service = crate::service::is_service_node(paths);
    let own = match service {
        true => crate::account::lookup(crate::service::USER)
            .ok()
            .flatten()
            .map_or(me, |a| a.uid),
        false => me,
    };
    crate::account::for_commands(
        cfg.machine.user.as_deref(),
        own,
        service,
        service || crate::account::can_switch(),
        crate::account::lookup,
    )
    .ok()
    .flatten()
}

fn folder_commands_off() -> String {
    format!(
        "folder mode runs no command: {}",
        crate::daemon::KEYRING_NOT_CONFINED
    )
}

/// Whether, with the keys in the keyring, `c` leaves folder mode's commands
/// a way to the session bus: Landlock without ABI 9, for commands that run
/// as the node's own user or root (crate::daemon::keys_kept_from_commands).
/// `account` is asked only on such a kernel.
fn keyring_turns_commands_off(
    c: nerve_sandbox::Confinement,
    account: impl FnOnce() -> Option<crate::service::Account>,
) -> bool {
    c.available()
        && !crate::daemon::keys_kept_from_commands(
            SecretStorage::Keyring,
            c.keeps_sockets(),
            account,
        )
}

/// `proxy set|rm|ls`. The header values, and a user name and password given
/// in an `http://` URL, go into the system keyring ([`crate::secrets`]);
/// `node.toml` keeps the URL without them and the header names. The
/// installed node on Windows refuses them, as the service does not read the
/// keyring of the account that runs this. The password of an `https://`
/// proxy, a relay token, is kept with the node's own keys instead, where
/// `machine.secret_storage` says, and its user name in `connection.login`.
/// Nothing here prints, logs or audits a value.
async fn proxy_cmd(paths: &NodePaths, c: ProxyCmd, out: &mut dyn Write) -> Result<(), String> {
    match c {
        ProxyCmd::Set { url, pin, headers } => {
            let mut hs: Vec<(String, String)> = Vec::new();
            for (i, h) in headers.iter().enumerate() {
                // Not echoed: without its colon the whole line may be the secret.
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("--header number {} is not `Name: value`", i + 1))?;
                let k = k.trim().to_string();
                if hs.iter().any(|(n, _)| n.eq_ignore_ascii_case(&k)) {
                    return Err(format!("the header {k} is given twice"));
                }
                hs.push((k, v.trim().to_string()));
            }
            let (url, login) = split_credentials(&url)?;
            let https = url.to_ascii_lowercase().starts_with("https://");
            let (now, _) = read_config(paths).await?;
            let storage = now.machine.secret_storage;
            // An https:// proxy's login is the node's own secret.
            let (login, kept) = match login {
                Some((user, password)) if https => {
                    if !nerve_policy::config::valid_login(&user) {
                        return Err("the proxy URL has an empty or bad user name".into());
                    }
                    if hs
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case(PROXY_AUTHORIZATION))
                    {
                        return Err(format!(
                            "give the proxy's user name and password either in the URL or as a {PROXY_AUTHORIZATION} header, not both"
                        ));
                    }
                    (None, Some((user, password)))
                }
                other => (other, None),
            };
            if let Some((user, password)) = login {
                if hs
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(PROXY_AUTHORIZATION))
                {
                    return Err(format!(
                        "give the proxy's user name and password either in the URL or as a {PROXY_AUTHORIZATION} header, not both"
                    ));
                }
                use base64::Engine;
                let basic =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
                hs.push((PROXY_AUTHORIZATION.into(), format!("Basic {basic}")));
            }
            nerve_transport::net::Proxy::parse(&url, hs.clone())?.pinned(pin.clone())?;
            let names: Vec<String> = hs.iter().map(|(k, _)| k.clone()).collect();
            // The relay token goes where the node's keys are; where that is
            // a keyring that does not answer, this fails as for any key of
            // the node, and nothing is changed.
            match &kept {
                Some((_, password)) => crate::secrets::store_proxy_login(paths, storage, password)?,
                None if now.connection.login.is_some() => {
                    let _ = crate::secrets::remove_proxy_login(paths, storage);
                }
                None => {}
            }
            // The keyring first: when it cannot take the values, node.toml
            // stays as it was rather than name headers nobody can send. A
            // proxy without headers leaves the keyring alone, unless the one
            // before had some: their entry would only linger.
            if !hs.is_empty() {
                crate::secrets::store_proxy_headers(paths, &hs)?;
            } else if !now.connection.headers.is_empty() {
                let _ = crate::secrets::remove_proxy_headers(paths);
            }
            let user = kept.as_ref().map(|(u, _)| u.clone());
            edit(paths, |c| {
                c.connection.proxy = Some(url.clone());
                c.connection.pin = pin.clone();
                c.connection.login = user.clone();
                c.connection.headers = names.clone();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "proxy {url}");
            if let Some(p) = &pin {
                let _ = writeln!(out, "pin {p}");
            }
            if let Some(u) = &user {
                let _ = writeln!(
                    out,
                    "login {u} (its password is kept with the node's keys: {})",
                    keys_place(storage)
                );
            }
            for n in &names {
                let _ = writeln!(out, "header {n} (its value is in the system keyring)");
            }
            Ok(())
        }
        ProxyCmd::Rm => {
            let (cfg, _) = read_config(paths).await?;
            edit(paths, |c| {
                c.connection.proxy = None;
                c.connection.pin = None;
                c.connection.login = None;
                c.connection.headers.clear();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "no proxy");
            if cfg.connection.login.is_some()
                && let Err(e) =
                    crate::secrets::remove_proxy_login(paths, cfg.machine.secret_storage)
            {
                return Err(format!("the proxy is removed, but {e}"));
            }
            // A proxy without headers has no entry; where there is no
            // keyring, asking for one would only fail.
            if cfg.connection.headers.is_empty() {
                return Ok(());
            }
            match crate::secrets::remove_proxy_headers(paths) {
                Ok(true) => {
                    let _ = writeln!(out, "deleted the header values from the system keyring");
                }
                Ok(false) => {}
                Err(e) => return Err(format!("the proxy is removed, but {e}")),
            }
            Ok(())
        }
        ProxyCmd::Ls => {
            let (cfg, _) = read_config(paths).await?;
            let Some(url) = &cfg.connection.proxy else {
                let _ = writeln!(out, "no proxy");
                return Ok(());
            };
            let _ = writeln!(out, "proxy {url}");
            if let Some(p) = &cfg.connection.pin {
                let _ = writeln!(out, "pin {p}");
            }
            if let Some(u) = &cfg.connection.login {
                let storage = cfg.machine.secret_storage;
                match crate::secrets::proxy_login(paths, storage) {
                    Ok(_) => {
                        let _ = writeln!(
                            out,
                            "login {u} (its password is kept with the node's keys: {})",
                            keys_place(storage)
                        );
                    }
                    Err(e) => {
                        let _ = writeln!(out, "login {u}");
                        let _ = writeln!(out, "the link cannot use this proxy: {e}");
                    }
                }
            }
            // The keyring is asked whether it holds every value; only the
            // names are shown.
            let names = &cfg.connection.headers;
            match crate::secrets::proxy_headers(paths, names) {
                Ok(_) => {
                    for n in names {
                        let _ = writeln!(out, "header {n} (its value is in the system keyring)");
                    }
                }
                Err(e) => {
                    for n in names {
                        let _ = writeln!(out, "header {n}");
                    }
                    let _ = writeln!(out, "the link cannot use this proxy: {e}");
                }
            }
            Ok(())
        }
    }
}

/// `relay set|off|add|token|set-centers|set-limits|rm|ls` (crate::relay).
/// A token is shown once, by `add` or `token`; `node.toml` keeps only its
/// hash. Each change says when it is in force ([`relay_in_force`]).
async fn relay_cmd(paths: &NodePaths, c: RelayCmd, out: &mut dyn Write) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    match c {
        RelayCmd::Set {
            address,
            max_links,
            max_links_per_node,
            max_opens_per_minute,
        } => {
            if address.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "relay.listen {address:?}: an address and a port, like 0.0.0.0:7490 or [::]:7490"
                ));
            }
            let (now, _) = read_config(paths).await?;
            let (pin, made) = relay_pin(paths, &now, Some(&address))?;
            let cfg = edit(paths, |c| {
                c.relay.listen = Some(address.clone());
                c.relay.pin = Some(pin.clone());
                if let Some(n) = max_links {
                    c.relay.max_links = n;
                }
                if let Some(n) = max_links_per_node {
                    c.relay.max_links_per_node = n;
                }
                if let Some(n) = max_opens_per_minute {
                    c.relay.max_opens_per_minute = n;
                }
                Ok(())
            })
            .await?;
            w(
                out,
                format!(
                    "relay on {address}: at most {} tunnels, {} per node, {} opened a minute per node",
                    cfg.relay.max_links,
                    cfg.relay.max_links_per_node,
                    cfg.relay.max_opens_per_minute
                ),
            );
            w(out, format!("its TLS certificate has the pin {pin}"));
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    "that is a new certificate: the relayed nodes need the new pin in `proxy set --pin`".into(),
                );
            }
            if cfg.relay.nodes.is_empty() {
                w(
                    out,
                    "no node may use it yet: `nerve-node relay add <name>` makes a token".into(),
                );
            }
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::Off => {
            edit(paths, |c| {
                c.relay.listen = None;
                Ok(())
            })
            .await?;
            w(out, "relay off".into());
            relay_in_force(
                paths,
                out,
                Some("the relay stops listening, and every tunnel ends"),
            )
            .await;
            Ok(())
        }
        RelayCmd::Add { name, centers } => {
            if !nerve_proto::valid_node_name(&name) {
                return Err(format!(
                    "{name:?} is not a relay node name: 1 to 32 characters of a-z, 0-9 and -"
                ));
            }
            let (now, _) = read_config(paths).await?;
            relay_centers(&now, &centers)?;
            let (pin, made) = relay_pin(paths, &now, now.relay.listen.as_deref())?;
            let (token, hash) = crate::relay::new_token();
            let cfg = edit(paths, |c| {
                if c.relay.node(&name).is_some() {
                    return Err(format!(
                        "the relay knows a node {name} already; `nerve-node relay rm {name}` takes its token away first"
                    ));
                }
                relay_centers(c, &centers)?;
                c.relay.pin = Some(pin.clone());
                c.relay.nodes.push(nerve_policy::config::RelayNode {
                    name: name.clone(),
                    token_sha256: hash.clone(),
                    centers: centers.clone(),
                    max_links: None,
                    max_opens_per_minute: None,
                });
                Ok(())
            })
            .await?;
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    format!(
                        "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {pin}): the relayed nodes need the new pin in `proxy set --pin`"
                    ),
                );
            }
            let at = relay_address(cfg.relay.listen.as_deref());
            w(
                out,
                format!("relay node {name} added; its token, shown only now:"),
            );
            w(out, format!("  {token}"));
            w(out, format!("it may reach {}", reach_of(&centers)));
            w(out, format!("on {name}, run:"));
            w(
                out,
                format!("  nerve-node proxy set 'https://{name}:{token}@{at}' --pin {pin}"),
            );
            if cfg.relay.listen.is_none() {
                w(
                    out,
                    "the relay is off: `nerve-node relay set <address>` turns it on".into(),
                );
            }
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::SetLimits {
            name,
            max_links,
            max_opens_per_minute,
        } => {
            let cfg = edit(paths, |c| {
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| format!("the relay knows no node {name}"))?;
                // As `relay set`: a limit not given stays; no flag at all
                // gives the node the relay's limits again.
                if max_links.is_none() && max_opens_per_minute.is_none() {
                    node.max_links = None;
                    node.max_opens_per_minute = None;
                }
                if let Some(n) = max_links {
                    node.max_links = Some(n);
                }
                if let Some(n) = max_opens_per_minute {
                    node.max_opens_per_minute = Some(n);
                }
                Ok(())
            })
            .await?;
            let node = cfg.relay.node(&name).expect("set above");
            let links = node.links(&cfg.relay);
            let mut line = format!(
                "relay node {name}: at most {links} tunnels at once, {} opened a minute",
                node.opens(&cfg.relay)
            );
            if cfg.relay.max_links < links {
                line.push_str(&format!(
                    " (the relay's {} tunnels in all bound it; `relay set <address> --max-links N` raises that)",
                    cfg.relay.max_links
                ));
            }
            w(out, line);
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::Token { name } => {
            let (now, _) = read_config(paths).await?;
            let (pin, made) = relay_pin(paths, &now, now.relay.listen.as_deref())?;
            let (token, hash) = crate::relay::new_token();
            let cfg = edit(paths, |c| {
                c.relay.pin = Some(pin.clone());
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| {
                        format!("the relay knows no node {name}; `relay add {name}` makes one")
                    })?;
                node.token_sha256 = hash.clone();
                Ok(())
            })
            .await?;
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    format!(
                        "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {pin}): the relayed nodes need the new pin in `proxy set --pin`"
                    ),
                );
            }
            let node = cfg.relay.node(&name).expect("set above");
            let at = relay_address(cfg.relay.listen.as_deref());
            // Whether the old token is dead is the running node's to say
            // (`relay_in_force`): on Windows it takes the change at its next
            // start.
            w(
                out,
                format!("relay node {name} has a new token, shown only now:"),
            );
            w(out, format!("  {token}"));
            w(out, format!("it may reach {}", reach_of(&node.centers)));
            w(out, format!("on {name}, run:"));
            w(
                out,
                format!("  nerve-node proxy set 'https://{name}:{token}@{at}' --pin {pin}"),
            );
            if cfg.relay.listen.is_none() {
                w(
                    out,
                    "the relay is off: `nerve-node relay set <address>` turns it on".into(),
                );
            }
            relay_in_force(
                paths,
                out,
                Some("the old token no longer works, and its tunnels end"),
            )
            .await;
            Ok(())
        }
        RelayCmd::SetCenters { name, centers } => {
            edit(paths, |c| {
                relay_centers(c, &centers)?;
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| format!("the relay knows no node {name}"))?;
                node.centers = centers.clone();
                Ok(())
            })
            .await?;
            w(
                out,
                format!("relay node {name} may reach {}", reach_of(&centers)),
            );
            relay_in_force(paths, out, Some("its tunnels to other centers end")).await;
            Ok(())
        }
        RelayCmd::Rm { name } => {
            edit(paths, |c| {
                let before = c.relay.nodes.len();
                c.relay.nodes.retain(|n| n.name != name);
                if c.relay.nodes.len() == before {
                    return Err(format!("the relay knows no node {name}"));
                }
                Ok(())
            })
            .await?;
            w(out, format!("relay node {name} removed"));
            relay_in_force(
                paths,
                out,
                Some("its token no longer works, and its tunnels end"),
            )
            .await;
            Ok(())
        }
        RelayCmd::Ls => {
            let (cfg, _) = read_config(paths).await?;
            let r = &cfg.relay;
            #[cfg(unix)]
            let live =
                match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
                    Ok(v) => Some(v["relay"].clone()),
                    Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
                    Err(e) => return Err(e),
                };
            // Windows: the control pipe answers `status` too. Only a pipe
            // that is not there means no node runs; any other error is
            // said, not taken for "no tunnel".
            #[cfg(windows)]
            let live = match crate::pipe::call(paths, "status", json!({})).await {
                Ok(v) => Some(v["relay"].clone()),
                Err(e) if e == nerve_transport::ctl::NOT_RUNNING => None,
                Err(e) => return Err(format!("cannot ask the running node: {e}")),
            };
            #[cfg(not(any(unix, windows)))]
            let live: Option<Value> = None;
            match (&r.listen, &live) {
                (None, _) => w(out, "relay off".into()),
                (Some(l), Some(v)) => w(
                    out,
                    format!(
                        "relay on {l}: {}",
                        v["status"].as_str().unwrap_or("not known")
                    ),
                ),
                (Some(l), None) => w(out, format!("relay on {l}")),
            }
            w(
                out,
                format!(
                    "at most {} tunnels, {} per node, {} opened a minute per node",
                    r.max_links, r.max_links_per_node, r.max_opens_per_minute
                ),
            );
            if let Some(pin) = &r.pin {
                w(out, format!("pin {pin}"));
            }
            if r.nodes.is_empty() {
                w(out, "no node may use it".into());
            }
            for n in &r.nodes {
                let mut line = format!("node {}: {}", n.name, reach_of(&n.centers));
                if n.max_links.is_some() || n.max_opens_per_minute.is_some() {
                    line.push_str(&format!(
                        "; its own limits: {} tunnels at once, {} opened a minute",
                        n.links(r),
                        n.opens(r)
                    ));
                }
                w(out, line);
            }
            match live {
                Some(v) => {
                    let now = crate::now_ms();
                    for t in v["tunnels"].as_array().into_iter().flatten() {
                        let since = t["since_ms"].as_u64().unwrap_or(now);
                        w(
                            out,
                            format!(
                                "tunnel {} from {} to center {} for {}",
                                t["node"].as_str().unwrap_or_default(),
                                t["from"].as_str().unwrap_or_default(),
                                t["center"].as_str().unwrap_or_default(),
                                nerve_transport::log::span(std::time::Duration::from_millis(
                                    now.saturating_sub(since)
                                )),
                            ),
                        );
                    }
                }
                None if r.listen.is_some() => {
                    w(out, "no node runs here, so no tunnel is open".into())
                }
                None => {}
            }
            Ok(())
        }
    }
}

/// Says when a relay change is in force. A running node that took it
/// applies it at once: `now` says what that does ("its tunnels end"), for
/// the changes that take something away. On Windows the CLI writes the file
/// and the running node reads it at its next start, so until then that node
/// goes on by its old relay settings, for new tunnels as well as open ones:
/// a removed or replaced token still opens tunnels, and a new one is
/// refused. With no node running there is nothing to say.
async fn relay_in_force(paths: &NodePaths, out: &mut dyn Write, now: Option<&str>) {
    if daemon_answers(paths, false).await {
        if let Some(what) = now {
            let _ = writeln!(out, "{what} now");
        }
    } else if cfg!(windows) {
        let _ = writeln!(out, "{RELAY_AT_NEXT_START}");
    }
}

/// [`relay_in_force`] on Windows, where a running node has not taken the
/// change.
const RELAY_AT_NEXT_START: &str = "a running node takes this change only at its next start, and until then works by its old relay settings: a removed or replaced token still opens new tunnels, the tunnels it carries stay, and a new token or node is refused. Restart it (`Restart-Service nerve-node` for the installed node) to apply the change now";

/// Refuses a `--center` list that names a center this node is not paired
/// with, or one twice.
fn relay_centers(cfg: &NodeConfig, centers: &[String]) -> Result<(), String> {
    for (i, c) in centers.iter().enumerate() {
        let Some(entry) = cfg.center(c) else {
            return Err(format!("no center named {c} is paired here"));
        };
        if centers[..i].contains(c) {
            return Err(format!("--center {c} is given twice"));
        }
        // A tunnel reaches a host and port, not a center: a center there
        // that is not on the list would be reached as well.
        let at = |url: &str| {
            nerve_proto::link::CenterUrl::parse(url)
                .ok()
                .map(|u| (u.host, u.port))
        };
        let same = |a: Option<(String, u16)>, b: Option<(String, u16)>| match (a, b) {
            (Some((ha, pa)), Some((hb, pb))) => pa == pb && crate::relay::same_host(&ha, &hb),
            _ => false,
        };
        if let Some(other) = cfg.centers.iter().find(|o| {
            o.name != entry.name && !centers.contains(&o.name) && same(at(&o.url), at(&entry.url))
        }) {
            return Err(format!(
                "the centers {c} and {} share one host and port, and a tunnel reaches the host and port, so the relay cannot keep them apart: name both or neither",
                other.name
            ));
        }
    }
    Ok(())
}

/// What a relay node's center list allows, in words.
fn reach_of(centers: &[String]) -> String {
    if centers.is_empty() {
        "every https center of this node".into()
    } else {
        format!("the centers {}", centers.join(", "))
    }
}

/// The pin of the relay's TLS certificate, and whether it was made now: one
/// is made when the relay has none, or its key is gone or is not the one
/// `relay.pin` names. The key goes where the node keeps its keys
/// (`machine.secret_storage`), before the config names its pin; where that
/// is a keyring that does not answer, this fails as for any of its keys.
fn relay_pin(
    paths: &NodePaths,
    cfg: &NodeConfig,
    address: Option<&str>,
) -> Result<(String, bool), String> {
    let storage = cfg.machine.secret_storage;
    if let Some(pin) = &cfg.relay.pin
        && let Ok(Some(id)) = crate::secrets::relay_tls(paths, storage)
        && id.pin() == *pin
    {
        return Ok((pin.clone(), false));
    }
    let names: Vec<String> = address
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .filter(|a| !a.ip().is_unspecified())
        .map(|a| a.ip().to_string())
        .into_iter()
        .collect();
    let id = nerve_transport::tls::ServerIdentity::generate(&names)?;
    crate::secrets::store_relay_tls(paths, storage, &id)?;
    Ok((id.pin(), true))
}

/// Where a relayed node finds the relay, for the line `relay add` shows:
/// the listening address, or a placeholder where it listens on every
/// address or is not set.
fn relay_address(listen: Option<&str>) -> String {
    match listen.and_then(|l| l.parse::<std::net::SocketAddr>().ok()) {
        Some(a) if !a.ip().is_unspecified() => a.to_string(),
        Some(a) => format!("<address of this machine>:{}", a.port()),
        None => "<address of this machine>:<port>".into(),
    }
}

const PROXY_AUTHORIZATION: &str = "Proxy-Authorization";

/// Where the node's keys are, in words.
fn keys_place(storage: SecretStorage) -> &'static str {
    match storage {
        SecretStorage::File => "a file in the config folder",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// Splits a user name and password off a proxy URL
/// (`http://user:pass@host:port`), percent-escapes decoded. Errors never quote
/// the URL once it holds an `@`.
fn split_credentials(url: &str) -> Result<(String, Option<(String, String)>), String> {
    let Some(at) = url.rfind('@') else {
        return Ok((url.to_string(), None));
    };
    let scheme_end = url
        .find("://")
        .filter(|i| *i < at)
        .ok_or("a proxy URL with a user name starts with http://")?;
    let (scheme, info, rest) = (
        &url[..scheme_end + 3],
        &url[scheme_end + 3..at],
        &url[at + 1..],
    );
    let (user, password) = info.split_once(':').unwrap_or((info, ""));
    let decode = |s: &str| {
        pct_decode(s).ok_or("the user name or password in the proxy URL has a bad %-escape")
    };
    let (user, password) = (decode(user)?, decode(password)?);
    if user.is_empty() || user.contains(':') {
        return Err("the proxy URL has an empty or bad user name".into());
    }
    Ok((format!("{scheme}{rest}"), Some((user, password))))
}

/// `%XX` escapes decoded; `None` for a broken escape or text that is not UTF-8.
fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `config accept`: the running daemon takes the file, or, when none runs,
/// the file is signed here.
async fn accept(paths: &NodePaths) -> Result<u64, String> {
    // Keys already in the keyring move nowhere when the file is taken, so
    // the settings store alone would not refuse it.
    if crate::secrets::stated_storage(paths) == SecretStorage::Keyring
        && let Some(n) = crate::secrets::no_keyring(paths)
    {
        return Err(format!(
            "{} says machine.secret_storage = \"keyring\", but {}. So the file was not accepted: change it to `secret_storage = \"file\"` and accept it again, which takes keys found in the keyring into files",
            paths.config_file().display(),
            n.why()
        ));
    }
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "config.accept", json!({})).await {
        Ok(v) => return Ok(v["version"].as_u64().unwrap_or_default()),
        Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
        Err(_) => {}
    }
    let (_, v) = SettingsStore::open_accepting_with(
        paths.config_file(),
        Box::new(crate::secrets::NodeSecrets::for_accept(paths)),
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

    /// A folder in a home the node's user may not look into (the installed
    /// node's CLI runs as `nerve`) is kept as given, in its normal form;
    /// what may be seen is resolved.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_cli_cannot_look_into_is_kept_as_given() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let d = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("proj")).unwrap();
        std::os::unix::fs::symlink(home.join("proj"), root.join("link")).unwrap();
        assert_eq!(
            resolve_folder(&root.join("link")).unwrap(),
            home.join("proj").display().to_string()
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let given = format!("{}//proj/./x/", home.display());
        let r = resolve_folder(Path::new(&given));
        let up = resolve_folder(&home.join("proj/../../etc"));
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(r.unwrap(), home.join("proj/x").display().to_string());
        assert!(up.is_err(), "{up:?}");
    }

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
        let e = run(&paths, &["mode", "set", "user"]).unwrap_err();
        assert!(e.contains("--center"), "{e}");
        run(&paths, &["mode", "set", "user", "--center", "b"]).unwrap();
        assert_eq!(load(&paths).center("b").unwrap().policy.mode, Mode::User);
        // A new center is in default deny.
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        run(&paths, &["mode", "set", "folder", "--center", "a"]).unwrap();
        assert_eq!(load(&paths).center("a").unwrap().policy.mode, Mode::Folder);
        run(&paths, &["mode", "set", "allowlist", "--center", "a"]).unwrap();
        assert_eq!(
            load(&paths).center("a").unwrap().policy.mode,
            Mode::Allowlist
        );
        let e = run(&paths, &["mode", "set", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown mode"), "{e}");
        let e = run(&paths, &["cap", "set", "fs", "ask", "--center", "a"]).unwrap_err();
        assert!(e.contains("unknown setting"), "{e}");
    }

    #[test]
    fn folder_and_user_mode_have_no_limit_unless_asked_for() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        for mode in ["user", "folder"] {
            run(&paths, &["mode", "set", mode]).unwrap();
            assert_eq!(policy().until, None, "{mode}");
        }
        // --for sets a limit of any length, on folder as on user.
        let before = crate::now_ms();
        run(&paths, &["mode", "set", "folder", "--for", "1000"]).unwrap();
        let until = policy().until.unwrap();
        assert!(until >= before + 1000 * 3_600_000, "{until}");
        assert_eq!(policy().mode_at(before), Mode::Folder);
        assert_eq!(policy().mode_at(until), Mode::Allowlist);
        run(&paths, &["mode", "set", "user", "--for", "9"]).unwrap();
        assert_eq!(policy().mode, Mode::User);
        // Setting the mode again without --for drops the old limit.
        run(&paths, &["mode", "set", "user"]).unwrap();
        assert_eq!(policy().until, None);
        // Allowlist has nothing to limit; nonsense hours are refused.
        run(&paths, &["mode", "set", "folder", "--for", "1"]).unwrap();
        let e = run(&paths, &["mode", "set", "allowlist", "--for", "1"]).unwrap_err();
        assert!(e.contains("--for"), "{e}");
        let e = run(&paths, &["mode", "set", "user", "--for", "0"]).unwrap_err();
        assert!(e.contains("at least 1"), "{e}");
        let e = run(
            &paths,
            &["mode", "set", "user", "--for", "18446744073709551615"],
        )
        .unwrap_err();
        assert!(e.contains("too large"), "{e}");
        let e = run(&paths, &["mode", "set", "user", "--for", "soon"]).unwrap_err();
        assert!(e.contains("invalid value"), "{e}");
        // A refused change leaves the mode as it was.
        assert_eq!(policy().mode, Mode::Folder);
        run(&paths, &["mode", "set", "allowlist"]).unwrap();
        assert_eq!(policy().until, None);
    }

    /// Without a control socket to tell (no daemon, or Windows, which has
    /// none), a change lands in the file only, and the CLI says when it
    /// counts; what changes nothing says nothing of the kind.
    #[test]
    fn a_change_no_running_node_was_told_of_says_when_it_takes_effect() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        let next = "takes effect at the next start of the node";
        let line = format!("the change is in node.toml; it {next}");
        for args in [
            &["folder", "add", folder.to_str().unwrap(), "+r"][..],
            &["mode", "set", "user"],
            &["rule", "add", "deny", "rm -rf /"],
        ] {
            let out = run(&paths, args).unwrap();
            assert_eq!(out.lines().last(), Some(line.as_str()), "{args:?}: {out}");
            assert_eq!(out.matches(next).count(), 1, "{args:?}: {out}");
        }
        for args in [&["status"][..], &["center", "ls"], &["folder", "ls"]] {
            let out = run(&paths, args).unwrap();
            assert!(!out.contains(&line), "{args:?}: {out}");
        }
        // A command that fails changed nothing.
        assert!(run(&paths, &["mode", "set", "ask"]).is_err());
    }

    #[test]
    fn edits_without_a_daemon_land_in_the_file_and_the_audit_log() {
        let (d, paths) = setup(&["home"]);
        let folder = d.path().join("work");
        std::fs::create_dir(&folder).unwrap();
        let note = run(
            &paths,
            &["folder", "add", folder.to_str().unwrap(), "+rw", "+x"],
        )
        .unwrap();
        assert!(note.contains("folders count in folder mode"), "{note}");
        run(&paths, &["cap", "set", "exec.run", "off"]).unwrap();
        run(&paths, &["center", "grant", "settings", "write"]).unwrap();
        run(
            &paths,
            &["rule", "add", "allow", "git status --short", "--wildcard"],
        )
        .unwrap();
        run(&paths, &["rule", "add", "sudo", "sudo apt update"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        run(&paths, &["mode", "set", "user", "--for", "2"]).unwrap();
        let cfg = load(&paths);
        let c = cfg.center("home").unwrap();
        let real = nerve_policy::paths::resolve(&folder).unwrap();
        assert_eq!(c.policy.folders[0].path, real.display().to_string());
        assert_eq!(c.policy.folders[0].access, Access::ALL);
        assert_eq!(c.policy.caps["exec.run"], CapSetting::Off);
        assert_eq!(c.settings, SettingsGrant::Write);
        assert_eq!(c.policy.allow, vec!["exec.run:git *".to_string()]);
        assert_eq!(c.policy.sudo_allow, vec!["sudo apt update".to_string()]);
        assert_eq!(c.policy.deny, vec!["exec.run:rm -rf /".to_string()]);
        assert_eq!(c.policy.mode, Mode::User);
        assert!(c.policy.until.is_some());
        let log = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(log.contains("local"), "{log}");
        run(&paths, &["panic"]).unwrap();
        assert!(load(&paths).locked);
        run(&paths, &["unlock"]).unwrap();
        assert!(!load(&paths).locked);
    }

    #[test]
    fn folder_add_needs_a_right_and_takes_only_plus() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let folders = || load(&paths).centers[0].policy.folders.clone();
        // No sign at all: refused, nothing stored.
        let e = run(&paths, &["folder", "add", dir]).unwrap_err();
        assert!(e.contains("+r"), "{e}");
        assert!(folders().is_empty());
        // The old flags and the other signs are no rights of a new folder.
        for bad in [
            &["--rw"][..],
            &["--execute"],
            &["--ro"],
            &["rw"],
            &["-w"],
            &["=r"],
            &["+"],
            &["+q"],
        ] {
            let mut args = vec!["folder", "add", dir];
            args.extend(bad);
            assert!(run(&paths, &args).is_err(), "{bad:?}");
        }
        assert!(folders().is_empty());
        // Each right alone, and several in one word or in several.
        for (rights, want) in [
            (&["+r"][..], "r"),
            (&["+w"], "w"),
            (&["+x"], "x"),
            (&["+r", "+x"], "rx"),
            (&["+wx"], "wx"),
            (&["+r", "+w", "+x"], "rwx"),
        ] {
            let mut args = vec!["folder", "add", dir];
            args.extend(rights);
            run(&paths, &args).unwrap();
            assert_eq!(folders().len(), 1, "added again, not twice");
            assert_eq!(folders()[0].access.to_string(), want, "{rights:?}");
        }
    }

    /// `folder add` records the place it stores, so that a link which
    /// replaces the folder later is refused (`exec::folder_sets`). Adding it
    /// again, also through a link of the owner's, keeps one entry; `folder
    /// set` keeps it, and `folder rm` takes it away with the folder.
    #[cfg(unix)]
    #[test]
    fn folder_add_records_the_place_and_rm_forgets_it() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&work, &link).unwrap();
        let real = nerve_policy::paths::resolve(&work)
            .unwrap()
            .display()
            .to_string();
        let (work, link) = (work.to_str().unwrap(), link.to_str().unwrap());
        let places = || load(&paths).centers[0].policy.places.clone();
        assert!(places().is_empty());
        run(&paths, &["folder", "add", work, "+r"]).unwrap();
        assert_eq!(places(), std::slice::from_ref(&real));
        // The same place again, and by a link: one folder, one entry.
        run(&paths, &["folder", "add", link, "+rw"]).unwrap();
        run(&paths, &["folder", "set", work, "+x"]).unwrap();
        assert_eq!(load(&paths).centers[0].policy.folders.len(), 1);
        assert_eq!(places(), std::slice::from_ref(&real));
        run(&paths, &["folder", "rm", link]).unwrap();
        assert!(load(&paths).centers[0].policy.folders.is_empty());
        assert!(places().is_empty());
        // Added once more, it is recorded once more.
        run(&paths, &["folder", "add", work, "+r"]).unwrap();
        assert_eq!(places(), std::slice::from_ref(&real));
    }

    /// A folder the CLI cannot look into (the installed node's CLI runs as
    /// `nerve`, a home may be closed to it) is stored as given and cannot be
    /// recorded here: with no running node to judge it as the account, the
    /// command says so.
    #[cfg(unix)]
    #[test]
    fn a_folder_the_cli_cannot_judge_is_added_with_a_note_and_no_record() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(home.join("proj")).unwrap();
        let proj = home.join("proj");
        let closed = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(&home, closed).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "+rw"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let out = out.unwrap();
        assert!(out.contains("not recorded at its real place"), "{out}");
        assert!(out.contains(&proj.display().to_string()), "{out}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert!(policy.places.is_empty(), "{policy:?}");
        // One it could judge says nothing of the kind.
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "+rw"]).unwrap();
        assert!(!out.contains("not recorded"), "{out}");
        assert_eq!(load(&paths).centers[0].policy.places.len(), 1);
        // Added again where it cannot look, the rights change and the record
        // it has stays: a record only narrows, and the node checks it as the
        // account before each command.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let out = run(&paths, &["folder", "add", proj.to_str().unwrap(), "+r"]);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(out.unwrap().contains("not recorded at its real place"));
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1);
        assert_eq!(policy.folders[0].access.to_string(), "r");
        assert_eq!(policy.places, [proj.display().to_string()]);
    }

    /// In the state the new warning reports, a link has replaced a recorded
    /// folder and its real place is another folder. `folder set` and `folder
    /// rm` act on the folder the path is spelled as (also with a trailing
    /// slash), name it, and leave the folder the link leads to alone; a path
    /// that is a link to a folder still finds the folder at its real place.
    #[cfg(unix)]
    #[test]
    fn folder_set_and_rm_find_a_folder_a_link_replaced_by_its_spelling() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        for (p, rights) in [(&work, "+rw"), (&bin, "+r"), (&docs, "+r")] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), rights]).unwrap();
        }
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let folders = || load(&paths).centers[0].policy.clone();
        let access = |p: &Path| {
            let policy = folders();
            let f = policy.folders.iter().find(|f| Path::new(&f.path) == p);
            f.map(|f| f.access.to_string())
        };
        let spelled = format!("{}/", bin.display());

        let out = run(&paths, &["folder", "set", &spelled, "+x"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", bin.display())),
            "{out}"
        );
        assert_eq!(access(&bin).as_deref(), Some("rx"));
        assert_eq!(access(&docs).as_deref(), Some("r"));

        let out = run(&paths, &["folder", "rm", &spelled]).unwrap();
        assert!(out.contains(&format!("removed {}", bin.display())), "{out}");
        assert_eq!(access(&bin), None);
        assert_eq!(access(&docs).as_deref(), Some("r"));
        assert!(!folders().is_placed(&bin.display().to_string()));
        assert!(folders().is_placed(&docs.display().to_string()));

        // The owner's own link to a folder finds the folder it leads to.
        let to_docs = root.join("to-docs");
        std::os::unix::fs::symlink(&docs, &to_docs).unwrap();
        let out = run(&paths, &["folder", "rm", to_docs.to_str().unwrap()]).unwrap();
        assert!(
            out.contains(&format!("removed {}", docs.display())),
            "{out}"
        );
        assert_eq!(access(&docs), None);
        assert_eq!(access(&work).as_deref(), Some("rw"));
    }

    /// `folder rm` and `folder set` find the stored folder by the path the
    /// owner gave `folder add`, when that went through a link of the owner's
    /// and the stored place has been replaced by a link since; and where a
    /// dangling link or a loop of links stands in the folder's place, which
    /// resolving the path would refuse. A folder the path only passes is not
    /// the folder it names.
    #[cfg(unix)]
    #[test]
    fn folder_rm_and_set_reach_a_folder_through_links_and_where_none_resolves() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs, data) = (root.join("work"), root.join("docs"), root.join("data"));
        let (real, code) = (data.join("real"), root.join("code"));
        for p in [&work.join("bin"), &work.join("sub"), &docs, &real] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::os::unix::fs::symlink(&real, &code).unwrap();
        for (p, rights) in [
            (&work, "+rw"),
            (&work.join("bin"), "+r"),
            (&code, "+r"),
            (&docs, "+r"),
        ] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), rights]).unwrap();
        }
        let listed = || -> Vec<String> {
            load(&paths).centers[0]
                .policy
                .folders
                .iter()
                .map(|f| f.path.clone())
                .collect()
        };
        let has = |p: &Path| listed().contains(&p.display().to_string());
        assert!(has(&real) && !has(&code), "stored at the real place");

        // The stored place is replaced by a link to `docs`: `code`, the path
        // the owner gave, still names the stored folder and not `docs`.
        std::fs::remove_dir(&real).unwrap();
        std::os::unix::fs::symlink(&docs, &real).unwrap();
        let out = run(&paths, &["folder", "set", code.to_str().unwrap(), "+x"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", real.display())),
            "{out}"
        );
        let out = run(&paths, &["folder", "rm", code.to_str().unwrap()]).unwrap();
        assert!(
            out.contains(&format!("removed {}", real.display())),
            "{out}"
        );
        assert!(!has(&real) && has(&docs));

        // A folder the path only passes is not the folder it names.
        let e = run(
            &paths,
            &["folder", "rm", work.join("sub").to_str().unwrap()],
        )
        .unwrap_err();
        assert!(e.contains("not a folder of this center"), "{e}");
        assert!(has(&work));

        // A dangling link, and then a loop, stand where `work/bin` was.
        let bin = work.join("bin");
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(root.join("nowhere"), &bin).unwrap();
        let out = run(&paths, &["folder", "set", bin.to_str().unwrap(), "-r"]).unwrap();
        assert!(
            out.contains(&format!("folder {} ---", bin.display())),
            "{out}"
        );
        std::fs::remove_file(&bin).unwrap();
        std::os::unix::fs::symlink(&bin, &bin).unwrap();
        let out = run(&paths, &["folder", "rm", bin.to_str().unwrap()]).unwrap();
        assert!(out.contains(&format!("removed {}", bin.display())), "{out}");
        assert!(!has(&bin) && has(&work) && has(&docs));
        // What is not stored under any spelling still says why.
        let e = run(&paths, &["folder", "rm", bin.to_str().unwrap()]).unwrap_err();
        assert!(
            e.contains("Too many levels") || e.contains("symlink"),
            "{e}"
        );
    }

    /// The installed node's CLI runs as `nerve`, which cannot look into the
    /// owner's home: a link there stays as typed, and the folder `folder add`
    /// stored at the place the link leads to is not found. `folder set` and
    /// `folder rm` then name the path `folder ls` shows (issue #98), also where
    /// the center has more folders than the hint would list.
    #[cfg(unix)]
    #[test]
    fn folder_set_and_rm_name_the_listed_folder_for_a_link_the_cli_cannot_look_into() {
        use std::os::unix::fs::PermissionsExt;
        if nerve_transport::net::euid() == 0 {
            return; // root looks into every folder
        }
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (home, data) = (root.join("home"), root.join("data"));
        let (proj, work) = (home.join("proj"), data.join("work"));
        for p in [&proj, &work] {
            std::fs::create_dir_all(p).unwrap();
        }
        let (link, far) = (home.join("linkproj"), home.join("sub").join("linkwork"));
        std::fs::create_dir(home.join("sub")).unwrap();
        std::os::unix::fs::symlink(&proj, &link).unwrap();
        std::os::unix::fs::symlink(&work, &far).unwrap();
        for p in [&proj, &work] {
            run(&paths, &["folder", "add", p.to_str().unwrap(), "+r"]).unwrap();
        }
        let listed = |n: usize| load(&paths).centers[0].policy.folders.len() == n;
        // While the CLI can look at the link, it finds the folder.
        let out = run(&paths, &["folder", "set", link.to_str().unwrap(), "+x"]).unwrap();
        assert!(
            out.contains(&format!("folder {} r-x", proj.display())),
            "{out}"
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut errors = Vec::new();
        for args in [["set", "+w"], ["rm", ""]] {
            let mut cmd = vec!["folder", args[0], link.to_str().unwrap()];
            if !args[1].is_empty() {
                cmd.push(args[1]);
            }
            errors.push(run(&paths, &cmd).unwrap_err());
        }
        // Only folders far from the path are listed, and more than the hint
        // would name: it still says what to do.
        for n in ["a", "b"] {
            let p = root.join(n);
            std::fs::create_dir(&p).unwrap();
            run(&paths, &["folder", "add", p.to_str().unwrap(), "+r"]).unwrap();
        }
        errors.push(run(&paths, &["folder", "rm", far.to_str().unwrap()]).unwrap_err());
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        for e in &errors[..2] {
            assert!(
                e.starts_with(&format!(
                    "{} is not a folder of this center",
                    link.display()
                )),
                "{e}"
            );
            assert!(
                e.ends_with(&format!(
                    "`nerve-node folder ls` shows for the folder: {}",
                    proj.display()
                )),
                "{e}"
            );
        }
        let e = &errors[2];
        assert!(e.contains("this account cannot look into it"), "{e}");
        assert!(e.ends_with("shows for the folder"), "{e}");
        // The refused calls changed nothing.
        assert!(listed(4));
    }

    /// A link a command may have put inside a folder it can write in is not
    /// followed by `folder add`: it would store, and record, whatever the link
    /// leads to, past the check that keeps such a folder out of the sandbox.
    /// A link of the owner's elsewhere is followed, as before.
    #[cfg(unix)]
    #[test]
    fn folder_add_does_not_follow_a_link_inside_a_write_folder() {
        let (d, paths) = setup(&["home"]);
        let root = std::fs::canonicalize(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        // The folder is a plain one first, and then a command replaces it.
        run(&paths, &["folder", "add", bin.to_str().unwrap(), "+r"]).unwrap();
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let before = load(&paths).centers[0].policy.clone();
        let e = run(&paths, &["folder", "add", bin.to_str().unwrap(), "+rx"]).unwrap_err();
        assert!(e.contains("link") && e.contains("may write"), "{e}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(
            policy, before,
            "nothing changed, the record of `bin` included"
        );
        assert!(policy.is_placed(&bin.display().to_string()));
        assert!(!policy.is_placed(&docs.display().to_string()));
        assert!(!policy.is_placed(&docs.display().to_string()));
        // A link of the owner's outside every write folder is followed.
        let to_docs = root.join("to-docs");
        std::os::unix::fs::symlink(&docs, &to_docs).unwrap();
        run(&paths, &["folder", "add", to_docs.to_str().unwrap(), "+r"]).unwrap();
        assert!(
            load(&paths).centers[0]
                .policy
                .is_placed(&docs.display().to_string())
        );
    }

    /// On Windows, a junction a command may have put inside a folder it can
    /// write in is not followed by `folder add` either.
    #[cfg(windows)]
    #[test]
    fn folder_add_does_not_follow_a_junction_inside_a_write_folder() {
        let (d, paths) = setup(&["home"]);
        let root = nerve_policy::paths::resolve(d.path()).unwrap();
        let (work, docs) = (root.join("work"), root.join("docs"));
        let bin = work.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(&docs).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        std::fs::remove_dir(&bin).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&bin)
            .arg(&docs)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        let e = run(&paths, &["folder", "add", bin.to_str().unwrap(), "+rx"]).unwrap_err();
        assert!(e.contains("link") && e.contains("may write"), "{e}");
        let policy = load(&paths).centers[0].policy.clone();
        assert_eq!(policy.folders.len(), 1, "nothing was stored: {policy:?}");
        assert!(!policy.is_placed(&docs.display().to_string()));
    }

    #[test]
    fn folder_set_applies_its_changes_left_to_right() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        let dir = dir.to_str().unwrap();
        let access = || load(&paths).centers[0].policy.folders[0].access.to_string();
        // A folder that is not the center's is an error.
        assert!(run(&paths, &["folder", "set", dir, "+x"]).is_err());
        run(&paths, &["folder", "add", dir, "+r"]).unwrap();
        for (change, want) in [
            (&["+x"][..], "rx"),
            (&["-r"], "x"),
            (&["=rwx"], "rwx"),
            (&["-w"], "rx"),
            (&["+rw"], "rwx"),
            (&["-rw"], "x"),
            (&["=w"], "w"),
            (&["=rwx", "-x", "+x", "-r"], "wx"),
            (&["=r", "+w", "-r"], "w"),
            (&["="], ""),
        ] {
            let mut args = vec!["folder", "set", dir];
            args.extend(change);
            run(&paths, &args).unwrap();
            assert_eq!(access(), want, "{change:?}");
        }
        // A bad change anywhere in the list changes nothing.
        run(&paths, &["folder", "set", dir, "=rx"]).unwrap();
        for bad in [&["+w", "rw"][..], &["+q"], &["+"], &["=rr"]] {
            let mut args = vec!["folder", "set", dir];
            args.extend(bad);
            assert!(run(&paths, &args).is_err(), "{bad:?}");
            assert_eq!(access(), "rx", "{bad:?}");
        }
        // --center still works after hyphen-led changes.
        run(&paths, &["folder", "set", dir, "-w", "--center", "home"]).unwrap();
        run(&paths, &["folder", "set", dir, "+w", "--center=home"]).unwrap();
        run(&paths, &["folder", "set", "--center", "home", dir, "-w"]).unwrap();
        assert_eq!(access(), "rx");
        for bad in [
            &["--center", "nobody", "-w"][..],
            &["-w", "--center"],
            &["-w", "--bogus"],
            &["--center", "home"],
        ] {
            let mut args = vec!["folder", "set", dir];
            args.extend(bad);
            assert!(run(&paths, &args).is_err(), "{bad:?}");
        }
        assert_eq!(access(), "rx");
        let out = run(&paths, &["folder", "ls"]).unwrap();
        assert!(out.starts_with("r-x  "), "{out}");
        run(&paths, &["folder", "rm", dir]).unwrap();
        assert!(load(&paths).centers[0].policy.folders.is_empty());
        assert!(run(&paths, &["folder", "rm", dir]).is_err());
    }

    #[test]
    fn centers_pause_and_resume_by_the_owner() {
        let (_d, paths) = setup(&["a", "b"]);
        assert!(run(&paths, &["center", "pause"]).is_err());
        run(&paths, &["center", "pause", "--center", "a"]).unwrap();
        let cfg = load(&paths);
        assert!(cfg.center("a").unwrap().paused);
        assert!(!cfg.center("b").unwrap().paused);
        let ls = run(&paths, &["center", "ls"]).unwrap();
        assert!(ls.contains("[paused]"), "{ls}");
        run(&paths, &["center", "resume", "--center", "a"]).unwrap();
        assert!(!load(&paths).center("a").unwrap().paused);
        run(&paths, &["center", "rm", "--center", "b"]).unwrap();
        assert!(load(&paths).center("b").is_none());
    }

    /// On Windows: `center rm` removes the profile of the pairing's
    /// AppContainer also when the record of the grants does not name it,
    /// as after the state folder was deleted.
    #[cfg(windows)]
    #[test]
    fn center_rm_removes_the_profile_the_record_does_not_name() {
        let (_d, paths) = setup(&["home"]);
        let name = crate::grants::container(&paths, "n");
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(&name);
        // Starting a command in the container makes its profile; whether
        // the command runs does not matter here.
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            &name,
        );
        assert!(profile.exists(), "{}", profile.display());
        assert!(!crate::grants::record_file(&paths).exists());
        let ls = run(&paths, &["center", "ls"]).unwrap();
        assert!(ls.contains(&format!("AppContainer {name}")), "{ls}");
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(
            out.contains(&format!("removed the AppContainer profile {name} of home")),
            "{out}"
        );
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// On Windows: a node that spelled its state folder with `/`, as the
    /// default one is, is found by the folder typed with `\`.
    #[cfg(windows)]
    #[test]
    fn center_rm_finds_the_profile_of_the_state_folder_spelled_otherwise() {
        let (d, paths) = setup(&["home"]);
        let spelled = NodePaths::new(
            &paths.config_dir,
            PathBuf::from(format!("{}/s", d.path().display())),
        );
        assert_eq!(spelled.state_dir, paths.state_dir);
        let name = crate::grants::container(&spelled, "n");
        assert_ne!(name, crate::grants::container(&paths, "n"));
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(&name);
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            &name,
        );
        assert!(profile.exists(), "{}", profile.display());
        let ls = run(&paths, &["center", "ls"]).unwrap();
        assert!(ls.contains(&format!("AppContainer {name}")), "{ls}");
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(out.contains(&name), "{out}");
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// The profile folder of the container `name`, made by starting a
    /// command in it; whether the command runs does not matter.
    #[cfg(windows)]
    fn profile_of(name: &str) -> PathBuf {
        let _ = nerve_sandbox::appcontainer::run(
            Path::new("cmd.exe"),
            &["/C".into(), "exit 0".into()],
            name,
        );
        let profile = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
            .join("Packages")
            .join(name);
        assert!(profile.exists(), "{}", profile.display());
        profile
    }

    /// On Windows: the profile of a pairing with folder entries goes with
    /// their grants at `center rm`, which says so, and stays while the node
    /// runs, which it says too.
    #[cfg(windows)]
    #[test]
    fn center_rm_names_the_profile_that_goes_with_the_last_grant() {
        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        assert!(crate::grants::record_file(&paths).exists());
        let name = crate::grants::container(&paths, "n");
        let profile = profile_of(&name);
        // A node that runs holds the lock.
        let held = crate::secrets::KeysLock::try_take(&paths).unwrap().unwrap();
        let out = run(&paths, &["center", "rm"]).unwrap();
        drop(held);
        assert!(
            out.contains(&format!(
                "the AppContainer profile {name} of home stays, since the node at"
            )),
            "{out}"
        );
        assert!(profile.exists(), "{}", profile.display());
        nerve_sandbox::appcontainer::remove_profile(&name).unwrap();

        let (d, paths) = setup(&["home"]);
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        run(&paths, &["folder", "add", work.to_str().unwrap(), "+rw"]).unwrap();
        let name = crate::grants::container(&paths, "n");
        let profile = profile_of(&name);
        let out = run(&paths, &["center", "rm"]).unwrap();
        assert!(
            out.contains(&format!("removed the AppContainer profile {name} of home")),
            "{out}"
        );
        assert!(!profile.exists(), "{}", profile.display());
    }

    /// On Windows: when the grants of the pairings that stay do not follow
    /// (a hard link below a folder they write), `center rm` still removes
    /// the pairing's profile, as nothing names it once the pairing is gone,
    /// and then says what failed.
    #[cfg(windows)]
    #[test]
    fn center_rm_removes_the_profile_when_the_other_grants_do_not_follow() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        let work = d.path().join("work");
        std::fs::create_dir(&work).unwrap();
        std::fs::write(work.join("a.txt"), "x").unwrap();
        std::fs::hard_link(work.join("a.txt"), work.join("b.txt")).unwrap();
        let real = nerve_policy::paths::resolve(&work).unwrap();
        let mut cfg = NodeConfig::default();
        let mut home = entry("home");
        home.node_id = "n-home".into();
        home.policy.folders.push(nerve_policy::config::Folder {
            path: real.display().to_string(),
            access: Access::parse("rw").unwrap(),
        });
        let mut lab = entry("lab");
        lab.node_id = "n-lab".into();
        cfg.centers = vec![home, lab];
        cfg.save(&paths.config_file()).unwrap();
        let name = crate::grants::container(&paths, "n-lab");
        let profile = profile_of(&name);
        let e = run(&paths, &["center", "rm", "--center", "lab"]).unwrap_err();
        assert!(e.contains("the folder grants do not follow"), "{e}");
        assert!(load(&paths).center("lab").is_none());
        assert!(!profile.exists(), "{}", profile.display());
    }

    #[test]
    fn config_get_set_by_dotted_key() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["config", "set", "limits.max_running", "4"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 4);
        run(&paths, &["config", "set", "center.home.policy.until", "30"]).unwrap();
        assert_eq!(
            run(&paths, &["config", "get", "center.home.policy.until"]).unwrap(),
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

    /// The owner sets the run-time limits by name; a limit of 0 is refused
    /// and changes nothing, and unsetting one gives the default back.
    #[test]
    fn config_sets_the_run_time_limits() {
        let (_d, paths) = setup(&["home"]);
        assert_eq!(load(&paths).limits.default_timeout_secs, 600);
        assert_eq!(load(&paths).limits.max_timeout_secs, 3600);
        run(
            &paths,
            &["config", "set", "limits.default_timeout_secs", "30"],
        )
        .unwrap();
        run(&paths, &["config", "set", "limits.max_timeout_secs", "90"]).unwrap();
        assert_eq!(load(&paths).limits.default_timeout_secs, 30);
        assert_eq!(load(&paths).limits.max_timeout_secs, 90);
        assert_eq!(
            run(&paths, &["config", "get", "limits.max_timeout_secs"]).unwrap(),
            "90\n"
        );
        for key in ["default_timeout_secs", "max_timeout_secs"] {
            let e = run(&paths, &["config", "set", &format!("limits.{key}"), "0"]).unwrap_err();
            assert!(e.contains("must be at least 1"), "{e}");
        }
        assert_eq!(load(&paths).limits.max_timeout_secs, 90);
        run(&paths, &["config", "unset", "limits.max_timeout_secs"]).unwrap();
        assert_eq!(load(&paths).limits.max_timeout_secs, 3600);
    }

    /// install, update and uninstall work on the installed node only, so
    /// they take no folders; none says it is not done.
    #[test]
    fn the_service_commands_take_no_folders() {
        let (_d, paths) = setup(&[]);
        for cmd in [
            &["install"][..],
            &["update"],
            &["update", "--from", "/tmp/x"],
            &["uninstall"],
            &["uninstall", "--purge"],
        ] {
            let e = run(&paths, cmd).unwrap_err();
            assert!(e.contains("--config-dir and --state-dir do not go"), "{e}");
            assert!(!e.contains("not done"), "{e}");
        }
    }

    fn setup_with(paths: &NodePaths, answers: &str) -> (Result<(), String>, String) {
        setup_on(paths, None, None, answers)
    }

    fn setup_on(
        paths: &NodePaths,
        machine: Option<&dyn crate::service::System>,
        create_user: Option<&str>,
        answers: &str,
    ) -> (Result<(), String>, String) {
        let keyring = crate::keyring_setup::tests::FakeKeyring::new(true);
        setup_keyring(paths, machine, create_user, &keyring, answers)
    }

    fn setup_keyring(
        paths: &NodePaths,
        machine: Option<&dyn crate::service::System>,
        create_user: Option<&str>,
        keyring: &dyn crate::keyring_setup::Keyring,
        answers: &str,
    ) -> (Result<(), String>, String) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(answers.as_bytes().to_vec());
        let r = rt.block_on(super::setup(
            paths,
            machine,
            create_user,
            keyring,
            &mut input,
            &mut out,
        ));
        (r, String::from_utf8(out).unwrap())
    }

    /// `setup --create-user NAME` makes the account and runs commands as it
    /// without the question, and asks the other questions as before.
    #[cfg(target_os = "linux")]
    #[test]
    fn setup_creates_the_account_of_the_commands_when_asked() {
        use crate::service::System;
        let cli = Cli::try_parse_from(["nerve-node", "setup", "--create-user", "bob"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Setup { create_user: Some(ref n) } if n == "bob"));
        assert!(Cli::try_parse_from(["nerve-node", "setup", "--create-user"]).is_err());
        let (_d, paths) = setup(&["home"]);
        let sys = crate::service::tests::Fake::new();
        // Name, the keys stay in files, no link, user mode for the one
        // center: no account question.
        let (r, out) = setup_on(&paths, Some(&sys), Some("bob"), "lab-pc\n\n\nuser\n");
        r.unwrap();
        assert!(!out.contains("Account that commands"), "{out}");
        assert!(out.contains("commands run as bob"), "{out}");
        assert!(sys.calls().contains(&"useradd bob /home/bob".to_string()));
        assert_eq!(
            sys.account("bob").unwrap().unwrap().home,
            Path::new("/home/bob")
        );
        let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
        assert_eq!(cfg.machine.user.as_deref(), Some("bob"));
        assert_eq!(cfg.node.name.as_deref(), Some("lab-pc"));
        assert_eq!(cfg.center("home").unwrap().policy.mode, Mode::User);
        let steps = node_audit(&paths)[0]["steps"].to_string();
        assert!(steps.contains("made the account bob"), "{steps}");
        // Refused before any question: nerve, a bad name, and a node not
        // installed as a service.
        for (machine, name, why) in [
            (Some(&sys as &dyn System), "nerve", "node's own user"),
            (Some(&sys), "Bob!", "not a name setup makes"),
            (None, "carol", "installed as a service"),
        ] {
            let (r, out) = setup_on(&paths, machine, Some(name), "");
            let e = r.unwrap_err();
            assert!(e.contains(why), "{name}: {e}");
            assert!(!out.contains("Account that commands"), "{out}");
        }
        assert_eq!(
            SettingsStore::peek(&paths.config_file(), &paths.config_key())
                .unwrap()
                .machine
                .user
                .as_deref(),
            Some("bob")
        );
    }

    fn node_audit(paths: &NodePaths) -> Vec<Value> {
        AuditLog::new(paths.audit_log())
            .read()
            .unwrap()
            .into_iter()
            .filter(|v| v["kind"] == "node")
            .collect()
    }

    /// Setup asks name, center and mode; Enter keeps each, and every answer
    /// goes through the owner's path into the signed file and the audit log.
    #[test]
    fn setup_names_the_node_and_sets_the_first_centers_mode() {
        let (d, paths) = setup(&["home"]);
        let dir = d.path().join("work");
        std::fs::create_dir(&dir).unwrap();
        // A name, the keys where they are, no new center (the one paired is
        // the first), folder mode with one folder.
        let answers = format!("lab-pc\n\n\nfolder\n{}\n+r +x\n", dir.display());
        let (r, out) = setup_with(&paths, &answers);
        r.unwrap();
        assert!(out.contains("Name of this node"), "{out}");
        assert!(out.contains("home: mode folder"), "{out}");
        let cfg = SettingsStore::peek(&paths.config_file(), &paths.config_key()).unwrap();
        assert_eq!(cfg.node.name.as_deref(), Some("lab-pc"));
        let c = cfg.center("home").unwrap();
        assert_eq!(c.policy.mode, Mode::Folder);
        assert_eq!(c.policy.folders.len(), 1);
        assert_eq!(c.policy.folders[0].access.to_string(), "rx");
        let a = node_audit(&paths);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "setup");
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 3, "{}", a[0]);
        // Again with Enter everywhere: nothing changes.
        let before = std::fs::read(paths.config_file()).unwrap();
        let (r, _) = setup_with(&paths, "\n\n\n\n\n");
        r.unwrap();
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        // A bad name or a short input stops it, and the audit log says so.
        let (r, _) = setup_with(&paths, "Bad Name\n");
        assert!(r.unwrap_err().contains("not a node name"));
        let (r, _) = setup_with(&paths, "");
        assert!(r.unwrap_err().contains("input ended"));
        let a = node_audit(&paths);
        assert!(
            a.last().unwrap()["error"]
                .as_str()
                .unwrap()
                .contains("input ended")
        );
        let shown = run(&paths, &["audit"]).unwrap();
        assert!(
            shown.contains("setup: named the node lab-pc; home: mode folder"),
            "{shown}"
        );
    }

    /// Folder mode's commands are told off where Landlock cannot keep a
    /// command off the session bus, and `status` prints why the node says
    /// they are.
    #[test]
    fn the_keyring_turns_folder_commands_off_below_abi_9() {
        use nerve_sandbox::Confinement;
        let abi = |v| Confinement {
            landlock_abi: v,
            appcontainer: false,
        };
        let account = |uid| crate::service::Account {
            name: "alice".into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/home/alice".into(),
            groups: vec![uid],
        };
        let (root, alice) = (account(0), account(4242));
        assert!(keyring_turns_commands_off(abi(Some(6)), || None));
        assert!(keyring_turns_commands_off(abi(Some(6)), || Some(root)));
        // Another account than root cannot reach the bus: its commands run.
        assert!(!keyring_turns_commands_off(abi(Some(6)), || Some(alice)));
        let asked = std::cell::Cell::new(false);
        let ask = || {
            asked.set(true);
            None
        };
        assert!(!keyring_turns_commands_off(abi(Some(9)), ask));
        assert!(!keyring_turns_commands_off(abi(None), ask));
        assert!(!asked.get());
        assert!(folder_commands_off().contains("machine.secret_storage file"));
    }

    /// The node's keys as setup and `config set` leave them: whether the
    /// config's key is in its file, and in the test keyring.
    fn config_key_at(paths: &NodePaths) -> (bool, bool) {
        let entry = crate::secrets::Entry::config_key(paths);
        (
            paths.config_key().exists(),
            crate::secrets::store::get(entry.account())
                .unwrap()
                .is_some(),
        )
    }

    #[test]
    fn config_set_moves_the_keys_and_center_rm_deletes_them_from_the_keyring() {
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // Without a keyring nothing moves, and the setting stays.
        crate::secrets::store::set_unreachable(true);
        let e = set("keyring").unwrap_err();
        crate::secrets::store::set_unreachable(false);
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        set("keyring").unwrap();
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
        assert!(!paths.key_file("home").exists());
        let read = crate::secrets::center_key(&paths, SecretStorage::Keyring, "home").unwrap();
        assert_eq!(read.public_key(), key.public_key());
        run(&paths, &["center", "rm", "--center", "home"]).unwrap();
        assert!(crate::secrets::center_key(&paths, SecretStorage::Keyring, "home").is_err());
        set("file").unwrap();
        assert_eq!(config_key_at(&paths), (true, false));
        assert_eq!(
            run(&paths, &["config", "get", "machine.secret_storage"])
                .unwrap()
                .trim(),
            "file"
        );
    }

    /// Setup asks where the keys go; `keyring` moves them there.
    #[test]
    fn setup_keeps_the_keys_in_the_keyring_when_asked() {
        let (_d, paths) = setup(&[]);
        // Name kept, keys to the keyring, no link.
        let (r, out) = setup_with(&paths, "\nkeyring\n\n");
        r.unwrap();
        assert!(out.contains("Where the node keeps its keys"), "{out}");
        assert!(out.contains("[file]"), "{out}");
        assert!(
            out.contains("the node's keys are in the system keyring now"),
            "{out}"
        );
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
        let steps = node_audit(&paths)[0]["steps"].to_string();
        assert!(steps.contains("system keyring"), "{steps}");
        // Asked again, the keyring is what Enter keeps.
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("[keyring]"), "{out}");
        let (r, _) = setup_with(&paths, "\nwallet\n");
        assert!(r.unwrap_err().contains("file or keyring"));
    }

    /// The installed node on Windows keeps its keys in files: `config set`
    /// refuses the keyring and changes nothing, and setup does not ask
    /// where the keys go but takes keys left in the keyring into files.
    #[test]
    fn the_installed_node_on_windows_keeps_its_keys_in_files() {
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // Moved there before it was the installed node.
        set("keyring").unwrap();
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("Where the node keeps its keys"), "{out}");
        assert!(
            out.contains("Warning: the installed node on Windows"),
            "{out}"
        );
        assert!(out.contains("the node's keys are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        let e = set("keyring").unwrap_err();
        assert!(e.contains("cannot be \"keyring\""), "{e}");
        assert!(
            e.contains(
                "go to the Credential Manager of the account that runs them, not to that of nerve"
            ),
            "{e}"
        );
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        // Asked again, setup leaves the files as they are.
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
    }

    /// Below Landlock ABI 9 the keys stay in files: setup warns and does
    /// not ask, taking keys left in the keyring into files; `config set`
    /// refuses the keyring; `config accept` refuses a file that keeps them
    /// there. Where the ABI cannot be read, setup warns and still asks.
    #[test]
    fn below_landlock_9_the_keys_stay_in_files() {
        use crate::secrets::{Landlock, for_tests::pretend_landlock};
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // The ABI cannot be read: a warning, the question, and the keyring
        // if asked for.
        pretend_landlock(&paths, Landlock::Unknown);
        let (r, out) = setup_with(&paths, "\nkeyring\n\n\n");
        r.unwrap();
        assert!(
            out.contains("the Landlock ABI of this kernel cannot be read"),
            "{out}"
        );
        assert!(out.contains("keep the keys in files (file)"), "{out}");
        assert!(out.contains("Where the node keeps its keys"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        // A file changed by hand that keeps them there is not taken.
        pretend_landlock(&paths, Landlock::Abi(5));
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        std::fs::write(paths.config_file(), format!("{text}# edited\n")).unwrap();
        let e = run(&paths, &["config", "accept"]).unwrap_err();
        assert!(e.contains("was not accepted"), "{e}");
        assert!(e.contains("Landlock ABI 5, below 9"), "{e}");
        std::fs::write(paths.config_file(), &text).unwrap();
        // Setup warns, asks nothing about the keys, and moves them out.
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("Where the node keeps its keys"), "{out}");
        assert!(out.contains("Warning: on this kernel (Landlock ABI 5, below 9) a folder mode command cannot run programs from its folders while the node's keys are in the system keyring: the sandbox cannot grant the keyring's access and execute together"), "{out}");
        assert!(out.contains("the node's keys are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        let e = set("keyring").unwrap_err();
        assert!(e.contains("Landlock ABI 5, below 9"), "{e}");
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        // ABI 9 lets them go there again.
        pretend_landlock(&paths, Landlock::Abi(9));
        set("keyring").unwrap();
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
    }

    /// Below Landlock ABI 9 with the keys in a keyring that does not
    /// answer, setup still offers to install one, so that it can take the
    /// keys into files.
    #[test]
    fn below_landlock_9_setup_reaches_the_keyring_to_empty_it() {
        use crate::secrets::{Landlock, for_tests::pretend_landlock};
        let (_d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "machine.secret_storage", "keyring"],
        )
        .unwrap();
        pretend_landlock(&paths, Landlock::Abi(5));
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_keyring(&paths, None, None, &k, "y\n\n\n");
        crate::secrets::store::set_unreachable(false);
        r.unwrap();
        assert!(out.contains("Install it now? [y/N]"), "{out}");
        assert!(out.contains("the node's keys are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
    }

    /// Where no keyring answers, setup offers to install one: no keeps the
    /// files, yes installs it and moves the keys.
    #[test]
    fn setup_offers_a_keyring_where_none_answers() {
        let (_d, paths) = setup(&[]);
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_keyring(&paths, None, None, &k, "\nkeyring\nn\n");
        let e = r.unwrap_err();
        assert!(e.contains("no system keyring answers"), "{e}");
        assert!(out.contains("Install it now? [y/N]"), "{out}");
        assert!(k.installed.borrow().is_empty());
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        let (r, out) = setup_keyring(&paths, None, None, &k, "\nkeyring\ny\n\n");
        r.unwrap();
        assert_eq!(k.installed.borrow().len(), 1);
        assert!(out.contains("the system keyring answers"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
    }

    /// A running node that found no keyring keeps that failure: after
    /// setup installed one, the installed node is restarted before the keys
    /// move, and the owner of a node run by hand is told to restart it. A
    /// node that never failed is left alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_node_that_found_no_keyring_is_restarted_after_one_is_installed() {
        let (_d, paths) = setup(&[]);
        let failed = json!({"version": 1, "keyring_failed": true});
        let sys = crate::service::tests::Fake::new();
        let mut out = Vec::new();
        restart_for_keyring(&failed, &paths, Some(&sys), &mut out).unwrap();
        assert!(
            sys.calls()
                .contains(&format!("systemctl restart {}", crate::service::UNIT_NAME)),
            "{:?}",
            sys.calls()
        );
        assert!(String::from_utf8_lossy(&out).contains("restarted the node"));
        let e = restart_for_keyring(&failed, &paths, None, &mut out).unwrap_err();
        assert!(
            e.contains("restart it, then run `nerve-node setup` again"),
            "{e}"
        );
        let sys = crate::service::tests::Fake::new();
        let fine = json!({"version": 1, "keyring_failed": false});
        restart_for_keyring(&fine, &paths, Some(&sys), &mut out).unwrap();
        restart_for_keyring(&fine, &paths, None, &mut out).unwrap();
        assert!(sys.calls().is_empty(), "{:?}", sys.calls());
    }

    /// `status` shows the limits per command the owner set, and whether
    /// the running node holds commands to them, or why not.
    #[cfg(unix)]
    #[test]
    fn the_status_shows_the_limits_per_command() {
        let (d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "limits.command.memory_mb", "512"],
        )
        .unwrap();
        let out = run(&paths, &["status"]).unwrap();
        assert!(
            out.contains("limits per command: memory 512 MiB, CPU 200 %, 1024 processes; a call may ask for up to 16384 MiB, 800 %, 8192 processes"),
            "{out}"
        );
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let node = {
            let (home, paths) = (d.path().to_path_buf(), paths.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let mut opts = NodeOptions::new(paths);
                opts.home = home;
                opts.full_rights = Some(false);
                opts.cgroups = Some(Err("no cgroup for this test".into()));
                let daemon = rt.block_on(Daemon::start(opts)).unwrap();
                ready_tx.send(()).unwrap();
                rt.block_on(async {
                    while stop_rx.try_recv().is_err() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    daemon.stop().await;
                });
            })
        };
        ready.recv().unwrap();
        let out = run(&paths, &["status"]);
        stop.send(()).unwrap();
        node.join().unwrap();
        let out = out.unwrap();
        assert!(out.contains("limits per command: memory 512 MiB"), "{out}");
        assert!(
            out.contains("commands run WITHOUT these limits: no cgroup for this test"),
            "{out}"
        );
    }

    #[test]
    fn the_status_names_the_cgroup_and_what_it_holds() {
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "/system.slice/nerve-node.service",
                       "enforced": ["memory", "processes"], "off": null});
        assert_eq!(
            limits_lines(&v),
            [
                "limits per command: memory 1 MiB, CPU 3 %, 5 processes; a call may ask for up to 2 MiB, 4 %, 6 processes",
                "limits held by the cgroup /system.slice/nerve-node.service: memory, processes; not cpu (the cgroup has no controller for it)",
            ]
        );
        // Turned off since the start: said apart from what the cgroup never
        // had, with what follows from it.
        let v = json!({"memory_mb": 1, "memory_max_mb": 2, "cpu_percent": 3,
                       "cpu_max_percent": 4, "processes": 5, "processes_max": 6,
                       "cgroup": "/", "enforced": [], "lost": ["memory", "processes"],
                       "off": null});
        assert_eq!(
            limits_lines(&v)[1..],
            [
                "limits held by the cgroup /: none; not cpu (the cgroup has no controller for it)",
                "NO COMMAND RUNS: memory, processes turned off in the cgroup since the node started; start the node again",
            ]
        );
    }

    /// Setup restarts a node that found no keyring also when the keyring
    /// answers without setup installing it, e.g. installed by hand.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_node_that_found_no_keyring_is_restarted_when_one_answers_setup() {
        let (d, paths) = setup(&[]);
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let node = {
            let (home, paths) = (d.path().to_path_buf(), paths.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                // This node asked a keyring that was not there yet, and
                // keeps that answer.
                crate::secrets::store::set_unreachable(true);
                assert!(crate::secrets::store::get("any").is_err());
                let mut opts = NodeOptions::new(paths);
                opts.home = home;
                opts.full_rights = Some(false);
                let daemon = rt.block_on(Daemon::start(opts)).unwrap();
                ready_tx.send(()).unwrap();
                rt.block_on(async {
                    while stop_rx.try_recv().is_err() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    daemon.stop().await;
                });
            })
        };
        ready.recv().unwrap();
        // The keyring answers setup: nothing to install.
        let k = crate::keyring_setup::tests::FakeKeyring::new(true);
        let (r, _) = setup_keyring(&paths, None, None, &k, "\nkeyring\n");
        let e = r.unwrap_err();
        assert!(
            e.contains("restart it, then run `nerve-node setup` again"),
            "{e}"
        );
        assert!(k.installed.borrow().is_empty());
        let sys = crate::service::tests::Fake::new();
        // Name, the account question of the installed node, the keys.
        let (r, out) = setup_keyring(&paths, Some(&sys), None, &k, "\n\nkeyring\n");
        assert!(
            sys.calls()
                .contains(&format!("systemctl restart {}", crate::service::UNIT_NAME)),
            "{:?} {r:?} {out}",
            sys.calls()
        );
        stop.send(()).unwrap();
        node.join().unwrap();
    }

    /// The running node says in its status whether it found no keyring.
    #[cfg(unix)]
    #[test]
    fn the_status_says_whether_the_node_found_no_keyring() {
        let (d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        assert_eq!(daemon.status()["keyring_failed"], false);
        crate::secrets::store::set_unreachable(true);
        assert!(crate::secrets::store::get("any").is_err());
        assert_eq!(daemon.status()["keyring_failed"], true);
        crate::secrets::store::set_unreachable(false);
        rt.block_on(daemon.stop());
    }

    /// A node whose keys are in a keyring that no longer answers: setup
    /// asks about that before anything else, and a no stops it.
    #[test]
    fn setup_on_keys_in_a_keyring_that_does_not_answer_asks_first() {
        let (_d, paths) = setup(&[]);
        run(
            &paths,
            &["config", "set", "machine.secret_storage", "keyring"],
        )
        .unwrap();
        crate::secrets::store::set_unreachable(true);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let (r, out) = setup_keyring(&paths, None, None, &k, "\n");
        assert!(r.unwrap_err().contains("no system keyring answers"));
        assert!(!out.contains("Name of this node"), "{out}");
        assert!(run(&paths, &["status"]).is_err());
        let (r, out) = setup_keyring(&paths, None, None, &k, "y\n\n\n\n");
        r.unwrap();
        assert!(out.contains("Name of this node"), "{out}");
        assert!(run(&paths, &["status"]).is_ok());
    }

    #[test]
    fn setup_without_a_center_stops_after_the_name() {
        let (_d, paths) = setup(&[]);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("No center is paired"), "{out}");
        let (_d, paths) = setup(&["a", "b"]);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(out.contains("Several centers are paired"), "{out}");
        // A link that does not parse pairs nothing.
        let (r, _) = setup_with(&paths, "\n\nnot a link\n");
        assert!(r.unwrap_err().contains("nerve://pair"));
    }

    /// A control socket whose queue is full and that nothing accepts from: a
    /// node that runs but takes no connection now. Dropped, the socket is
    /// gone with it.
    #[cfg(unix)]
    struct BusyNode {
        _listener: std::os::unix::net::UnixListener,
        _queued: Vec<tokio::net::UnixStream>,
    }

    #[cfg(unix)]
    impl BusyNode {
        async fn start(paths: &NodePaths) -> BusyNode {
            use std::os::unix::io::AsRawFd;
            let sock = paths.ctl_socket();
            std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
            let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            // SAFETY: listen on a socket this test owns; a backlog of one is
            // full after a few connections, and nothing accepts them.
            assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
            let mut queued = vec![];
            while let Ok(s) = tokio::net::UnixStream::connect(&sock).await {
                queued.push(s);
                assert!(queued.len() < 100, "the queue never filled");
            }
            BusyNode {
                _listener: listener,
                _queued: queued,
            }
        }

        fn stop(self, paths: &NodePaths) {
            drop(self);
            std::fs::remove_file(paths.ctl_socket()).unwrap();
        }
    }

    /// A node that runs but takes no connection now (its queue is full) is
    /// not "not running": `panic` and `sudo off` must not write the file and
    /// report the change as done while the node never got it.
    #[cfg(unix)]
    #[test]
    fn a_busy_node_is_not_taken_for_none() {
        let (_d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(BusyNode::start(&paths));
        let before = std::fs::read(paths.config_file()).unwrap();
        let busy = nerve_transport::ctl::BUSY;
        for args in [
            &["panic"][..],
            &["sudo", "off"],
            &["rule", "add", "allow", "ls"],
        ] {
            let e = run(&paths, args).unwrap_err();
            assert_eq!(e, busy, "{args:?}");
        }
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert!(!load(&paths).locked);
        // Gone, the node is none, and the same commands go to the file.
        node.stop(&paths);
        run(&paths, &["panic"]).unwrap();
        assert!(load(&paths).locked);
    }

    /// A node that answers but keeps refusing the write with a conflict (the
    /// settings change under the CLI) is a node that did not get the change:
    /// `panic` fails and the file stays as it is. Writing the file here
    /// would be undone by the node's next write, with the change reported as
    /// made.
    #[cfg(unix)]
    #[test]
    fn a_node_that_always_answers_conflict_does_not_get_the_file_written() {
        use nerve_transport::ctl::{Reply, serve};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_d, paths) = setup(&["home"]);
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        let writes = std::sync::Arc::new(AtomicUsize::new(0));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (sock, counted) = (paths.ctl_socket(), writes.clone());
        rt.spawn(async move {
            let _ = serve(&sock, move |req, _| {
                let (text, counted) = (text.clone(), counted.clone());
                async move {
                    match req.method.as_str() {
                        "config.read" => Reply::Ok(json!({"config": text, "version": 7})),
                        "config.write" => {
                            counted.fetch_add(1, Ordering::SeqCst);
                            Reply::Err("conflict: the config changed (version 8)".into())
                        }
                        _ => Reply::Ok(json!({})),
                    }
                }
            })
            .await;
        });
        while !paths.ctl_socket().exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let before = std::fs::read(paths.config_file()).unwrap();
        let e = run(&paths, &["panic"]).unwrap_err();
        assert!(e.contains("keeps changing"), "{e}");
        assert_eq!(writes.load(Ordering::SeqCst), 5);
        assert_eq!(std::fs::read(paths.config_file()).unwrap(), before);
        assert!(!load(&paths).locked);
    }

    /// The callers that only ask whether a node runs take a busy one for a
    /// node: it is not told that a change waits for the next start, and a
    /// second node does not start beside it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_busy_node_still_counts_as_running() {
        let (d, paths) = setup(&["home"]);
        assert!(!daemon_answers(&paths, false).await);
        let node = BusyNode::start(&paths).await;
        assert!(daemon_answers(&paths, false).await);
        let mut out = Vec::new();
        after_keyring_answers(&paths, None, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("was not asked whether it found a keyring"),
            "{out}"
        );
        let cfg = NodeConfig::load(&paths.config_file()).unwrap();
        let mut out = Vec::new();
        tell_folder_commands(&paths, &cfg, &mut out).await;
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("was not asked whether folder mode"), "{out}");
        let mut opts = crate::NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let e = crate::Daemon::start(opts)
            .await
            .err()
            .expect("a second node");
        assert!(e.contains("already runs"), "{e}");
        node.stop(&paths);
        assert!(!daemon_answers(&paths, false).await);
        // A socket that cannot be reached at all is neither a node nor the
        // lack of one: the start says what is wrong.
        std::fs::remove_dir_all(paths.state_dir.join("run")).unwrap();
        std::fs::write(paths.state_dir.join("run"), b"").unwrap();
        assert!(!daemon_answers(&paths, false).await);
        let mut opts = crate::NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let e = crate::Daemon::start(opts).await.err().expect("no socket");
        assert!(e.contains("cannot tell whether a node runs"), "{e}");
        assert!(!e.contains("already runs"), "{e}");
    }

    /// With several centers the commands the ambiguous `rule rm` prints name
    /// the center, so they work as printed.
    #[test]
    fn the_rm_refusal_names_the_center_it_means() {
        let (_d, paths) = setup(&["home", "work"]);
        let made = "exec.run:exec.run:git [*]";
        for rule in ["exec.run:git *", made] {
            let list = "center.work.policy.allow";
            run(&paths, &["config", "add", list, rule]).unwrap();
        }
        let args = ["rule", "rm", "allow", "exec.run:git *", "--center", "work"];
        let e = run(&paths, &args).unwrap_err();
        assert!(
            e.contains(&format!("rule rm allow '{made}' --center work")),
            "{e}"
        );
        assert!(
            e.contains("rule rm allow 'exec.run:git *' --center work"),
            "{e}"
        );
        // Run as printed.
        run(&paths, &["rule", "rm", "allow", made, "--center", "work"]).unwrap();
        run(&paths, &args).unwrap();
        assert!(load(&paths).center("work").unwrap().policy.allow.is_empty());
    }

    #[test]
    fn the_three_lists_add_remove_and_show() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "rm *", "--wildcard"]).unwrap();
        run(
            &paths,
            &["rule", "add", "sudo", "sudo apt update", "--wildcard"],
        )
        .unwrap();
        // The sudo list takes the command without the sudo as well.
        run(&paths, &["rule", "add", "sudo", "systemctl restart nginx"]).unwrap();
        let p = load(&paths).centers[0].policy.clone();
        // Neither list loses a rule to the other; deny wins when they meet.
        assert_eq!(p.allow, ["exec.run:git status"]);
        assert_eq!(p.deny, ["exec.run:git status", "exec.run:rm *"]);
        assert_eq!(p.sudo_allow, ["sudo apt *", "sudo systemctl restart nginx"]);
        assert!(run(&paths, &["rule", "add", "allow", "  "]).is_err());
        // A sudo command is not an allow rule.
        let e = run(&paths, &["rule", "add", "allow", "sudo apt update"]).unwrap_err();
        assert!(e.contains("rule add sudo"), "{e}");
        // The `cap.action:pattern` form is for `config add`; as a command it
        // would become a rule that never matches.
        for list in ["allow", "deny"] {
            let e = run(&paths, &["rule", "add", list, "exec.run:echo *"]).unwrap_err();
            assert!(e.contains("config add"), "{e}");
        }
        let e = run(&paths, &["rule", "add", "allow", "fs.read:~/notes/*"]).unwrap_err();
        assert!(e.contains("policy.allow"), "{e}");
        // So is the form with a capability alone, which the docs show.
        for (list, rule) in [("deny", "fs:~/private/*"), ("allow", "exec:git *")] {
            let e = run(&paths, &["rule", "add", list, rule]).unwrap_err();
            assert!(e.contains("config add"), "{e}");
        }
        assert_eq!(
            load(&paths).centers[0].policy.allow,
            ["exec.run:git status"]
        );
        // With the working rule on the list as well (added as the refusal
        // says), the arguments name neither of the two: the user picks one.
        let broken = "exec.run:fs:~/private/[*]";
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", broken],
        )
        .unwrap();
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "fs:~/private/*"],
        )
        .unwrap();
        let e = run(&paths, &["rule", "rm", "deny", "fs:~/private/*"]).unwrap_err();
        assert!(
            e.contains(broken) && e.contains("\"fs:~/private/*\""),
            "{e}"
        );
        // The refusal's own instructions work, also for an entry as `ls`
        // shows the working one.
        assert!(
            e.contains(&format!("rule rm deny '{broken}' --center home")),
            "{e}"
        );
        let out = run(&paths, &["rule", "rm", "deny", broken]).unwrap();
        assert!(out.contains(broken), "{out}");
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            ["exec.run:git status", "exec.run:rm *", "fs:~/private/*"]
        );
        run(&paths, &["rule", "rm", "deny", "fs:~/private/*"]).unwrap();
        for rule in ["exec.run:git *", "exec.run:exec.run:git [*]"] {
            let list = "center.home.policy.allow";
            run(&paths, &["config", "add", list, rule]).unwrap();
        }
        let e = run(&paths, &["rule", "rm", "allow", "exec.run:git *"]).unwrap_err();
        assert!(
            e.contains("rule rm allow 'exec.run:exec.run:git [*]'"),
            "{e}"
        );
        run(
            &paths,
            &["rule", "rm", "allow", "exec.run:exec.run:git [*]"],
        )
        .unwrap();
        run(&paths, &["rule", "rm", "allow", "exec.run:git *"]).unwrap();
        // A colon in a command that is not a scope stays a command.
        run(&paths, &["rule", "add", "allow", "C:\\tools\\x.exe"]).unwrap();
        run(&paths, &["rule", "rm", "allow", "C:\\tools\\x.exe"]).unwrap();
        // The rule an older `rule add` made of the pattern form goes with the
        // arguments that made it.
        let broken = "exec.run:exec.run:echo [*]";
        run(
            &paths,
            &["config", "add", "center.home.policy.allow", broken],
        )
        .unwrap();
        run(&paths, &["rule", "rm", "allow", "exec.run:echo *"]).unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.allow,
            ["exec.run:git status"]
        );
        // A command with a glob character in it is allowed as itself.
        run(&paths, &["rule", "add", "allow", "rm *"]).unwrap();
        assert!(load(&paths).centers[0].policy.allow[1].contains("[*]"));
        // Rules for other actions go in through `config add` and show in `ls`.
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
        let ls = run(&paths, &["rule", "ls", "allow"]).unwrap();
        assert_eq!(ls.lines().count(), 3, "{ls}");
        assert!(ls.contains("fs.read:~/notes/*"), "{ls}");
        // rm takes the command like add, or an entry as ls shows it.
        run(&paths, &["rule", "rm", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "rm", "allow", "fs.read:~/notes/*"]).unwrap();
        run(&paths, &["rule", "rm", "deny", "rm *", "--wildcard"]).unwrap();
        run(&paths, &["rule", "rm", "sudo", "apt update", "--wildcard"]).unwrap();
        let p = load(&paths).centers[0].policy.clone();
        assert_eq!(p.allow.len(), 1, "{:?}", p.allow);
        assert_eq!(p.deny, ["exec.run:git status"]);
        assert_eq!(p.sudo_allow, ["sudo systemctl restart nginx"]);
        // Something that is not on the list is an error.
        let e = run(&paths, &["rule", "rm", "deny", "ls"]).unwrap_err();
        assert!(e.contains("not on the deny rule"), "{e}");
        let ls = run(&paths, &["rule", "ls", "sudo"]).unwrap();
        assert_eq!(ls, "sudo systemctl restart nginx\n");
        // Without a list, `ls` shows all three, each line with its list.
        let all = run(&paths, &["rule", "ls"]).unwrap();
        assert!(all.contains("deny  exec.run:git status\n"), "{all}");
        assert!(
            all.contains("sudo  sudo systemctl restart nginx\n"),
            "{all}"
        );
        run(&paths, &["rule", "rm", "sudo", "systemctl restart nginx"]).unwrap();
        let ls = run(&paths, &["rule", "ls", "sudo"]).unwrap();
        assert!(ls.contains("nothing on the sudo allow list"), "{ls}");
    }

    #[test]
    fn caps_and_proxy_show_what_is_set() {
        let (_d, paths) = setup(&["home"]);
        assert!(
            run(&paths, &["cap", "ls"])
                .unwrap()
                .contains("no capability")
        );
        run(&paths, &["cap", "set", "exec", "hidden"]).unwrap();
        assert_eq!(run(&paths, &["cap", "ls"]).unwrap(), "exec  hidden\n");
        assert_eq!(run(&paths, &["proxy", "ls"]).unwrap(), "no proxy\n");
        run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
            ],
        )
        .unwrap();
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert!(
            ls.contains("http://127.0.0.1:3128") && ls.contains("X-Key"),
            "{ls}"
        );
        assert!(!ls.contains("s3cret"), "{ls}");
        run(&paths, &["proxy", "rm"]).unwrap();
        assert_eq!(run(&paths, &["proxy", "ls"]).unwrap(), "no proxy\n");
    }

    /// What the test keyring holds for the node at `paths`.
    fn keyring_entry(paths: &NodePaths) -> Option<String> {
        let entry = crate::secrets::Entry::proxy(paths);
        crate::secrets::store::get(entry.account()).unwrap()
    }

    #[test]
    fn proxy_set_keeps_header_values_in_the_keyring_not_in_node_toml() {
        let (_d, paths) = setup(&["home"]);
        let out = run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
                "--header",
                "X-Other:  two words ",
            ],
        )
        .unwrap();
        assert!(
            out.contains("header X-Key") && out.contains("header X-Other"),
            "{out}"
        );
        assert!(!out.contains("s3cret"), "{out}");
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !file.contains("s3cret") && !file.contains("two words"),
            "{file}"
        );
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(cfg.connection.headers, ["X-Key", "X-Other"]);
        let held: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&keyring_entry(&paths).unwrap()).unwrap();
        assert_eq!(held["X-Key"], "s3cret-value");
        assert_eq!(held["X-Other"], "two words");
        // A proxy without headers needs no entry; the old one goes.
        run(&paths, &["proxy", "set", "http://127.0.0.1:3129"]).unwrap();
        assert_eq!(keyring_entry(&paths), None);
        assert!(load(&paths).connection.headers.is_empty());
    }

    #[test]
    fn a_user_and_password_in_the_url_go_to_the_keyring() {
        let (_d, paths) = setup(&["home"]);
        let out = run(
            &paths,
            &["proxy", "set", "http://alice:pa%40ss-w0rd@127.0.0.1:3128"],
        )
        .unwrap();
        assert!(!out.contains("pa%40ss") && !out.contains("alice"), "{out}");
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !file.contains("alice") && !file.contains("pa%40ss"),
            "{file}"
        );
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(cfg.connection.headers, [PROXY_AUTHORIZATION]);
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:pa@ss-w0rd");
        assert!(!file.contains(&basic), "{file}");
        let held: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&keyring_entry(&paths).unwrap()).unwrap();
        assert_eq!(held[PROXY_AUTHORIZATION], format!("Basic {basic}"));
        // Both ways at once is refused, and so is a bad URL, without quoting it.
        let both = [
            "proxy",
            "set",
            "http://alice:s3cret@127.0.0.1:3128",
            "--header",
            "proxy-authorization: Basic x",
        ];
        assert!(run(&paths, &both).unwrap_err().contains("not both"));
        for bad in [
            "alice:s3cret@127.0.0.1:3128",
            "http://alice:s3cret@127.0.0.1:3128/path",
            "https://alice:s3cret@127.0.0.1:3128/path",
            "http://alice:s3cr%zzet@127.0.0.1:3128",
        ] {
            let e = run(&paths, &["proxy", "set", bad]).unwrap_err();
            assert!(!e.contains("s3cr"), "{bad}: {e}");
        }
        // A --header without its colon is not quoted either.
        let e = run(
            &paths,
            &["proxy", "set", "http://127.0.0.1:1", "--header", "s3cret"],
        )
        .unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
    }

    #[test]
    fn a_node_toml_with_header_values_is_refused_with_run_proxy_set_again() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            paths.config_file(),
            "[connection]\nproxy = \"http://127.0.0.1:3128\"\nheaders = { X-Key = \"s3cret-value\" }\n",
        )
        .unwrap();
        for args in [&["proxy", "ls"][..], &["status"]] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains("run `nerve-node proxy set` again"), "{e}");
            assert!(!e.contains("s3cret"), "{e}");
        }
    }

    /// `relay add` shows a node's token once, with the line its node runs
    /// (an https:// proxy with the relay's pin), and `node.toml` keeps only
    /// the token's hash; the relay's TLS key is kept with the node's keys;
    /// `set`, `set-centers`, `rm` and `off` change the relay and nothing
    /// else.
    #[test]
    fn relay_add_shows_the_token_once_and_keeps_only_its_hash() {
        let (_d, paths) = setup(&["home", "work"]);
        // home and its neighbour share one address, behind one proxy.
        let mut cfg = load(&paths);
        cfg.centers[0].url = "https://h.example/a".into();
        cfg.centers[1].url = "https://w.example".into();
        let mut neighbour = entry("home-b");
        neighbour.url = "https://H.example:443/b".into();
        cfg.centers.push(neighbour);
        cfg.save(&paths.config_file()).unwrap();
        let paired = load(&paths).centers;
        let out = run(
            &paths,
            &["relay", "set", "0.0.0.0:7490", "--max-links", "8"],
        )
        .unwrap();
        let pin = load(&paths).relay.pin.expect("a pin");
        assert!(
            out.starts_with(&format!(
                "relay on 0.0.0.0:7490: at most 8 tunnels, 4 per node, 30 opened a minute per node\nits TLS certificate has the pin {pin}\nno node may use it yet"
            )),
            "{out}"
        );
        let id = crate::secrets::relay_tls(&paths, SecretStorage::File)
            .unwrap()
            .expect("the relay's TLS key");
        assert_eq!(id.pin(), pin);
        assert!(paths.relay_tls_file().exists());
        // Again: the same certificate.
        run(
            &paths,
            &[
                "relay",
                "set",
                "0.0.0.0:7491",
                "--max-opens-per-minute",
                "300",
            ],
        )
        .unwrap();
        assert_eq!(load(&paths).relay.max_opens_per_minute, 300);
        assert!(
            run(
                &paths,
                &[
                    "relay",
                    "set",
                    "0.0.0.0:7491",
                    "--max-opens-per-minute",
                    "0"
                ]
            )
            .is_err()
        );
        assert_eq!(load(&paths).relay.pin.as_deref(), Some(pin.as_str()));
        let e = run(&paths, &["relay", "set", "relay.example:7490"]).unwrap_err();
        assert!(e.contains("relay.listen"), "{e}");
        assert_eq!(load(&paths).relay.listen.as_deref(), Some("0.0.0.0:7491"));

        let out = run(&paths, &["relay", "add", "lab-pc"]).unwrap();
        let token = out.lines().nth(1).unwrap().trim().to_string();
        assert_eq!(token.len(), 43, "{out}");
        assert!(
            out.contains(&format!(
                "it may reach every https center of this node\non lab-pc, run:\n  nerve-node proxy set 'https://lab-pc:{token}@<address of this machine>:7491' --pin {pin}\n"
            )),
            "{out}"
        );
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(!file.contains(&token), "{file}");
        let cfg = load(&paths);
        let node = cfg.relay.node("lab-pc").unwrap();
        assert_eq!(node.token_sha256, crate::relay::token_hash(&token));
        assert!(node.centers.is_empty());
        assert_eq!(cfg.centers, paired);
        let e = run(&paths, &["relay", "add", "lab-pc"]).unwrap_err();
        assert!(e.contains("relay rm lab-pc"), "{e}");
        assert!(run(&paths, &["relay", "add", "Lab PC"]).is_err());

        // A node limited to some centers; only paired ones can be named.
        // A list that splits one address is refused: the relay cannot keep
        // the two apart.
        let e = run(&paths, &["relay", "add", "lab-2", "--center", "home"]).unwrap_err();
        assert!(e.contains("home and home-b share one host and port"), "{e}");
        assert!(load(&paths).relay.node("lab-2").is_none());
        let out = run(&paths, &["relay", "add", "lab-2", "--center", "work"]).unwrap();
        assert!(out.contains("it may reach the centers work\n"), "{out}");
        assert_eq!(load(&paths).relay.node("lab-2").unwrap().centers, ["work"]);
        let e = run(&paths, &["relay", "add", "lab-3", "--center", "elsewhere"]).unwrap_err();
        assert!(e.contains("no center named elsewhere"), "{e}");
        assert!(load(&paths).relay.node("lab-3").is_none());
        let out = run(
            &paths,
            &[
                "relay",
                "set-centers",
                "lab-2",
                "--center",
                "work",
                "--center",
                "home",
                "--center",
                "home-b",
            ],
        )
        .unwrap();
        assert!(
            out.starts_with("relay node lab-2 may reach the centers work, home, home-b\n"),
            "{out}"
        );
        assert!(
            run(
                &paths,
                &["relay", "set-centers", "nobody", "--center", "home"]
            )
            .is_err()
        );

        // A node of its own limits, for a relay behind this one.
        let out = run(
            &paths,
            &[
                "relay",
                "set-limits",
                "lab-2",
                "--max-links",
                "12",
                "--max-opens-per-minute",
                "300",
            ],
        )
        .unwrap();
        assert!(
            out.starts_with("relay node lab-2: at most 12 tunnels at once, 300 opened a minute (the relay's 8 tunnels in all bound it;"),
            "{out}"
        );
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(
            (node.max_links, node.max_opens_per_minute),
            (Some(12), Some(300))
        );
        // One flag sets that limit and keeps the other, as `relay set` does.
        run(
            &paths,
            &["relay", "set-limits", "lab-2", "--max-links", "20"],
        )
        .unwrap();
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(
            (node.max_links, node.max_opens_per_minute),
            (Some(20), Some(300))
        );
        run(
            &paths,
            &["relay", "set-limits", "lab-2", "--max-links", "12"],
        )
        .unwrap();
        // A new token keeps the node's centers and limits; the old one
        // stops working.
        let before = load(&paths).relay.node("lab-2").unwrap().clone();
        let out = run(&paths, &["relay", "token", "lab-2"]).unwrap();
        let token2 = out.lines().nth(1).unwrap().trim().to_string();
        assert_eq!(token2.len(), 43, "{out}");
        assert!(
            out.contains("it may reach the centers work, home, home-b\n"),
            "{out}"
        );
        let after = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(after.token_sha256, crate::relay::token_hash(&token2));
        assert_ne!(after.token_sha256, before.token_sha256);
        assert_eq!(
            (&after.centers, after.max_links, after.max_opens_per_minute),
            (
                &before.centers,
                before.max_links,
                before.max_opens_per_minute
            )
        );
        assert!(
            !std::fs::read_to_string(paths.config_file())
                .unwrap()
                .contains(&token2)
        );
        assert!(run(&paths, &["relay", "token", "nobody"]).is_err());
        // The flag's help sends a chain to `set-limits`, not to the
        // relay-wide budget.
        let help = Cli::command()
            .find_subcommand_mut("relay")
            .unwrap()
            .find_subcommand_mut("set")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("relay set-limits <name>"), "{help}");
        assert!(!help.contains("more for a relay behind this one"), "{help}");
        assert_eq!(
            load(&paths).relay.max_links_per_node,
            4,
            "the relay's stays"
        );
        assert!(
            run(
                &paths,
                &["relay", "set-limits", "lab-2", "--max-links", "0"]
            )
            .is_err()
        );
        assert!(
            run(
                &paths,
                &["relay", "set-limits", "nobody", "--max-links", "2"]
            )
            .is_err()
        );
        let ls = run(&paths, &["relay", "ls"]).unwrap();
        assert!(
            ls.contains("node lab-2: the centers work, home, home-b; its own limits: 12 tunnels at once, 300 opened a minute\n"),
            "{ls}"
        );
        run(&paths, &["relay", "set-limits", "lab-2"]).unwrap();
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!((node.max_links, node.max_opens_per_minute), (None, None));

        let ls = run(&paths, &["relay", "ls"]).unwrap();
        assert!(
            ls.starts_with(&format!(
                "relay on 0.0.0.0:7491\nat most 8 tunnels, 4 per node, 300 opened a minute per node\npin {pin}\nnode lab-pc: every https center of this node\nnode lab-2: the centers work, home, home-b\n"
            )),
            "{ls}"
        );
        assert!(!ls.contains(&token), "{ls}");
        run(&paths, &["relay", "set-centers", "lab-2"]).unwrap();
        assert!(load(&paths).relay.node("lab-2").unwrap().centers.is_empty());

        // A lost TLS key: relay add makes a new certificate and says so.
        std::fs::remove_file(paths.relay_tls_file()).unwrap();
        let out = run(&paths, &["relay", "add", "lab-4"]).unwrap();
        let new_pin = load(&paths).relay.pin.unwrap();
        assert_ne!(new_pin, pin);
        assert!(
            out.starts_with(&format!(
                "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {new_pin})"
            )),
            "{out}"
        );
        let out = run(&paths, &["relay", "add", "lab-5"]).unwrap();
        assert!(!out.contains("new certificate"), "{out}");

        let out = run(&paths, &["relay", "rm", "lab-pc"]).unwrap();
        assert!(out.starts_with("relay node lab-pc removed"), "{out}");
        assert!(load(&paths).relay.node("lab-pc").is_none());
        assert!(run(&paths, &["relay", "rm", "lab-pc"]).is_err());
        let out = run(&paths, &["relay", "off"]).unwrap();
        assert!(out.starts_with("relay off\n"), "{out}");
        let cfg = load(&paths);
        assert_eq!(cfg.relay.listen, None);
        assert_eq!(cfg.relay.max_links, 8);
        assert!(
            run(&paths, &["relay", "ls"])
                .unwrap()
                .starts_with("relay off\n")
        );
    }

    /// The login of an https:// proxy, a relay token, is kept where the
    /// node keeps its keys: its file by default, the keyring with
    /// `keyring`, which refuses clearly when it does not answer; never in
    /// node.toml, and `proxy rm` deletes it.
    #[test]
    fn an_https_proxy_login_is_kept_with_the_node_keys() {
        let pin = "A".repeat(43);
        let url = "https://lab:t0ken-value@127.0.0.1:7490";
        for storage in [SecretStorage::File, SecretStorage::Keyring] {
            let (_d, paths) = setup(&["home"]);
            if storage == SecretStorage::Keyring {
                let mut cfg = load(&paths);
                cfg.machine.secret_storage = storage;
                cfg.save(&paths.config_file()).unwrap();
            }
            let out = run(&paths, &["proxy", "set", url, "--pin", &pin]).unwrap();
            assert!(
                out.contains(&format!(
                    "pin {pin}\nlogin lab (its password is kept with the node's keys"
                )),
                "{out}"
            );
            assert!(!out.contains("t0ken"), "{out}");
            let cfg = load(&paths);
            assert_eq!(
                cfg.connection.proxy.as_deref(),
                Some("https://127.0.0.1:7490")
            );
            assert_eq!(cfg.connection.login.as_deref(), Some("lab"));
            assert!(cfg.connection.headers.is_empty());
            let toml = std::fs::read_to_string(paths.config_file()).unwrap();
            assert!(!toml.contains("t0ken"), "{toml}");
            assert_eq!(keyring_entry(&paths), None, "the header entry stays empty");
            let entry = crate::secrets::Entry::proxy_login(&paths);
            let in_keyring = crate::secrets::store::get(entry.account()).unwrap();
            let in_file = std::fs::read_to_string(paths.proxy_login_file()).ok();
            match storage {
                SecretStorage::File => {
                    assert_eq!(in_file.as_deref().map(str::trim), Some("t0ken-value"));
                    assert_eq!(in_keyring, None);
                }
                SecretStorage::Keyring => {
                    assert_eq!(in_keyring.as_deref(), Some("t0ken-value"));
                    assert_eq!(in_file, None);
                }
            }
            let ls = run(&paths, &["proxy", "ls"]).unwrap();
            assert!(ls.contains("login lab (its password is kept"), "{ls}");
            run(&paths, &["proxy", "rm"]).unwrap();
            assert_eq!(crate::secrets::store::get(entry.account()).unwrap(), None);
            assert!(!paths.proxy_login_file().exists());
            assert_eq!(load(&paths).connection, Default::default());
        }
        // With the keys in a keyring that does not answer, it refuses and
        // changes nothing, as for any key of the node.
        let (_d, paths) = setup(&["home"]);
        let mut cfg = load(&paths);
        cfg.machine.secret_storage = SecretStorage::Keyring;
        cfg.save(&paths.config_file()).unwrap();
        run(&paths, &["status"]).unwrap();
        crate::secrets::store::set_unreachable(true);
        let r = run(&paths, &["proxy", "set", url, "--pin", &pin]);
        crate::secrets::store::set_unreachable(false);
        let e = r.unwrap_err();
        assert!(e.contains("system keyring"), "{e}");
        assert!(!e.contains("t0ken"), "{e}");
        assert_eq!(load(&paths).connection, Default::default());
        assert!(!paths.proxy_login_file().exists());
        // A pin is for an https:// proxy only.
        let e = run(
            &paths,
            &["proxy", "set", "http://127.0.0.1:3128", "--pin", &pin],
        )
        .unwrap_err();
        assert!(e.contains("https"), "{e}");
    }

    #[test]
    fn proxy_ls_and_rm_with_and_without_a_keyring_entry() {
        let (_d, paths) = setup(&["home"]);
        let set = [
            "proxy",
            "set",
            "http://127.0.0.1:3128",
            "--header",
            "X-Key: s3cret-value",
        ];
        // With the entry: ls says the value is there, rm deletes it.
        run(&paths, &set).unwrap();
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert_eq!(
            ls,
            "proxy http://127.0.0.1:3128\nheader X-Key (its value is in the system keyring)\n"
        );
        let rm = run(&paths, &["proxy", "rm"]).unwrap();
        assert!(rm.contains("deleted the header values"), "{rm}");
        assert_eq!(keyring_entry(&paths), None);
        assert_eq!(run(&paths, &["proxy", "ls"]).unwrap(), "no proxy\n");

        // Without it: ls names the entry the link misses, rm still works.
        run(&paths, &set).unwrap();
        let entry = crate::secrets::Entry::proxy(&paths);
        crate::secrets::store::delete(entry.account()).unwrap();
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert!(ls.contains("header X-Key\n"), "{ls}");
        assert!(ls.contains(&format!("no entry {entry}")), "{ls}");
        let rm = run(&paths, &["proxy", "rm"]).unwrap();
        assert_eq!(
            rm,
            format!("no proxy\nthe change is in node.toml; it {NEXT_START}\n")
        );
        assert_eq!(load(&paths).connection, Default::default());

        // A proxy without headers never needs the keyring, reachable or not.
        crate::secrets::store::set_unreachable(true);
        let plain = run(&paths, &["proxy", "set", "http://127.0.0.1:3128"]);
        let ls = run(&paths, &["proxy", "ls"]);
        let rm = run(&paths, &["proxy", "rm"]);
        crate::secrets::store::set_unreachable(false);
        let next = format!("the change is in node.toml; it {NEXT_START}\n");
        assert_eq!(
            plain.unwrap(),
            format!("proxy http://127.0.0.1:3128\n{next}")
        );
        assert_eq!(ls.unwrap(), "proxy http://127.0.0.1:3128\n");
        assert_eq!(rm.unwrap(), format!("no proxy\n{next}"));
    }

    #[test]
    fn without_a_keyring_proxy_set_refuses_and_writes_no_value() {
        let (_d, paths) = setup(&["home"]);
        let before = std::fs::read_to_string(paths.config_file()).unwrap();
        crate::secrets::store::set_unreachable(true);
        let r = run(
            &paths,
            &[
                "proxy",
                "set",
                "http://alice:pa55w0rd@127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
            ],
        );
        crate::secrets::store::set_unreachable(false);
        let e = r.unwrap_err();
        assert!(
            e.contains("cannot store the proxy's header values in the system keyring"),
            "{e}"
        );
        assert!(e.contains(crate::secrets::store::NO_SERVICE), "{e}");
        assert!(!e.contains("s3cret") && !e.contains("pa55w0rd"), "{e}");
        // Nothing changed, and no value went to any file of the node.
        assert_eq!(
            std::fs::read_to_string(paths.config_file()).unwrap(),
            before
        );
        assert_eq!(keyring_entry(&paths), None);
        for dir in [&paths.config_dir, &paths.state_dir] {
            for f in files_below(dir) {
                let bytes = std::fs::read(&f).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("s3cret") && !text.contains("pa55w0rd"),
                    "{f:?}"
                );
            }
        }
    }

    /// The installed node on Windows runs as `nerve`, whose Credential
    /// Manager is not the administrator's that `proxy set` writes to. So
    /// a header or a password is refused, with the keyring left alone and
    /// nothing changed; a proxy that needs neither works, and its call
    /// takes an entry left by an earlier `proxy set` away.
    #[test]
    fn on_the_installed_node_on_windows_proxy_set_refuses_header_values_and_a_password() {
        let (_d, paths) = setup(&["home"]);
        // Set as an administrator before the node was installed.
        run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Old: o1d-value",
            ],
        )
        .unwrap();
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let before = std::fs::read_to_string(paths.config_file()).unwrap();
        let held = keyring_entry(&paths);
        assert!(held.is_some());
        let asked = crate::secrets::store::calls();
        for args in [
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3129",
                "--header",
                "X-Key: s3cret-value",
            ][..],
            &["proxy", "set", "http://alice:pa55w0rd@127.0.0.1:3129"],
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(
                e.contains(
                    "go to the Credential Manager of the account that runs it, not to that of nerve"
                ),
                "{e}"
            );
            assert!(e.contains("nothing was changed"), "{e}");
            assert!(e.contains("`nerve-node proxy set <url>`"), "{e}");
            assert!(!e.contains("s3cret") && !e.contains("pa55w0rd"), "{e}");
            assert!(!e.contains("alice"), "{e}");
        }
        // The keyring was not asked, and node.toml and the old entry stayed.
        assert_eq!(crate::secrets::store::calls(), asked);
        assert_eq!(
            std::fs::read_to_string(paths.config_file()).unwrap(),
            before
        );
        assert_eq!(keyring_entry(&paths), held);

        // The entry an administrator's keyring holds is not what the service
        // reads, so `proxy ls` does not call it good.
        let ls = run(&paths, &["proxy", "ls"]).unwrap();
        assert!(ls.contains("header X-Old\n"), "{ls}");
        assert!(!ls.contains("its value is in the system keyring"), "{ls}");
        assert!(ls.contains("the link cannot use this proxy"), "{ls}");
        assert!(ls.contains("the service does not find them"), "{ls}");
        assert!(!ls.contains("o1d-value"), "{ls}");

        // A proxy that needs neither works, and takes the old entry away.
        let next = format!("the change is in node.toml; it {NEXT_START}\n");
        let out = run(&paths, &["proxy", "set", "http://127.0.0.1:3129"]).unwrap();
        assert_eq!(out, format!("proxy http://127.0.0.1:3129\n{next}"));
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3129")
        );
        assert!(cfg.connection.headers.is_empty());
        assert_eq!(keyring_entry(&paths), None);
        assert_eq!(
            run(&paths, &["proxy", "ls"]).unwrap(),
            "proxy http://127.0.0.1:3129\n"
        );
        assert_eq!(
            run(&paths, &["proxy", "rm"]).unwrap(),
            format!("no proxy\n{next}")
        );
    }

    fn files_below(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_below(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    /// A buffer the test's log subscriber writes into (the one test that
    /// reads it is Unix only).
    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(unix)]
    impl std::io::Write for LogBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Everything the test process logs, from every thread. A subscriber
    /// for one thread or one test misses lines: tracing caches per call site
    /// whether anyone listens, and other tests' threads reach the same sites.
    #[cfg(unix)]
    fn process_logs() -> LogBuf {
        static LOGS: std::sync::OnceLock<LogBuf> = std::sync::OnceLock::new();
        LOGS.get_or_init(|| {
            let logs = LogBuf::default();
            let sink = logs.clone();
            tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(move || sink.clone())
                    .with_max_level(tracing::Level::TRACE)
                    .with_ansi(false)
                    .finish(),
            )
            .expect("no other test sets a global subscriber");
            logs
        })
        .clone()
    }

    /// `proxy set` through a running daemon: the audit log records the
    /// change, and neither it nor the log holds a value.
    #[cfg(unix)]
    #[test]
    fn no_secret_reaches_the_audit_log_or_the_log() {
        let logs = process_logs();
        let (d, paths) = setup(&["home"]);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        let set = [
            "proxy",
            "set",
            "http://alice:pa55w0rd@127.0.0.1:3128",
            "--header",
            "X-Key: s3cret-value",
        ];
        let out = run(&paths, &set).unwrap();
        assert_eq!(
            daemon.config().connection.headers,
            ["X-Key", PROXY_AUTHORIZATION]
        );
        // The running node took the change at once.
        assert!(!out.contains("next start"), "{out}");
        rt.block_on(daemon.stop());
        drop(rt);
        let audit = std::fs::read_to_string(paths.audit_log()).unwrap();
        assert!(audit.contains("connection.headers"), "{audit}");
        let logs = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        assert!(logs.contains("node daemon running"), "{logs}");
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:pa55w0rd");
        for (what, text) in [("audit", &audit), ("log", &logs), ("output", &out)] {
            for secret in ["s3cret", "pa55w0rd", &basic] {
                assert!(!text.contains(secret), "{what} holds {secret}: {text}");
            }
        }
    }

    /// The names of the commands, noun then verb: the first list parses, the
    /// second (single words and other orders) does not.
    #[test]
    fn the_commands_are_noun_then_verb() {
        let parses = |args: &[&str]| {
            let mut argv = vec!["nerve-node"];
            argv.extend(args);
            Cli::try_parse_from(argv).is_ok()
        };
        for ok in [
            &["center", "add", "nerve://x"][..],
            &["center", "rm"],
            &["center", "ls"],
            &["center", "pause"],
            &["center", "resume"],
            &["center", "grant", "settings", "write"],
            &["folder", "add", "/p", "+r"],
            &["folder", "set", "/p", "=rwx", "-w"],
            &["folder", "rm", "/p"],
            &["folder", "ls"],
            &["mode", "set", "user", "--for", "2"],
            &["rule", "add", "allow", "ls", "--wildcard"],
            &["rule", "rm", "deny", "ls"],
            &["rule", "ls", "sudo"],
            &["cap", "set", "fs", "on"],
            &["cap", "ls"],
            &["proxy", "set", "http://p:1"],
            &["proxy", "rm"],
            &["proxy", "ls"],
            &["config", "get", "limits"],
            &["sudo", "on"],
            &["sudo", "off"],
            &["sudo", "status"],
            &["audit", "--denied"],
            &["panic"],
            &["unlock"],
            &["status"],
            &["run"],
        ] {
            assert!(parses(ok), "{ok:?}");
        }
        for bad in [
            &["pair", "nerve://x"][..],
            &["unpair"],
            &["centers"],
            &["caps", "fs", "on"],
            &["grant", "settings", "write"],
            &["allow", "ls"],
            &["deny", "ls"],
            &["mode", "user"],
            &["mode", "user", "--hours", "2"],
            &["mode", "set", "user", "--hours", "2"],
            &["folder", "add", "/p", "--rw"],
            &["folder", "add", "/p", "--execute"],
            &["folder", "add", "/p", "--ro"],
            &["folder", "remove", "/p"],
            &["proxy", "clear"],
            &["sudo", "rule", "add", "x"],
            &["rule", "add", "x"],
            &["rule", "allow", "add", "x"],
            &["rule", "deny", "rm", "x"],
            &["rule", "sudo", "ls"],
            &["rule", "add", "allow"],
            &["rule", "add", "bogus", "x"],
            &["rule", "ls", "allow", "extra"],
        ] {
            assert!(!parses(bad), "{bad:?}");
        }
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
        assert!(names.len() > 40, "{names:?}");
        let h = help();
        // Every command is on a card, once: the ones that do something as a
        // verb, the ones that only hold more commands in the card's `holds`.
        let mut listed: Vec<String> = h.command_names().iter().map(|n| n.to_string()).collect();
        let mut want = names.clone();
        want.sort();
        listed.sort();
        assert_eq!(listed, want);
        for s in &h.sections {
            assert!(!s.about.is_empty(), "section `{}` has no sentence", s.name);
            assert!(!s.cards.is_empty(), "section `{}` is empty", s.name);
        }
        for v in h.verbs() {
            assert!(!v.about.is_empty(), "`{}` has no explanation", v.name);
            assert!(
                v.usage.starts_with(&format!("nerve-node {}", v.name)),
                "{}",
                v.usage
            );
        }
        // Every command is placed in SECTIONS, none in the catch-all.
        let names: Vec<&str> = h.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Install and set up",
                "Pair and connect",
                "What a center may do",
                "Run and watch",
            ]
        );
        // A noun is one card with its verbs; `rule` has the three lists as
        // an argument, not as three sub-trees.
        let card = |n: &str| {
            h.sections
                .iter()
                .flat_map(|s| &s.cards)
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("no card `{n}`"))
        };
        let rule = card("rule");
        let rule_verbs: Vec<&str> = rule.verbs.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(rule_verbs, ["rule add", "rule rm", "rule ls"]);
        assert_eq!(rule.holds, ["rule"]);
        assert!(
            rule.verbs[0].usage.contains("<LIST>"),
            "{}",
            rule.verbs[0].usage
        );
        assert!(
            rule.verbs[2].usage.contains("[LIST]"),
            "{}",
            rule.verbs[2].usage
        );
        assert_eq!(card("panic / unlock").verbs.len(), 2);
        assert_eq!(card("install / uninstall").verbs.len(), 2);
        assert_eq!(card("setup").verbs.len(), 1);
        assert_eq!(card("update").verbs.len(), 1);
        // What several verbs take alike is said once, on the card, and what
        // several cards take alike once on the page.
        let folder = card("folder");
        assert!(folder.shared_args.iter().any(|a| a.name == "<PATH>"));
        assert!(h.common.iter().any(|a| a.name == "--center <CENTER>"));
        let cards: Vec<&Card> = h.sections.iter().flat_map(|s| &s.cards).collect();
        for a in &h.common {
            assert!(cards.iter().all(|c| !c.shared_args.contains(a)));
            assert!(h.verbs().all(|v| !v.args.contains(a)));
        }
        // `config add` and `remove` take the key of a list, the other verbs
        // the key of any setting; each text is said once on the card.
        let key = card("config");
        let keys: Vec<&str> = key
            .shared_args
            .iter()
            .filter(|a| a.name == "<KEY>")
            .map(|a| a.about.as_str())
            .collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(
            keys.iter()
                .any(|k| k.contains("of a list") && k.contains(".policy.allow")),
            "{keys:?}"
        );
        assert!(keys.iter().any(|k| k.contains(".policy.mode")), "{keys:?}");
        // The rights of `folder add` are required, so the page does not call
        // them optional.
        let add = h.verbs().find(|v| v.name == "folder add").unwrap();
        assert!(
            add.args
                .iter()
                .any(|a| a.name == "<+r|+w|+x>" && !a.about.is_empty() && !a.optional),
            "{:?}",
            add.args
        );
        // What can be left out says so.
        let mode = h.verbs().find(|v| v.name == "mode set").unwrap();
        assert!(
            mode.args
                .iter()
                .any(|a| a.name == "--for <HOURS>" && a.optional)
        );
        assert!(mode.args.iter().any(|a| a.name == "<MODE>" && !a.optional));
        // The options every command takes are listed once, not per command.
        assert!(h.global.iter().any(|a| a.name.starts_with("--config-dir")));
        assert!(add.args.iter().all(|a| !a.name.starts_with("--config-dir")));
        // No usage line, and no explanation of a verb, is on the page twice.
        let mut usages: Vec<&str> = h.verbs().map(|v| v.usage.as_str()).collect();
        usages.sort();
        usages.dedup();
        assert_eq!(usages.len(), h.verbs().count());
        let mut abouts: Vec<&str> = h.verbs().map(|v| v.about.as_str()).collect();
        abouts.sort();
        let n = abouts.len();
        abouts.dedup();
        assert_eq!(abouts.len(), n, "two commands say the same");
    }

    /// The help page calls no command not done.
    #[test]
    fn no_command_is_called_not_done() {
        let text = Cli::command().render_help().to_string();
        assert!(!text.contains("not done"), "{text}");
        assert!(text.contains("install"), "{text}");
        let page = serde_json::to_string(&help()).unwrap();
        assert!(!page.to_lowercase().contains("not done"), "{page}");
    }

    #[test]
    fn every_argument_is_explained() {
        let h = help();
        let cards = h.sections.iter().flat_map(|s| &s.cards);
        for a in &h.common {
            assert!(!a.about.is_empty(), "{} has no explanation", a.name);
        }
        for c in cards.clone() {
            for a in &c.shared_args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    c.name,
                    a.name
                );
            }
        }
        for v in h.verbs() {
            for a in &v.args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    v.name,
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

    /// An audit line of a decision.
    fn decided(ts: u64, cap: &str, action: &str, target: &str, decision: &str) -> String {
        format!(
            "{}\n",
            serde_json::json!({"ts": ts, "center": "lab", "cap": cap, "action": action,
                "target": target, "decision": decision})
        )
    }

    /// After a rotation the older entries are in `audit.jsonl.1`; `audit`
    /// shows them before the current file's.
    #[test]
    fn audit_shows_the_rotated_file_too() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let old = paths.state_dir.join("audit.jsonl.1");
        std::fs::write(
            &old,
            decided(1, "fs", "read", "~/.ssh/id_ed25519", "allowed")
                + &decided(2, "exec", "run", "curl -d @~/notes x", "allowed"),
        )
        .unwrap();
        std::fs::write(
            paths.audit_log(),
            decided(3, "exec", "run", "ls", "forbidden"),
        )
        .unwrap();
        let out = run(&paths, &["audit"]).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(
            lines[0].contains("fs.read  ~/.ssh/id_ed25519  allowed"),
            "{out}"
        );
        assert!(lines[1].contains("curl -d @~/notes x  allowed"), "{out}");
        assert!(lines[2].contains("exec.run  ls  forbidden"), "{out}");
        let out = run(&paths, &["audit", "--denied"]).unwrap();
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains("ls  forbidden"), "{out}");
    }

    /// Output that a test reads while `audit --follow` writes it.
    #[derive(Clone, Default)]
    struct Seen(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Seen {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seen {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }

        async fn until(&self, what: &str) {
            for _ in 0..100 {
                if self.text().contains(what) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("{what:?} was not shown: {}", self.text());
        }
    }

    /// `--follow` goes on after the line it looked at last: also when the
    /// log dropped lines before it (old refusals), when the same line came
    /// again, and by time when that line itself was dropped.
    #[test]
    fn audit_follow_goes_on_after_the_last_line_it_saw() {
        let l = |ts: u64, t: &str| {
            decided(ts, "exec", "run", t, "forbidden")
                .trim()
                .to_string()
        };
        let mut shown = Shown::default();
        let first = vec![l(1, "a"), l(2, "b"), l(3, "c"), l(3, "c")];
        assert_eq!(shown.next(&first), 0);
        shown.saw(&first);
        // `a` and `b` were dropped; one more `c` and a `d` came.
        let now = vec![l(3, "c"), l(3, "c"), l(3, "c"), l(4, "d")];
        assert_eq!(&now[shown.next(&now)..], &now[2..]);
        shown.saw(&now);
        // `d` itself was dropped: what is newer than it is new.
        let now = vec![l(3, "c"), l(5, "e")];
        assert_eq!(&now[shown.next(&now)..], &now[1..]);
        shown.saw(&now);
        assert_eq!(shown.next(&now), now.len());
    }

    /// `--follow` finishes the old file after a rotation before it reads the
    /// new one: a line written right before the rotation is shown, and each
    /// line once.
    #[tokio::test]
    async fn audit_follow_finishes_the_old_file_after_a_rotation() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let log = paths.audit_log();
        let append = |line: String| {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .unwrap();
            f.write_all(line.as_bytes()).unwrap();
        };
        append(decided(1, "fs", "read", "first", "allowed"));
        let seen = Seen::default();
        let mut out = seen.clone();
        let follow = audit(&paths, true, false, &mut out);
        let writer = async {
            seen.until("first").await;
            append(decided(2, "fs", "read", "before-the-rotation", "allowed"));
            std::fs::rename(&log, paths.state_dir.join("audit.jsonl.1")).unwrap();
            append(decided(3, "fs", "read", "after-the-rotation", "allowed"));
            seen.until("after-the-rotation").await;
            // One more look, which must show nothing twice.
            tokio::time::sleep(Duration::from_millis(1200)).await;
        };
        tokio::select! {
            r = follow => panic!("follow ended: {r:?}"),
            () = writer => {}
        }
        let text = seen.text();
        let shown: Vec<&str> = text
            .lines()
            .map(|l| l.split("fs.read  ").nth(1).unwrap_or(l))
            .collect();
        assert_eq!(
            shown,
            [
                "first  allowed",
                "before-the-rotation  allowed",
                "after-the-rotation  allowed"
            ],
            "{text}"
        );
    }
}
