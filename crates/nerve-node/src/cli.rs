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
use nerve_policy::config::{Access, CapSetting, Folder, SettingsGrant};
use nerve_policy::{Mode, NodeConfig, SetError, SettingsStore, rules, sudo_command};
use nerve_proto::link::PairLink;
use nerve_sandbox::stubs::NOT_DONE;

use crate::daemon::{Daemon, NodeOptions};
use crate::paths::NodePaths;

#[derive(Debug, Parser)]
#[command(
    name = "nerve-node",
    version,
    about = "Links this machine to its Nerve centers.",
    after_help = "install, setup, update and uninstall are not done in 0.0.1: they only say so. Start the node by hand with `nerve-node run`."
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
    /// Install the node as a service.
    Install,
    /// Set up this machine for the node.
    Setup {
        /// Create a dedicated user for the node.
        #[arg(long)]
        create_user: bool,
    },
    /// Update the node.
    Update,
    /// Remove the node from this machine.
    Uninstall,
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
    /// Turn sudo on; asks for your sudo password and keeps it in memory only.
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
    /// Reach centers through an HTTP proxy. Header values and a password are kept in the system keyring, never in node.toml.
    Set {
        /// The proxy, http://host:port, or http://user:password@host:port when it wants a login.
        url: String,
        /// A header for the proxy, `Name: value`; can be given more than once. The value goes into the system keyring.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
    },
    /// Reach centers directly again, and delete the proxy's values from the system keyring.
    Rm,
    /// Show the proxy that is set and the names of its headers, never their values.
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
        "Pair and connect",
        "Link this machine to centers and choose how it reaches them.",
        &[&["center"], &["proxy"]],
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
    (
        "Not done yet",
        "These answer \"not done in 0.0.1\" and change nothing.",
        &[&["install", "setup", "update", "uninstall"]],
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

    /// The entry a command line stands for. The allow and deny lists hold
    /// `exec.run` rules; the sudo list holds the sudo command lines, and takes
    /// the command with or without the `sudo` in front.
    fn entry(self, command: &str, wildcard: bool) -> Result<String, String> {
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
            let name = edit_center(paths, &center, |e| {
                let l = list.of(&mut e.policy);
                // An entry copied from `ls` goes as it is, so rules for
                // files and other actions can be removed too.
                let rule = if l.contains(&command) {
                    command.clone()
                } else {
                    list.entry(&command, wildcard)?
                };
                let before = l.len();
                l.retain(|r| *r != rule);
                if l.len() == before {
                    return Err(format!("{rule:?} is not on the {}", list.label()));
                }
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "{name}: removed from the {}", list.label());
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
/// which has no socket in 0.0.1) is only in the file, so the output says
/// when it counts.
pub async fn execute(cli: Cli, out: &mut dyn Write) -> Result<(), String> {
    let paths = NodePaths::from_args(cli.config_dir, cli.state_dir);
    // The daemon writes the file itself while it runs.
    let before = (!matches!(cli.cmd, Cmd::Run)).then(|| std::fs::read(paths.config_file()).ok());
    let r = command(paths.clone(), cli.cmd, out).await;
    if r.is_ok()
        && let Some(before) = before
        && std::fs::read(paths.config_file()).ok() != before
        && !daemon_answers(&paths).await
    {
        let _ = writeln!(out, "the change is in node.toml; it {NEXT_START}");
    }
    r
}

/// Whether a daemon answers on the control socket; it then took every
/// change at once.
async fn daemon_answers(paths: &NodePaths) -> bool {
    #[cfg(unix)]
    {
        nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({}))
            .await
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
        false
    }
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
            if !yes && !confirm(out)? {
                return Err("not paired".into());
            }
            let e = crate::pair::pair(&paths, &link, name.as_deref()).await?;
            w(out, format!("paired with {} as {}", e.url, e.name));
            Ok(())
        }
        Cmd::Center(CenterCmd::Rm(center)) => {
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
            w(out, no_daemon_status(cfg!(unix)));
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
        }) => {
            let m = match mode.as_str() {
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
            let name = edit_center(&paths, &center, |e| {
                e.policy.mode = m;
                e.policy.until = until;
                Ok(())
            })
            .await?;
            w(out, format!("{name}: mode {}", m.as_str()));
            Ok(())
        }
        Cmd::Folder(FolderCmd::Add {
            path,
            rights,
            center,
        }) => {
            // Nothing is the default, and a folder that grants nothing is
            // never what was meant, so it is refused.
            let access = rights.iter().try_fold(Access::NONE, |a, r| {
                if r.starts_with('+') {
                    a.change(r)
                } else {
                    Err(format!("{r:?}: a new folder takes +r, +w or +x"))
                }
            })?;
            if access.is_none() {
                return Err(
                    "name what the center may do in the folder: +r (read), +w (write), +x (run commands)"
                        .into(),
                );
            }
            let real = resolve_folder(&path)?;
            let mode = std::cell::Cell::new(Mode::Folder);
            let name = edit_center(&paths, &center, |e| {
                e.policy.folders.retain(|f| f.path != real);
                e.policy.folders.push(Folder {
                    path: real.clone(),
                    access,
                });
                mode.set(e.policy.mode);
                Ok(())
            })
            .await?;
            w(out, format!("{name}: folder {real} {}", access.to_chmod()));
            let mode = mode.get();
            if mode != Mode::Folder {
                w(
                    out,
                    format!(
                        "note: folders count in folder mode; {name} is in {} mode (`nerve-node mode set folder`)",
                        mode.as_str()
                    ),
                );
            }
            Ok(())
        }
        Cmd::Folder(FolderCmd::Set {
            path,
            changes,
            center,
        }) => {
            let (changes, center) = take_center_flag(changes, center)?;
            let real = resolve_folder(&path)?;
            let given = path.display().to_string();
            let access = std::cell::Cell::new(Access::NONE);
            let name = edit_center(&paths, &center, |e| {
                let f = e
                    .policy
                    .folders
                    .iter_mut()
                    .find(|f| f.path == real || f.path == given)
                    .ok_or_else(|| format!("{real} is not a folder of this center"))?;
                f.access = changes.iter().try_fold(f.access, |a, c| a.change(c))?;
                access.set(f.access);
                Ok(())
            })
            .await?;
            let access = access.get();
            w(out, format!("{name}: folder {real} {}", access.to_chmod()));
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

/// `proxy set|rm|ls`. The header values, and a user name and password given
/// in the URL, go into the system keyring ([`crate::secrets`]); `node.toml`
/// keeps the URL without them and the header names. Nothing here prints,
/// logs or audits a value.
async fn proxy_cmd(paths: &NodePaths, c: ProxyCmd, out: &mut dyn Write) -> Result<(), String> {
    match c {
        ProxyCmd::Set { url, headers } => {
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
            nerve_transport::net::Proxy::parse(&url, hs.clone())?;
            let names: Vec<String> = hs.iter().map(|(k, _)| k.clone()).collect();
            // The keyring first: when it cannot take the values, node.toml
            // stays as it was rather than name headers nobody can send. A
            // proxy without headers leaves the keyring alone, unless the one
            // before had some: their entry would only linger.
            if !hs.is_empty() {
                crate::secrets::store_proxy_headers(paths, &hs)?;
            } else if !read_config(paths).await?.0.connection.headers.is_empty() {
                let _ = crate::secrets::remove_proxy_headers(paths);
            }
            edit(paths, |c| {
                c.connection.proxy = Some(url.clone());
                c.connection.headers = names.clone();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "proxy {url}");
            for n in &names {
                let _ = writeln!(out, "header {n} (its value is in the system keyring)");
            }
            Ok(())
        }
        ProxyCmd::Rm => {
            let (cfg, _) = read_config(paths).await?;
            edit(paths, |c| {
                c.connection.proxy = None;
                c.connection.headers.clear();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "no proxy");
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

const PROXY_AUTHORIZATION: &str = "Proxy-Authorization";

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
            "https://alice:s3cret@127.0.0.1:3128",
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

    /// The names of the commands, noun then verb; the first column is what
    /// parses, the second what each one was called before.
    #[test]
    fn the_commands_are_noun_then_verb_and_the_old_names_are_gone() {
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
        for old in [
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
            assert!(!parses(old), "{old:?}");
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
                "Pair and connect",
                "What a center may do",
                "Run and watch",
                "Not done yet"
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
        assert_eq!(card("install / setup / update / uninstall").verbs.len(), 4);
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

    #[test]
    fn the_root_help_says_which_commands_are_not_done() {
        let text = Cli::command().render_help().to_string();
        assert!(
            text.contains("install, setup, update and uninstall are not done in 0.0.1"),
            "{text}"
        );
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
}
