//! Allow and deny rules (docs/dev/policy-engine.md, spec node-local §3).
//!
//! A rule is `<scope>` or `<scope>:<pattern>`. The scope is a capability or
//! `cap.action`, as in `caps`. The pattern is a glob over the call's target:
//! the whole command line for `exec.run`, the resolved path for every `fs`
//! action (in the center's form, `/c/Users/x` on Windows, and `~/` is the
//! owner's home), and `<cap>.<action>` for any other action. `*` matches
//! across `/` and spaces. A rule without a pattern covers every target of its
//! scope.
//!
//! A pattern ending in ` *` also covers the bare program (`git *` covers
//! `git`), and one ending in `/*` the folder itself, so the wildcard the
//! buttons write covers what the owner clicked on. The audit buttons write
//! rules with [`rule_for`], the CLI with the same function.

use std::path::Path;

use globset::{GlobBuilder, GlobMatcher};

use crate::decide::sudo_command;
use crate::paths::to_wire;

/// The capability whose targets are paths.
const FS: &str = "fs";

/// Whether `s` is `cap` or `cap.action`: the shape of a `caps` key.
pub fn valid_scope(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').count() <= 2
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

fn split(rule: &str) -> Result<(&str, Option<&str>), String> {
    let (scope, pattern) = match rule.split_once(':') {
        Some((s, p)) => (s, Some(p)),
        None => (rule, None),
    };
    if !valid_scope(scope) {
        return Err(format!(
            "rule {rule:?}: it starts with `cap` or `cap.action`, then `:` and a pattern"
        ));
    }
    if pattern == Some("") {
        return Err(format!("rule {rule:?}: the pattern after `:` is empty"));
    }
    Ok((scope, pattern))
}

fn is_path_scope(scope: &str) -> bool {
    scope.split('.').next() == Some(FS)
}

fn build(pattern: &str, path: bool) -> Result<GlobMatcher, globset::Error> {
    // globset matches every target as a path and on Windows turns its `\`
    // into `/` first, so the pattern must too: else a rule with a `\` (most
    // Windows command lines have one) never matches, and a deny rule denies
    // nothing.
    let pattern = if cfg!(windows) {
        pattern.replace('\\', "/")
    } else {
        pattern.to_string()
    };
    GlobBuilder::new(&pattern)
        // NTFS ignores case; a Windows path rule must too.
        .case_insensitive(path && cfg!(windows))
        // `{,.exe}` is "nothing or `.exe`", as a reader takes it; globset
        // would drop the empty choice otherwise.
        .empty_alternates(true)
        .build()
        .map(|g| g.compile_matcher())
}

/// Checks a rule of the allow or deny list.
pub fn validate(rule: &str) -> Result<(), String> {
    let (scope, pattern) = split(rule)?;
    if let Some(p) = pattern {
        build(p, is_path_scope(scope)).map_err(|e| format!("rule {rule:?}: {e}"))?;
    }
    Ok(())
}

/// Checks an entry of the sudo allow list: a glob over the command line.
pub fn validate_command_glob(glob: &str) -> Result<(), String> {
    build(glob, false)
        .map(|_| ())
        .map_err(|e| format!("sudo rule {glob:?}: {e}"))
}

/// The pattern without the tail that stands for "and anything after":
/// ` *` after a program, `/*` or `/**` after a folder.
fn bare(pattern: &str, path: bool) -> Option<String> {
    if path {
        let rest = pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("/*"))?;
        Some(if rest.is_empty() { "/" } else { rest }.to_string())
    } else {
        pattern
            .strip_suffix(" *")
            .filter(|r| !r.is_empty())
            .map(str::to_string)
    }
}

/// The matchers of one pattern: itself and its bare form.
fn matchers(pattern: &str, path: bool) -> Vec<GlobMatcher> {
    let mut out = Vec::new();
    out.extend(build(pattern, path).ok());
    if let Some(b) = bare(pattern, path) {
        out.extend(build(&b, path).ok());
    }
    out
}

/// Whether `command` matches one of the globs `patterns` (the sudo allow
/// list).
pub fn command_matches(patterns: &[String], command: &str) -> bool {
    let command = command.trim();
    patterns
        .iter()
        .any(|p| matchers(p, false).iter().any(|m| m.is_match(command)))
}

/// Whether an allow rule of `rules` covers `cap.action` for some target: the
/// scope decides, the pattern does not. The rule may allow only some paths or
/// commands, so an action it covers is offered and each call is still checked.
/// A rule that does not parse covers nothing, as in [`RuleSet::new`].
pub fn offers(rules: &[String], cap: &str, action: &str) -> bool {
    rules.iter().any(|text| {
        validate(text).is_ok()
            && split(text).is_ok_and(|(scope, _)| match scope.split_once('.') {
                Some((c, a)) => c == cap && a == action,
                None => scope == cap,
            })
    })
}

struct Compiled {
    text: String,
    cap: String,
    action: Option<String>,
    /// The pattern with `~/` resolved; [`RuleSet::find_exact`] compares it.
    pattern: Option<String>,
    globs: Vec<GlobMatcher>,
}

/// An allow or deny list, compiled.
pub struct RuleSet {
    rules: Vec<Compiled>,
}

impl RuleSet {
    /// Compiles `rules`; one that does not parse is left out (the config
    /// check refuses them before they get here). `~/` in an `fs` pattern is
    /// `home`.
    pub fn new(rules: &[String], home: &Path) -> RuleSet {
        let home = to_wire(home);
        let rules = rules
            .iter()
            .filter_map(|text| {
                let (scope, pattern) = split(text).ok()?;
                let (cap, action) = match scope.split_once('.') {
                    Some((c, a)) => (c, Some(a)),
                    None => (scope, None),
                };
                let path = is_path_scope(scope);
                let pattern = pattern.map(|p| expand_home(p, &home, path));
                let globs = match &pattern {
                    Some(p) => {
                        let g = matchers(p, path);
                        if g.is_empty() {
                            return None;
                        }
                        g
                    }
                    None => Vec::new(),
                };
                Some(Compiled {
                    text: text.clone(),
                    cap: cap.into(),
                    action: action.map(Into::into),
                    pattern,
                    globs,
                })
            })
            .collect();
        RuleSet { rules }
    }

    /// The first rule that covers `target` of `cap.action`.
    pub fn find(&self, cap: &str, action: &str, target: &str) -> Option<&str> {
        self.rules
            .iter()
            .filter(|r| r.covers(cap, action))
            .find(|r| r.globs.is_empty() || r.globs.iter().any(|g| g.is_match(target)))
            .map(|r| r.text.as_str())
    }

    /// The first rule of this scope that names `target` and nothing else: one
    /// the "Allow" button writes, not a wildcard.
    pub fn find_exact(&self, cap: &str, action: &str, target: &str) -> Option<&str> {
        let want = escape(target);
        self.rules
            .iter()
            .filter(|r| r.covers(cap, action))
            .find(|r| r.pattern.as_deref() == Some(want.as_str()))
            .map(|r| r.text.as_str())
    }
}

impl Compiled {
    fn covers(&self, cap: &str, action: &str) -> bool {
        self.cap == cap && self.action.as_deref().is_none_or(|a| a == action)
    }
}

fn expand_home(pattern: &str, home: &str, path: bool) -> String {
    if !path {
        return pattern.to_string();
    }
    if pattern == "~" {
        escape(home)
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{}/{rest}", escape(home.trim_end_matches('/')))
    } else {
        pattern.to_string()
    }
}

/// `s` as a glob that matches exactly `s`: every character a glob reads is
/// put in a class of its own.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            out.push('[');
            out.push(c);
            out.push(']');
        } else {
            out.push(c);
        }
    }
    out
}

/// The rule an audit button writes for the entry `cap.action` with `target`
/// (the entry's `target` field): `wildcard` widens it to the program and
/// anything after it (`exec.run`), the folder and anything below it (`fs`),
/// or the whole capability (any other action).
pub fn rule_for(cap: &str, action: &str, target: &str, wildcard: bool) -> Result<String, String> {
    let scope = format!("{cap}.{action}");
    if !valid_scope(&scope) {
        return Err(format!("{scope:?} is not a capability and action"));
    }
    let target = target.trim();
    match (cap, action) {
        ("exec", "run") => {
            if target.is_empty() {
                return Err("no command".into());
            }
            let pattern = if wildcard {
                let program = target.split_whitespace().next().unwrap_or(target);
                format!("{} *", escape(program))
            } else {
                escape(target)
            };
            Ok(format!("{scope}:{pattern}"))
        }
        (FS, _) => {
            if !target.starts_with('/') {
                return Err(format!("{target:?} is not an absolute path"));
            }
            let pattern = if wildcard {
                let target = target.trim_end_matches('/');
                let folder = target.rfind('/').map_or("", |i| &target[..i]);
                format!("{}/*", escape(folder))
            } else {
                escape(target)
            };
            Ok(format!("{scope}:{pattern}"))
        }
        // No pattern: the rule is the action, or with a wildcard its capability.
        _ => Ok(if wildcard { cap.to_string() } else { scope }),
    }
}

/// A letter as a class of both cases, for the Windows commands: PowerShell
/// and cmd ignore case, and a rule's glob does not. Each macro is one word.
macro_rules! sc {
    () => {
        "[Ss][Cc]"
    };
}
macro_rules! net {
    () => {
        "[Nn][Ee][Tt]"
    };
}
macro_rules! exe {
    () => {
        "[Ee][Xx][Ee]"
    };
}
macro_rules! stop {
    () => {
        "[Ss][Tt][Oo][Pp]"
    };
}
macro_rules! config {
    () => {
        "[Cc][Oo][Nn][Ff][Ii][Gg]"
    };
}
macro_rules! delete {
    () => {
        "[Dd][Ee][Ll][Ee][Tt][Ee]"
    };
}
macro_rules! restart {
    () => {
        "[Rr][Ee][Ss][Tt][Aa][Rr][Tt]"
    };
}
macro_rules! set {
    () => {
        "[Ss][Ee][Tt]"
    };
}
macro_rules! remove {
    () => {
        "[Rr][Ee][Mm][Oo][Vv][Ee]"
    };
}
macro_rules! service {
    () => {
        "[Ss][Ee][Rr][Vv][Ii][Cc][Ee]"
    };
}
macro_rules! process {
    () => {
        "[Pp][Rr][Oo][Cc][Ee][Ss][Ss]"
    };
}
macro_rules! taskkill {
    () => {
        "[Tt][Aa][Ss][Kk][Kk][Ii][Ll][Ll]"
    };
}
macro_rules! desktop {
    () => {
        "[Dd][Ee][Ss][Kk][Tt][Oo][Pp]"
    };
}
macro_rules! node {
    () => {
        "[Nn][Ee][Rr][Vv][Ee]-[Nn][Oo][Dd][Ee]"
    };
}

/// Up to eight spaces, tabs or line breaks: the indent of a line in a script.
macro_rules! ws {
    () => {
        concat!(
            "{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}",
            "{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}{,[ \t\r\n]}"
        )
    };
}

/// The scope and where a command of the service rules starts: the line's
/// start or after `;`, `&`, `|`, `(` or a line break, then `sudo` and its
/// flags if the command begins with it. `sudo` counts only at a command's
/// start, so a quoted mention (`git commit -m "run sudo systemctl stop
/// nerve-node"`) runs.
macro_rules! command {
    () => {
        concat!("exec.run:{,*[;&|(\r\n]}", ws!(), "{,sudo ,sudo * }")
    };
}

/// What ends a name: the line's end, or a space, tab, line break, quote, `)`
/// or a character that chains the next command.
macro_rules! end {
    () => {
        "{,[ \t\r\n\"');&|]*}"
    };
}

/// [`end!`], and a comma, which ends a name in a PowerShell list.
macro_rules! end_ps {
    () => {
        "{,[ \t\r\n\"');,&|]*}"
    };
}

/// The deny rules every new pairing gets, the guard against an agent that
/// changes the node it runs on (owner's decision of 2026-10-20): a command
/// that runs the node's programs (at the start of a command, after `sudo`,
/// or by a path, `.exe` too), names its socket and pipes (all named
/// `nerve-node…`) or its config and state folders, and a write into those
/// folders, and a command that stops, restarts, disables or kills the node's
/// service or process by its name (`systemctl stop nerve-node`,
/// `service nerve-node restart`, `pkill nerve-node`, `sc stop nerve-node`,
/// `taskkill /im nerve-node.exe`). Only running or stopping it counts, not
/// its name anywhere: `cargo build -p nerve-node`, `journalctl -u nerve-node`
/// and `systemctl status nerve-node` stay allowed. They
/// are on top of the node's own folders, which nothing releases
/// (crate::protected). A deny rule matches the whole line, so they catch a
/// confused agent, not one that builds the name at run time: the real
/// protection is that commands run as an account of their own. The owner
/// may remove any of them.
pub const GUARD: &[&str] = &[
    // By name where a command starts: the line's start, after `;`, `&`,
    // `|`, `(` or a line break (with its indent), and after `sudo`; then the
    // line's end, a space, a tab, a line break or a quote.
    concat!(
        "exec.run:{,*[;&|(\r\n]}",
        ws!(),
        "{,*sudo }nerve-node{,-desktop}{,.exe}{,[ \t\r\n\"']*}"
    ),
    "exec.run:*[/\\]nerve-node{,-desktop}{,.exe}{,[ \t\r\n\"']*}",
    "exec.run:*/run/nerve-node{,/*,[ \t\r\n\"']*}",
    "exec.run:*[/\\][/\\].[/\\]pipe[/\\]nerve-node*",
    "exec.run:*/etc/nerve{,/*,[ \t\r\n\"']*}",
    "exec.run:*/var/lib/nerve{,/*,[ \t\r\n\"']*}",
    "exec.run:*.config/nerve{,/*,[ \t\r\n\"']*}",
    "exec.run:*.local/state/nerve{,/*,[ \t\r\n\"']*}",
    // `C:\ProgramData\Nerve`, `%ProgramData%\Nerve`, `$env:ProgramData\Nerve`:
    // the line's `\` is matched as `/` on Windows.
    "exec.run:*[Pp]rogram[Dd]ata*/[Nn]erve{,/*,[ \t\r\n\"']*}",
    // Stopping, restarting, disabling or killing the node's service or
    // process, by its name, with the same line starts (and the program's path).
    // Reading it stays allowed: `systemctl status`, `sc query`, `Get-Service`.
    concat!(
        command!(),
        "{,*[/\\]}systemctl{, *} {stop,restart,try-restart,reload-or-restart,disable,kill,mask} {,*[ \"']}nerve-node{,.service}",
        end!()
    ),
    concat!(
        command!(),
        "{,*[/\\]}",
        sc!(),
        "{,.",
        exe!(),
        "} {,*[ ]}{",
        stop!(),
        ",",
        config!(),
        ",",
        delete!(),
        "} {,*[ \"']}",
        node!(),
        end!()
    ),
    concat!(
        command!(),
        "{,*[/\\]}",
        net!(),
        "{,.",
        exe!(),
        "} ",
        stop!(),
        " {,*[ \"']}",
        node!(),
        end!()
    ),
    concat!(
        command!(),
        "{",
        stop!(),
        ",",
        restart!(),
        ",",
        set!(),
        ",",
        remove!(),
        "}-",
        service!(),
        "{, *}[ \"':=,]",
        node!(),
        end_ps!()
    ),
    concat!(
        command!(),
        "{,*[/\\]}",
        taskkill!(),
        "{,.",
        exe!(),
        "} *[ \"':=]",
        node!(),
        "{,-",
        desktop!(),
        "}{,.",
        exe!(),
        "}",
        end!()
    ),
    concat!(
        command!(),
        stop!(),
        "-",
        process!(),
        "{, *}[ \"':=,]",
        node!(),
        "{,-",
        desktop!(),
        "}{,.",
        exe!(),
        "}",
        end_ps!()
    ),
    // The same through a pipe: `Get-Service nerve-node | Stop-Service`.
    concat!(
        "exec.run:*[ \"'(,:=]",
        node!(),
        "{,-",
        desktop!(),
        "}{,.",
        exe!(),
        "}*|",
        ws!(),
        "{",
        stop!(),
        ",",
        restart!(),
        ",",
        set!(),
        ",",
        remove!(),
        "}-{",
        service!(),
        ",",
        process!(),
        "}",
        end_ps!()
    ),
    // The SysV wrapper, `service nerve-node stop` (it calls systemctl).
    concat!(
        command!(),
        "{,*[/\\]}service {,*[ \"']}nerve-node{,.service}{,[\"']} {stop,restart,try-restart,force-reload,condrestart}",
        end!()
    ),
    // By the process's name: `pkill nerve-node`, `killall -9 nerve-node`,
    // `pkill -f '^/usr/bin/nerve-node'`. `pgrep` and `ps` stay allowed.
    concat!(
        command!(),
        "{,*[/\\]}{pkill,killall} {,-* }{,[\"']}{,^}{,*/}nerve-node{,-desktop}{,[$\"']}",
        end!()
    ),
    "fs.write:~/.config/nerve/*",
    "fs.write:~/.local/state/nerve/*",
    "fs.write:/etc/nerve/*",
    "fs.write:/var/lib/nerve/*",
    "fs.write:/?/ProgramData/Nerve/*",
];

/// The texts of [`GUARD`] rules from before a line break ended a command,
/// which `rule guard` takes off a deny list when it puts the new ones on.
pub const GUARD_OLD: &[&str] = &[
    "exec.run:{,*[;&|(] ,*[;&|(],*sudo }nerve-node{,-desktop}{,.exe}{,[ \"']*}",
    "exec.run:*[/\\]nerve-node{,-desktop}{,.exe}{,[ \"']*}",
    "exec.run:*/run/nerve-node{,/*,[ \"']*}",
    "exec.run:*/etc/nerve{,/*,[ \"']*}",
    "exec.run:*/var/lib/nerve{,/*,[ \"']*}",
    "exec.run:*.config/nerve{,/*,[ \"']*}",
    "exec.run:*.local/state/nerve{,/*,[ \"']*}",
    "exec.run:*[Pp]rogram[Dd]ata*/[Nn]erve{,/*,[ \"']*}",
];

/// `rule` with its tab, carriage return and line feed written `\t`, `\r` and
/// `\n`, as `rule ls` and the app show it: a rule of the guard holds them
/// (they end a command in a script), and a listing keeps one line a rule.
pub fn escape_controls(rule: &str) -> String {
    let mut out = String::with_capacity(rule.len());
    for c in rule.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// The reverse of [`escape_controls`]: `\t`, `\r` and `\n` become the
/// character. A `\\` pair is kept as it is, so `[/\\]n` stays. A rule that
/// has a `\n` of its own (a path `C:\new`) is not for this: the callers use
/// it only on an entry that is not on the list as it stands.
pub fn unescape_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The rules of [`GUARD`] that `deny` lacks.
pub fn guard_missing(deny: &[String]) -> Vec<&'static str> {
    GUARD
        .iter()
        .copied()
        .filter(|g| !deny.iter().any(|d| d == g))
        .collect()
}

/// The sudo allow list entry for `command`: the command itself, or with
/// `wildcard` its leading words up to the program that follows `sudo` and
/// its flags, then anything after (`sudo apt *`). A bare `sudo *` would let
/// a click allow everything, so the wildcard keeps the program.
pub fn sudo_rule_for(command: &str, wildcard: bool) -> Result<String, String> {
    let command = command.trim();
    if sudo_command(command).is_none() {
        return Err(format!("{command:?} is not a sudo command"));
    }
    if !wildcard {
        return Ok(escape(command));
    }
    let mut words = Vec::new();
    for (i, w) in command.split_whitespace().enumerate() {
        words.push(w);
        if i > 0 && !w.starts_with('-') {
            break;
        }
    }
    Ok(format!("{} *", escape(&words.join(" "))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(rules: &[&str]) -> RuleSet {
        let rules: Vec<String> = rules.iter().map(|s| s.to_string()).collect();
        RuleSet::new(&rules, Path::new("/h"))
    }

    #[test]
    fn scope_and_pattern() {
        let s = set(&[
            "exec.run:git *",
            "fs:/w/*",
            "fs.write:/x/*",
            "camera.snap",
            "mic",
        ]);
        assert!(s.find("exec", "run", "git status").is_some());
        assert!(s.find("exec", "run", "git").is_some(), "the bare program");
        assert!(s.find("exec", "run", "gitk").is_none());
        assert!(s.find("exec", "run", "ls").is_none());
        // A path pattern never matches a command and the other way round.
        assert!(s.find("exec", "run", "/w/evil").is_none());
        assert!(s.find("fs", "read", "git status").is_none());
        assert!(s.find("fs", "read", "/w/a/b").is_some());
        assert!(s.find("fs", "list", "/w").is_some(), "the folder itself");
        assert!(s.find("fs", "read", "/x/a").is_none());
        assert!(s.find("fs", "write", "/x/a").is_some());
        assert!(s.find("camera", "snap", "camera.snap").is_some());
        assert!(s.find("camera", "record", "camera.record").is_none());
        assert!(s.find("mic", "listen", "mic.listen").is_some());
    }

    #[test]
    fn home_is_the_owners() {
        let s = set(&["fs:~/notes/*"]);
        assert!(s.find("fs", "read", "/h/notes/a").is_some());
        assert!(s.find("fs", "read", "/h/other").is_none());
        // `~` means nothing in a command.
        let s = set(&["exec.run:~/bin/*"]);
        assert!(s.find("exec", "run", "/h/bin/x").is_none());
    }

    #[test]
    fn bad_rules_are_refused() {
        for ok in ["fs:/a/*", "exec.run:git status", "camera.snap", "fs"] {
            validate(ok).unwrap();
        }
        for bad in [
            "",
            "~/private",
            "/home/u/x",
            "git status",
            "fs:",
            "fs.read.x:/a",
            "fs:/a/[",
            "exec.run:{a",
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
        assert!(validate_command_glob("sudo apt *").is_ok());
        assert!(validate_command_glob("sudo [").is_err());
    }

    #[test]
    fn escaping_matches_the_text_and_nothing_else() {
        for s in [
            "rm *",
            "ls [a-z]?",
            "echo {a,b}",
            "grep \\d x",
            "a]b}",
            "plain",
        ] {
            let g = build(&escape(s), false).unwrap();
            assert!(g.is_match(s), "{s}");
            assert!(!g.is_match(format!("{s}x")), "{s}");
        }
        assert!(!build(&escape("rm *"), false).unwrap().is_match("rm -rf /"));
        // A button's exact rule names that command only.
        let rule = rule_for("exec", "run", "rm *", false).unwrap();
        let s = set(&[&rule]);
        assert!(s.find("exec", "run", "rm *").is_some());
        assert!(s.find("exec", "run", "rm -rf /").is_none());
    }

    /// Windows command lines name paths with `\`; a rule for them matches
    /// (a `\` is an escape in a Unix glob, so this is Windows only).
    #[cfg(windows)]
    #[test]
    fn a_command_rule_with_backslashes_matches_on_windows() {
        let s = set(&["exec.run:Remove-Item C:\\data\\*"]);
        assert!(s.find("exec", "run", "Remove-Item C:\\data\\x").is_some());
        assert!(s.find("exec", "run", "Remove-Item C:\\other\\x").is_none());
        let exact = rule_for("exec", "run", "type C:\\x\\a.txt", false).unwrap();
        assert!(
            set(&[&exact])
                .find("exec", "run", "type C:\\x\\a.txt")
                .is_some()
        );
    }

    /// The guard of a new pairing refuses what drives the node itself,
    /// and leaves work near it alone.
    #[test]
    fn the_guard_refuses_the_node_itself() {
        let home = Path::new("/home/alice");
        let set = RuleSet::new(
            &GUARD.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
            home,
        );
        let run = |c: &str| set.find("exec", "run", c).is_some();
        for c in [
            "nerve-node config set machine.user root",
            "nerve-node",
            "sudo /usr/local/bin/nerve-node-desktop mode set user",
            "sudo nerve-node rule rm deny 'rm *'",
            "cd /tmp && nerve-node status",
            "cd /tmp;nerve-node-desktop status",
            "true | nerve-node audit",
            "(nerve-node.exe panic)",
            "./target/release/nerve-node-desktop mode set user",
            "& 'C:/Program Files/Nerve/nerve-node-desktop.exe' config set node.name x",
            "socat - UNIX-CONNECT:/run/nerve-node/owner.sock",
            "ls /run/nerve-node",
            "echo x > //./pipe/nerve-node-owner",
            "cat /etc/nerve/node.toml",
            "rm -rf /var/lib/nerve/state",
            "sed -i s/a/b/ ~/.config/nerve/node.toml",
            "ls $HOME/.local/state/nerve",
            "type %ProgramData%/Nerve/config/node.toml",
            // A line break or a tab ends a command and its name like a space,
            // and a script line may be indented.
            "cd /tmp\nnerve-node status",
            "cd /tmp\r\nnerve-node status",
            "nerve-node\necho x",
            "nerve-node\r\n",
            "echo hi\n  nerve-node status",
            "echo hi\n\tsudo nerve-node audit",
            "/usr/local/bin/nerve-node\tstatus",
            "/usr/local/bin/nerve-node\nls",
            "ls /run/nerve-node\n",
            "cat /etc/nerve\nls",
            "cat /var/lib/nerve\tx",
            "cat ~/.config/nerve\r\nls",
            "ls $HOME/.local/state/nerve\n",
            "type %ProgramData%/Nerve\r\ndir",
        ] {
            assert!(run(c), "should be refused: {c}");
        }
        for c in [
            "ls ~/.config",
            "cargo build -p nerve-node",
            "cargo test -p nerve-node-desktop --test shots",
            "journalctl -u nerve-node",
            "grep -r nerve-node docs/",
            "git commit -m 'run nerve-node status'",
            "cargo build --manifest-path crates/nerve-node/Cargo.toml",
            "cat ~/.config/nerve-node-desktop/settings.json",
            "ls /etc/nervecenter",
            "git status",
        ] {
            assert!(!run(c), "should stay allowed: {c}");
        }
        let write = |p: &str| set.find("fs", "write", p).is_some();
        assert!(write("/home/alice/.config/nerve/node.toml"));
        assert!(write("/etc/nerve/keys/home.key"));
        assert!(write("/var/lib/nerve/state/audit.jsonl"));
        assert!(write("/c/ProgramData/Nerve/config/node.toml"));
        assert!(!write("/home/alice/notes.md"));
        assert!(set.find("fs", "read", "/etc/nerve/node.toml").is_none());
        for g in GUARD {
            validate(g).unwrap();
        }
        let have = vec![GUARD[0].to_string(), "exec.run:rm *".to_string()];
        assert_eq!(guard_missing(&have), GUARD[1..].to_vec());
    }

    /// The guard's rules before a line break ended a command let a second
    /// line through; the new texts do not. `rule guard` replaces the old ones.
    #[test]
    fn the_old_guard_texts_missed_a_line_break_and_are_replaced() {
        let home = Path::new("/home/alice");
        let old = RuleSet::new(
            &GUARD_OLD.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
            home,
        );
        let new = RuleSet::new(
            &GUARD.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
            home,
        );
        for c in [
            "cd /tmp\nnerve-node status",
            "nerve-node\necho x",
            "echo hi\n  nerve-node status",
            "/usr/local/bin/nerve-node\nls",
            "ls /run/nerve-node\n",
            "cat /etc/nerve\nls",
            "cat /var/lib/nerve\tx",
            "cat ~/.config/nerve\r\nls",
            "ls $HOME/.local/state/nerve\n",
            "type %ProgramData%/Nerve\r\ndir",
        ] {
            assert!(old.find("exec", "run", c).is_none(), "old guard: {c}");
            assert!(new.find("exec", "run", c).is_some(), "new guard: {c}");
        }
        // What the old texts refused, the new ones refuse.
        for c in [
            "nerve-node status",
            "sudo nerve-node audit",
            "ls /etc/nerve/x",
        ] {
            assert!(old.find("exec", "run", c).is_some(), "old guard: {c}");
            assert!(new.find("exec", "run", c).is_some(), "new guard: {c}");
        }
        for o in GUARD_OLD {
            validate(o).unwrap();
            assert!(!GUARD.contains(o), "{o} is current");
        }
    }

    #[test]
    fn controls_are_written_out_and_read_back() {
        for rule in GUARD {
            let shown = escape_controls(rule);
            assert!(!shown.contains(['\t', '\r', '\n']), "{shown}");
            assert_eq!(unescape_controls(&shown), *rule);
        }
        assert_eq!(escape_controls("a\tb\r\nc"), "a\\tb\\r\\nc");
        assert_eq!(unescape_controls("a\\tb\\r\\nc"), "a\tb\r\nc");
        // A pair of backslashes stays, and so does a lone one.
        assert_eq!(unescape_controls("[/\\\\]n \\x \\"), "[/\\\\]n \\x \\");
        assert_eq!(escape_controls("fs.read:/a b/*"), "fs.read:/a b/*");
    }

    /// The guard also refuses a command that stops, restarts, disables or
    /// kills the node's service by its name, and leaves reading it alone.
    #[test]
    fn the_guard_refuses_stopping_the_service() {
        // The rules before the service rules: they alone refuse none of these.
        const BEFORE: usize = 9;
        // The service rules after them: the fs.write rules follow.
        const SERVICE_RULES: usize = 9;
        assert!(GUARD[BEFORE + SERVICE_RULES].starts_with("fs.write"));
        let rules = |g: &[&str]| g.iter().map(|g| g.to_string()).collect::<Vec<_>>();
        let home = Path::new("/home/alice");
        let all = RuleSet::new(&rules(GUARD), home);
        let before = RuleSet::new(&rules(&GUARD[..BEFORE]), home);
        let mut caught = std::collections::BTreeSet::new();
        for c in [
            "systemctl stop nerve-node",
            "sudo systemctl stop nerve-node",
            "sudo -n systemctl stop nerve-node.service",
            "systemctl restart nerve-node",
            "systemctl try-restart nerve-node",
            "systemctl reload-or-restart nerve-node.service",
            "systemctl disable nerve-node",
            "systemctl disable --now nerve-node",
            "sudo systemctl --now disable nerve-node.service",
            "systemctl kill nerve-node",
            "systemctl kill -s KILL nerve-node",
            "systemctl kill --signal=SIGKILL nerve-node.service",
            "systemctl mask nerve-node",
            "systemctl mask --now nerve-node",
            "systemctl --no-block stop 'nerve-node'",
            "systemctl stop nerve-node nerve-center",
            "systemctl stop sshd; journalctl -u nerve-node",
            "/usr/bin/systemctl stop nerve-node",
            "sudo /bin/systemctl restart nerve-node.service",
            "cd /tmp && sudo systemctl stop nerve-node",
            "true; systemctl stop nerve-node",
            "(systemctl stop nerve-node)",
            "sc stop nerve-node",
            "sc.exe stop nerve-node",
            "sc config nerve-node start= disabled",
            "sc.exe config nerve-node start= disabled",
            "sc delete nerve-node",
            "sc \\\\host stop nerve-node",
            "sc stop \"nerve-node\"",
            "C:\\Windows\\System32\\sc.exe stop nerve-node",
            "Stop-Service nerve-node",
            "Stop-Service -Name nerve-node",
            "Stop-Service -Name nerve-node -Force",
            "Stop-Service -Name:nerve-node",
            "Stop-Service -Name \"nerve-node\"",
            "stop-service nerve-node",
            "Restart-Service nerve-node",
            "Restart-Service -Name nerve-node -Force",
            "Set-Service -Name nerve-node -StartupType Disabled",
            "Set-Service nerve-node -StartupType Disabled",
            "Remove-Service nerve-node",
            "cd C:\\ ; Stop-Service nerve-node",
            "& Stop-Service nerve-node",
            "Get-Service nerve-node | Stop-Service",
            "Get-Service nerve-node | Restart-Service -Force",
            "Get-Service -Name nerve-node | Set-Service -StartupType Disabled",
            "Get-Service nerve-node|Stop-Service",
            "Get-Service nerve-node | Select-Object Name | Stop-Service",
            "net stop nerve-node",
            "net.exe stop nerve-node",
            "net stop \"nerve-node\"",
            "taskkill /im nerve-node.exe",
            "taskkill /IM nerve-node.exe /F",
            "taskkill /f /im nerve-node-desktop.exe",
            "taskkill.exe /f /im nerve-node-desktop.exe /t",
            "taskkill /fi \"IMAGENAME eq nerve-node.exe\"",
            "Stop-Process -Name nerve-node",
            "Stop-Process -Name nerve-node-desktop -Force",
            "Stop-Process -Name nerve-node.exe",
            "stop-process -name:nerve-node",
            "Stop-Process -Force -Name \"nerve-node\"",
            "Get-Process nerve-node | Stop-Process",
            "Get-Process nerve-node-desktop | Stop-Process -Force",
            "Get-Process | Where-Object Name -eq nerve-node | Stop-Process",
            // A line break or a tab ends a command and its name like a space.
            "sudo systemctl restart nerve-node\necho done",
            "sudo systemctl restart nerve-node\n",
            "sudo systemctl restart nerve-node\t",
            "systemctl stop nerve-node\r\nsleep 1",
            "cd /srv\nsystemctl restart nerve-node",
            "cd /srv\r\nsystemctl restart nerve-node",
            "echo hi\n    systemctl stop nerve-node",
            "echo hi\n\tsudo systemctl stop nerve-node",
            "echo hi\n\n  sudo -n systemctl disable nerve-node.service",
            "sc stop nerve-node\nsc query nerve-node",
            "Stop-Service nerve-node\nStart-Sleep 2",
            "Stop-Service nerve-node\r\nStart-Sleep 2",
            "Start-Sleep 1\nStop-Service nerve-node",
            "Get-Service nerve-node |\n  Stop-Service",
            "taskkill /im nerve-node.exe\ntasklist",
            "Stop-Process -Name nerve-node\n",
            // sudo counts at a command's start, with its flags.
            "sudo -u root systemctl stop nerve-node",
            "cd x && sudo -u root systemctl restart nerve-node",
            "echo ok | sudo -n systemctl stop nerve-node",
            // The SysV wrapper calls systemctl.
            "service nerve-node stop",
            "sudo service nerve-node restart",
            "sudo -n service nerve-node.service try-restart",
            "/usr/sbin/service nerve-node force-reload",
            "service \"nerve-node\" stop",
            "service nerve-node condrestart; true",
            "service nerve-node stop\necho done",
            "cd /srv && service nerve-node restart",
            // Killing the process by its name.
            "pkill nerve-node",
            "sudo pkill nerve-node",
            "sudo killall nerve-node",
            "sudo pkill -f nerve-node",
            "pkill -9 -f 'nerve-node --config x'",
            "pkill -x \"nerve-node\"",
            "killall -s KILL nerve-node-desktop",
            "killall -9 nerve-node && echo gone",
            "pkill -u nerve -x nerve-node",
            "pkill '^nerve-node$'",
            "pkill -f nerve-node\nsleep 1",
            "/usr/bin/pkill nerve-node",
            "sudo -n killall -9 nerve-node; true",
            // The Windows commands ignore case.
            "STOP-SERVICE nerve-node",
            "Stop-service nerve-node",
            "RESTART-SERVICE -Name NERVE-NODE",
            "SET-SERVICE Nerve-Node -StartupType Disabled",
            "SC STOP nerve-node",
            "sc stop Nerve-Node",
            "SC.EXE CONFIG nerve-node start= disabled",
            "Sc Delete NERVE-NODE",
            "NET STOP nerve-node",
            "Net Stop NERVE-NODE",
            "NET.EXE STOP \"Nerve-Node\"",
            "TASKKILL /IM NERVE-NODE.EXE /F",
            "Taskkill /F /IM nerve-node-desktop.EXE",
            "taskkill /im Nerve-Node-Desktop.exe",
            "STOP-PROCESS -Name NERVE-NODE",
            "stop-process -name nerve-node-desktop -force",
            "get-service nerve-node | stop-service",
            "GET-SERVICE NERVE-NODE | STOP-SERVICE",
            "Get-Process Nerve-Node | Stop-Process",
        ] {
            let found = all.find("exec", "run", c);
            let Some(rule) = found else {
                panic!("should be refused: {c}");
            };
            assert!(
                before.find("exec", "run", c).is_none(),
                "refused without the service rules: {c}"
            );
            caught.insert(rule.to_string());
        }
        // Every service rule refuses a line of its own, so none can go dead.
        for g in &GUARD[BEFORE..BEFORE + SERVICE_RULES] {
            assert!(caught.contains(*g), "no case for {g}");
        }
        let run = |c: &str| all.find("exec", "run", c).is_some();
        for c in [
            "systemctl status nerve-node",
            "systemctl status nerve-node.service",
            "sudo systemctl status nerve-node",
            "systemctl is-active nerve-node",
            "systemctl is-enabled nerve-node",
            "systemctl show nerve-node",
            "systemctl cat nerve-node",
            "systemctl list-units 'nerve*'",
            "systemctl stop sshd",
            "systemctl restart nerve-center",
            "systemctl stop nerve-node-extra",
            "systemctl stop my-nerve-node",
            "journalctl -u nerve-node",
            "journalctl -u nerve-node -f",
            "sc query nerve-node",
            "sc.exe query nerve-node",
            "sc qc nerve-node",
            "sc stop spooler",
            "sc queryex nerve-node",
            "Get-Service nerve-node",
            "Get-Service -Name nerve-node | Format-List",
            "Get-Service nerve-node | Select-Object Status",
            "Stop-Service spooler",
            "Restart-Service -Name spooler",
            "Set-Service -Name spooler -StartupType Disabled",
            "net start spooler",
            "net stop spooler",
            "net start nerve-node-other",
            "taskkill /im notepad.exe",
            "taskkill /im nerve-center.exe",
            "tasklist /fi \"IMAGENAME eq nerve-node.exe\"",
            "Get-Process nerve-node",
            "Get-Process notepad | Stop-Process",
            "Stop-Process -Name notepad",
            "cargo build -p nerve-node",
            "cargo build -p nerve-node-desktop --release",
            "cargo test -p nerve-node",
            "git commit -m 'systemctl stop nerve-node'",
            "git commit -m 'Stop-Service nerve-node'",
            "echo systemctl stop nerve-node",
            "grep -r 'systemctl stop nerve-node' docs/",
            // A quoted mention that holds `sudo` is not a command: sudo has to
            // begin the command.
            "git commit -m \"Refuse sudo systemctl stop nerve-node in the guard\"",
            "echo \"then run: sudo systemctl restart nerve-node\"",
            "grep -rn \"sudo systemctl stop nerve-node\" docs/",
            "grep -rn 'sudo service nerve-node restart' docs/",
            "git commit -m 'Docs: sudo pkill nerve-node'",
            "git commit -m 'run sudo Stop-Service nerve-node'",
            // Reading the service, a process or a log, in one line or several.
            "systemctl status nerve-node\nsleep 1",
            "sudo systemctl status nerve-node\r\nsystemctl is-active nerve-node",
            "echo ok\nsystemctl stop sshd",
            "Get-Service nerve-node\nGet-Process nerve-node",
            "SC QUERY nerve-node",
            "NET START nerve-node",
            "TASKLIST /FI \"IMAGENAME eq nerve-node.exe\"",
            "STOP-SERVICE spooler",
            "TASKKILL /IM NOTEPAD.EXE",
            "service nerve-node status",
            "sudo service nerve-node-extra stop",
            "service sshd restart",
            "sudo service ssh restart",
            "pgrep nerve-node",
            "pgrep -a nerve-node",
            "ps aux | grep nerve-node",
            "pkill sshd",
            "pkill -f nginx",
            "sudo killall nginx",
            "pkill nerve-node-extra",
            "pkill -f my-nerve-node",
            "pkill -u nerve sshd",
        ] {
            assert!(!run(c), "should stay allowed: {c}");
        }
        // Refused by the rules for the program's path already.
        for c in [
            "pkill -f /usr/local/bin/nerve-node",
            "/etc/init.d/nerve-node stop",
        ] {
            assert!(all.find("exec", "run", c).is_some(), "{c}");
        }
    }

    #[test]
    fn rules_for_the_buttons() {
        let r = |cap, action, target, wild| rule_for(cap, action, target, wild).unwrap();
        assert_eq!(
            r("exec", "run", "git push origin", false),
            "exec.run:git push origin"
        );
        assert_eq!(
            r("exec", "run", " git push origin ", true),
            "exec.run:git *"
        );
        assert_eq!(r("fs", "read", "/h/p/a.rs", false), "fs.read:/h/p/a.rs");
        assert_eq!(r("fs", "read", "/h/p/a.rs", true), "fs.read:/h/p/*");
        assert_eq!(r("fs", "list", "/h", true), "fs.list:/*");
        assert_eq!(r("camera", "snap", "camera.snap", false), "camera.snap");
        assert_eq!(r("camera", "snap", "camera.snap", true), "camera");
        for (cap, action, target) in [
            ("exec", "run", "  "),
            ("fs", "read", "relative"),
            ("fs.x", "read", "/a"),
        ] {
            assert!(rule_for(cap, action, target, false).is_err());
        }
        // Whatever a button writes is a valid rule that covers its entry.
        for (cap, action, target) in [
            ("exec", "run", "git status"),
            ("fs", "write", "/h/p/[x]/a"),
            ("camera", "snap", "camera.snap"),
        ] {
            for wild in [false, true] {
                let rule = rule_for(cap, action, target, wild).unwrap();
                validate(&rule).unwrap();
                assert!(set(&[&rule]).find(cap, action, target).is_some(), "{rule}");
            }
        }
    }

    #[test]
    fn rules_offer_actions_by_scope() {
        let r = |rules: &[&str]| rules.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!offers(&r(&[]), "fs", "read"));
        // The pattern is not looked at; the scope is.
        assert!(offers(&r(&["fs:~/notes/*"]), "fs", "write"));
        assert!(offers(&r(&["fs.read:/a/*"]), "fs", "read"));
        assert!(!offers(&r(&["fs.read:/a/*"]), "fs", "write"));
        assert!(offers(&r(&["exec"]), "exec", "signal"));
        assert!(offers(&r(&["exec.run"]), "exec", "run"));
        assert!(!offers(&r(&["exec.run"]), "exec", "signal"));
        assert!(!offers(&r(&["execute:x", "fs"]), "exec", "run"));
        // Not a rule: nothing is covered.
        assert!(!offers(&r(&["fs:", "fs.read:[", "a.b.c"]), "fs", "read"));
    }

    #[test]
    fn sudo_rules() {
        assert_eq!(
            sudo_rule_for("sudo apt update", false).unwrap(),
            "sudo apt update"
        );
        assert_eq!(
            sudo_rule_for("sudo apt update", true).unwrap(),
            "sudo apt *"
        );
        assert_eq!(
            sudo_rule_for("sudo -n true x", true).unwrap(),
            "sudo -n true *"
        );
        assert_eq!(sudo_rule_for("sudo -i", true).unwrap(), "sudo -i *");
        assert!(sudo_rule_for("apt update", false).is_err());
        let list = vec![sudo_rule_for("sudo apt update", true).unwrap()];
        assert!(command_matches(&list, "sudo apt upgrade -y"));
        assert!(!command_matches(&list, "sudo rm -rf /"));
    }
}
