//! Pulling a command line apart so the blocklist sees the real commands, not
//! just the raw string (docs/dev/action-checker.md).
//!
//! A command line can hide a dangerous command behind separators, wrappers,
//! groups and nested shells. [`parse`] splits the line into its individual
//! commands: at `;`, `&&`, `||`, `|`, `&`, newlines and the parentheses of a
//! subshell, and inside `$( )`, backticks (also within double quotes),
//! process substitution `<( )`, `sh -c '…'` (with the `c` anywhere in the flag
//! word: `-c`, `-lc`, `-ce`, `-c -e`), `cmd /c …` and `powershell -Command`
//! bodies, and a here-document or here-string fed to a shell. It strips
//! wrappers (`sudo`, `env A=B`, `nohup`, `command`, `exec`, `time`, `nice`,
//! `xargs`, …) and shell keywords (`if`, `then`, `do`, `!`, `{`, …), takes the
//! program's base name (`/bin/rm` → `rm`, `bash.exe` → `bash`) and expands
//! combined short flags (`-rf` → `-r -f`) so `-rf`, `-fr` and `-r -f` all look
//! the same.
//!
//! A here-document that is not fed to a shell is data (a file being written):
//! its lines are not commands, so a file that merely mentions `rm -rf /` is
//! not refused. Only the `$( )` and backticks in an unquoted one, which the
//! shell does run, are looked at.
//!
//! The whole walk is bounded: nesting (`$( )`, backticks, `-c` bodies, all
//! together) at [`MAX_DEPTH`], and the number of commands at [`MAX_COMMANDS`],
//! far above any real script (the node refuses a command line over 64 KiB
//! anyway). A line past a bound is reported as [`Parsed::overflow`], and the
//! checker refuses it rather than pass a line it could not take apart.
//!
//! What it cannot see is in the docs: variables, aliases, a script written
//! then run, base64. Those the decision model and the node's own policy are
//! for.

/// The deepest nesting the walk descends, counting `$( )`, backticks and
/// `-c` bodies together. Real commands nest a few levels; past this the line
/// is reported as overflow.
pub const MAX_DEPTH: usize = 16;
/// The most commands the walk pulls from one line. A 64 KiB command line (the
/// node's own limit) holds at most about 32 000; a script or here-document
/// of ordinary size is far below. Only a line built to drown the matcher gets
/// here.
pub const MAX_COMMANDS: usize = 100_000;

/// One command pulled from a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program's base name, lower-cased, without `.exe` (`/usr/bin/RM` →
    /// `rm`, `C:\Windows\System32\cmd.exe` → `cmd`).
    pub program: String,
    /// Every argument after the program, in order, with combined short flags
    /// expanded (`-rf` → `-r`, `-f`).
    pub args: Vec<String>,
    /// The arguments as written (not expanded), for the patterns that look at
    /// words such as PowerShell's `-Recurse`.
    pub raw: Vec<String>,
}

impl Command {
    /// The short flags the command carries, each as one letter (`-rf -v` →
    /// `r`, `f`, `v`). Long flags (`--force`) are not here.
    pub fn short_flags(&self) -> Vec<char> {
        self.args
            .iter()
            .filter(|a| {
                a.len() == 2 && a.starts_with('-') && a.as_bytes()[1].is_ascii_alphanumeric()
            })
            .map(|a| a.chars().nth(1).unwrap())
            .collect()
    }

    /// The long flags, without the `--` (`--force` → `force`), lower-cased.
    pub fn long_flags(&self) -> Vec<String> {
        self.args
            .iter()
            .filter_map(|a| a.strip_prefix("--").filter(|r| !r.is_empty()))
            .map(|r| r.split('=').next().unwrap_or(r).to_ascii_lowercase())
            .collect()
    }

    /// The operands: the arguments that are not flags.
    pub fn operands(&self) -> Vec<&str> {
        self.args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect()
    }

    /// The command as one lower-case line, `program arg1 arg2 …` with the
    /// arguments as written: what a `cmd-re:` pattern matches.
    pub fn line(&self) -> String {
        let mut s = self.program.clone();
        for a in &self.raw {
            s.push(' ');
            s.push_str(&a.to_lowercase());
        }
        s
    }
}

/// Which bound a line hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overflow {
    /// Nested deeper than [`MAX_DEPTH`].
    Depth,
    /// More commands than [`MAX_COMMANDS`].
    Commands,
}

/// The result of pulling a command line apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub commands: Vec<Command>,
    /// The walk hit a bound and could not take the whole line apart. The
    /// checker treats this as "cannot see" and refuses.
    pub overflow: Option<Overflow>,
}

/// Wrapper programs that run another command: stripped so the real program is
/// seen. `env` and `xargs` also drop their `NAME=value` and flag arguments.
const WRAPPERS: &[&str] = &[
    "sudo",
    "doas",
    "env",
    "nohup",
    "command",
    "exec",
    "time",
    "nice",
    "ionice",
    "xargs",
    "setsid",
    "stdbuf",
    "npx",
    "pnpx",
    "builtin",
    "nocorrect",
    "noglob",
];

/// Shell words that may stand before a command and are not the program
/// (`if rm …`, `then rm …`, `! rm …`, `{ rm …; }`).
const KEYWORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "esac",
];

/// Programs whose `-c` argument is itself a command line to pull apart.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "ash", "busybox",
];
const POWERSHELLS: &[&str] = &["powershell", "pwsh"];

/// The commands in `line`, with the overflow flag ignored. Kept for the tests
/// and callers that only want the commands.
pub fn commands(line: &str) -> Vec<Command> {
    parse(line).commands
}

/// Pulls `line` apart, bounded in depth and in the number of commands.
pub fn parse(line: &str) -> Parsed {
    let mut w = Walk {
        commands: Vec::new(),
        overflow: None,
    };
    w.collect(line, 0);
    Parsed {
        commands: w.commands,
        overflow: w.overflow,
    }
}

/// The state threaded through one walk. One `Walk` per [`parse`], so the
/// bounds cover the whole line, not each nesting level on its own.
struct Walk {
    commands: Vec<Command>,
    overflow: Option<Overflow>,
}

impl Walk {
    fn collect(&mut self, line: &str, depth: usize) {
        if depth > MAX_DEPTH {
            self.overflow = Some(Overflow::Depth);
            return;
        }
        let (segments, subs) = split_segments(line);
        // The line's own commands first, then the nested ones, so the outer
        // command is seen before what it runs.
        for segment in &segments {
            if self.commands.len() >= MAX_COMMANDS {
                self.overflow = Some(Overflow::Commands);
                return;
            }
            if let Some(words) = tokenize(segment).filter(|w| !w.is_empty()) {
                self.parse_command(&words, depth);
                if self.overflow.is_some() {
                    return;
                }
            }
        }
        for body in subs {
            self.collect(&body, depth + 1);
            if self.overflow.is_some() {
                return;
            }
        }
    }

    /// One tokenized command, keywords and wrappers stripped, flags expanded;
    /// a nested shell's body is walked at `depth + 1`.
    fn parse_command(&mut self, words: &[String], depth: usize) {
        let Some(i) = program_index(words) else {
            return;
        };
        let program = base_name(&words[i]);
        let rest = &words[i + 1..];

        let args = rest.iter().flat_map(|a| expand_flags(a)).collect();
        self.commands.push(Command {
            program: program.clone(),
            args,
            raw: rest.to_vec(),
        });

        // A nested shell: its `-c` / `/c` / `-Command` body is another
        // command line.
        let body = if SHELLS.contains(&program.as_str()) {
            shell_c_body(rest)
        } else if program == "cmd" {
            cmd_c_body(rest)
        } else if POWERSHELLS.contains(&program.as_str()) {
            powershell_body(rest)
        } else {
            None
        };
        if let Some(body) = body {
            self.collect(&body, depth + 1);
        }
    }
}

/// The index of the program in a command's words: past the leading shell
/// keywords and wrappers (with a wrapper's own arguments: `env A=B`,
/// `nice -n 5`, `sudo -u user`, `xargs -0`).
fn program_index(words: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < words.len() {
        let w = base_name(&words[i]);
        if KEYWORDS.contains(&words[i].as_str()) {
            i += 1;
            continue;
        }
        if !WRAPPERS.contains(&w.as_str()) {
            break;
        }
        i += 1;
        while i < words.len() {
            let a = &words[i];
            if a.contains('=') && !a.starts_with('-') {
                i += 1;
            } else if a.starts_with('-') {
                let takes_value = a.len() == 2 && wrapper_value_flag(&w, a.as_bytes()[1]);
                i += 1;
                if takes_value && i < words.len() && !words[i].starts_with('-') {
                    i += 1;
                }
            } else {
                break;
            }
        }
    }
    (i < words.len()).then_some(i)
}

/// The program a segment runs, for telling whether a here-document is fed to
/// a shell.
fn segment_program(segment: &str) -> Option<String> {
    let words = tokenize(segment)?;
    let i = program_index(&words)?;
    Some(base_name(&words[i]))
}

/// A here-document waiting for its body: the lines after the current one,
/// up to the delimiter.
struct Pending {
    delim: String,
    /// `<<'EOF'` or `<<"EOF"` or `<<\EOF`: no expansion in the body.
    quoted: bool,
    /// `<<-`: leading tabs are stripped from the body and the delimiter line.
    strip_tabs: bool,
}

/// Splits a command line at the separators that start a new command (`;`,
/// `&&`, `||`, `|`, `&`, newlines, and the parentheses of a subshell), and
/// returns the bodies that run as commands of their own separately (raw, not
/// split) so the caller walks them at the next depth: `$( )`, backticks,
/// `<( )`/`>( )`, and here-documents and here-strings fed to a shell. Quotes
/// are honoured (and kept, for the tokenizer) so a separator inside a string
/// does not split, and nothing inside single quotes expands.
fn split_segments(line: &str) -> (Vec<String>, Vec<String>) {
    let mut segments = Vec::new();
    let mut subs = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut pending: Vec<Pending> = Vec::new();
    let mut herestrings: Vec<String> = Vec::new();
    // The first segment of the current line, for telling whether it feeds a
    // shell when a here-document closes.
    let mut line_start = 0;
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            cur.push(c);
            if q == '"' && c == '$' && chars.peek() == Some(&'(') {
                chars.next();
                cur.push('(');
                let body = take_until_balanced(&mut chars, '(', ')');
                cur.push_str(&body);
                cur.push(')');
                subs.push(body);
            } else if q == '"' && c == '`' {
                let body = take_until(&mut chars, '`');
                cur.push_str(&body);
                cur.push('`');
                subs.push(body);
            } else if q == '"' && c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                cur.push(c);
            }
            '\\' => {
                // Keep the escape with its character for the tokenizer.
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '`' => subs.push(take_until(&mut chars, '`')),
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                subs.push(take_until_balanced(&mut chars, '(', ')'));
            }
            '<' | '>' if chars.peek() == Some(&'(') => {
                chars.next();
                subs.push(take_until_balanced(&mut chars, '(', ')'));
            }
            '<' if chars.peek() == Some(&'<') => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    chars.next();
                    herestrings.push(take_word(&mut chars));
                } else {
                    let strip_tabs = chars.peek() == Some(&'-');
                    if strip_tabs {
                        chars.next();
                    }
                    let word = take_word(&mut chars);
                    let quoted = word.contains(['\'', '"', '\\']);
                    let delim: String = word.chars().filter(|c| !"'\"\\".contains(*c)).collect();
                    if !delim.is_empty() {
                        pending.push(Pending {
                            delim,
                            quoted,
                            strip_tabs,
                        });
                    }
                }
            }
            '\n' | '\r' => {
                push_segment(&mut segments, &mut cur);
                if !pending.is_empty() || !herestrings.is_empty() {
                    let feeds = feeds_shell(&segments[line_start..]);
                    for h in herestrings.drain(..) {
                        if feeds {
                            subs.push(dequote(&h));
                        }
                    }
                    for p in std::mem::take(&mut pending) {
                        let body = take_heredoc(&mut chars, &p);
                        if feeds {
                            subs.push(body);
                        } else if !p.quoted {
                            subs.extend(substitutions(&body));
                        }
                    }
                }
                line_start = segments.len();
            }
            ';' | '&' | '|' | '(' | ')' => {
                // `&&` and `||` are two characters; one `&` or `|` splits too.
                if (c == '&' || c == '|') && chars.peek() == Some(&c) {
                    chars.next();
                }
                push_segment(&mut segments, &mut cur);
            }
            _ => cur.push(c),
        }
    }
    push_segment(&mut segments, &mut cur);
    // A here-string on the last line.
    if !herestrings.is_empty() && feeds_shell(&segments[line_start..]) {
        subs.extend(herestrings.iter().map(|h| dequote(h)));
    }
    (segments, subs)
}

/// Whether any segment of a line runs a shell (so a here-document on it is a
/// script, not a file being written).
fn feeds_shell(segments: &[String]) -> bool {
    segments
        .iter()
        .filter_map(|s| segment_program(s))
        .any(|p| SHELLS.contains(&p.as_str()) || POWERSHELLS.contains(&p.as_str()))
}

/// Reads a here-document's body: the lines up to one that is the delimiter.
fn take_heredoc(chars: &mut std::iter::Peekable<std::str::Chars>, p: &Pending) -> String {
    let mut body = String::new();
    loop {
        let mut line = String::new();
        let mut ended = true;
        for c in chars.by_ref() {
            if c == '\n' {
                ended = false;
                break;
            }
            line.push(c);
        }
        let line = line.strip_suffix('\r').unwrap_or(&line).to_string();
        let check = if p.strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line.as_str()
        };
        if check == p.delim {
            break;
        }
        body.push_str(check);
        body.push('\n');
        if ended {
            break;
        }
    }
    body
}

/// The `$( )` and backtick bodies in a here-document's text, which the shell
/// runs even when the document is only written to a file. Quotes are not
/// special in a here-document, so they are not honoured here.
fn substitutions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                out.push(take_until_balanced(&mut chars, '(', ')'));
            }
            '`' => out.push(take_until(&mut chars, '`')),
            _ => {}
        }
    }
    out
}

/// One shell word after `<<` or `<<<`, with its quotes kept (so the caller can
/// tell a quoted delimiter), after any blanks.
fn take_word(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        chars.next();
    }
    let mut out = String::new();
    let mut quote: Option<char> = None;
    while let Some(&c) = chars.peek() {
        match quote {
            Some(q) => {
                out.push(c);
                chars.next();
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c.is_whitespace() || ";&|()<>".contains(c) {
                    break;
                }
                if c == '\'' || c == '"' {
                    quote = Some(c);
                }
                out.push(c);
                chars.next();
            }
        }
    }
    out
}

/// A shell word with its quotes removed but its spaces kept, for a here-string
/// body (`'rm -rf ~'` → `rm -rf ~`): the shell runs it as input.
fn dequote(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut quote: Option<char> = None;
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    out.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                _ => out.push(c),
            },
        }
    }
    out
}

fn push_segment(segments: &mut Vec<String>, cur: &mut String) {
    let s = cur.trim();
    if !s.is_empty() {
        segments.push(s.to_string());
    }
    cur.clear();
}

fn take_until(chars: &mut std::iter::Peekable<std::str::Chars>, end: char) -> String {
    let mut out = String::new();
    for c in chars.by_ref() {
        if c == end {
            break;
        }
        out.push(c);
    }
    out
}

/// Reads up to the matching close, honouring nesting of `open`/`close`.
fn take_until_balanced(
    chars: &mut std::iter::Peekable<std::str::Chars>,
    open: char,
    close: char,
) -> String {
    let mut out = String::new();
    let mut depth = 1;
    for c in chars.by_ref() {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        out.push(c);
    }
    out
}

/// Splits one command (no separators) into words, honouring quotes. A `\`
/// before a blank joins it to the word; other backslashes are resolved per
/// word by [`unescape`]. Returns `None` only for an empty line. A quote that
/// is not closed is taken to the end, so a half-written line still yields its
/// words.
fn tokenize(segment: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = segment.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                in_word = true;
            }
            '\\' if chars.peek().is_some_and(|n| n.is_whitespace()) => {
                cur.push(chars.next().unwrap());
                in_word = true;
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(unescape(&std::mem::take(&mut cur)));
                    in_word = false;
                }
            }
            _ => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(unescape(&cur));
    }
    Some(words)
}

/// A word with its POSIX backslash escapes resolved: a `\` before a shell
/// metacharacter or a blank is dropped (`\~` → `~`, `a\ b` → `a b`), but a
/// `\` before a letter or digit is kept, so a Windows path keeps its
/// separators (`C:\Windows\System32` stays).
fn unescape(word: &str) -> String {
    if !word.contains('\\') {
        return word.to_string();
    }
    let special = |c: char| c.is_whitespace() || " ;&|<>()$`\"'#*?[]{}~=,\\".contains(c);
    let mut out = String::with_capacity(word.len());
    let mut chars = word.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek().copied().is_some_and(special) {
            out.push(chars.next().unwrap());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a wrapper's short flag takes a value as the next word (`nice -n 5`,
/// `sudo -u user`), so that value is dropped with it, not taken as the
/// command.
fn wrapper_value_flag(wrapper: &str, flag: u8) -> bool {
    let flags: &[u8] = match wrapper {
        "sudo" | "doas" => b"ughpCrtT",
        "nice" | "ionice" => b"nc",
        "env" => b"uCS",
        "xargs" => b"nPIisdELa",
        "stdbuf" => b"ioe",
        _ => b"",
    };
    flags.contains(&flag)
}

/// The base name of a program path, lower-cased, without `.exe`: `/bin/rm` →
/// `rm`, `C:\Windows\System32\cmd.exe` → `cmd`, `bash.exe` → `bash`.
fn base_name(word: &str) -> String {
    let w = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let w = w.to_ascii_lowercase();
    match w.strip_suffix(".exe") {
        Some(b) if !b.is_empty() => b.to_string(),
        _ => w,
    }
}

/// The body a shell's `-c` carries. As in bash, the `c` may be anywhere in a
/// short-flag word (`-c`, `-lc`, `-ce`, `-xec`) and other options may follow
/// (`bash -c -e '…'`, `bash -c -- '…'`): the body is the first word that is
/// not an option. The words after it (`$0`, `$1`, …) are kept with it.
fn shell_c_body(rest: &[String]) -> Option<String> {
    let mut have_c = false;
    let mut i = 0;
    while i < rest.len() {
        let w = rest[i].as_str();
        if w == "--" {
            i += 1;
            break;
        }
        if let Some(long) = w.strip_prefix("--") {
            // `--login`, `--norc`, `--rcfile <file>`.
            i += if long == "rcfile" || long == "init-file" {
                2
            } else {
                1
            };
            continue;
        }
        let flags = w.strip_prefix('-').or_else(|| w.strip_prefix('+'));
        match flags {
            Some(f) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_alphabetic()) => {
                if f.contains('c') {
                    have_c = true;
                }
                // `-o pipefail`, `-O extglob`: the option's name follows.
                i += if f.ends_with('o') || f.ends_with('O') {
                    2
                } else {
                    1
                };
            }
            _ => break,
        }
    }
    (have_c && i < rest.len()).then(|| rest[i..].join(" "))
}

/// The command `cmd /c …` or `cmd /k …` runs: the words after the switch.
fn cmd_c_body(rest: &[String]) -> Option<String> {
    let i = rest.iter().position(|w| {
        let l = w.to_ascii_lowercase();
        l == "/c" || l == "/k" || l == "/r"
    })?;
    (i + 1 < rest.len()).then(|| rest[i + 1..].join(" "))
}

/// The command `powershell -Command …` runs, with `-Command` written in full or
/// shortened (`-c`, `-com`, …), or as `-Command:…`. An `-EncodedCommand`
/// (base64) is not decoded; that limit is in the docs.
fn powershell_body(rest: &[String]) -> Option<String> {
    for (i, w) in rest.iter().enumerate() {
        let lower = w.to_ascii_lowercase();
        let (name, inline) = match lower.split_once(':') {
            Some((n, _)) => (n.to_string(), Some(w[n.len() + 1..].to_string())),
            None => (lower.clone(), None),
        };
        let is_command =
            name.len() >= 2 && name.starts_with('-') && "-command".starts_with(name.as_str());
        if is_command {
            if let Some(v) = inline {
                return Some(v);
            }
            return (i + 1 < rest.len()).then(|| rest[i + 1..].join(" "));
        }
    }
    None
}

/// Expands a combined short-flag word into one flag each: `-rf` → `-r`, `-f`.
/// A long flag (`--force`), a `-` alone, or anything that is not a run of
/// letters stays as it is.
fn expand_flags(word: &str) -> Vec<String> {
    let is_combined = word.len() > 2
        && word.starts_with('-')
        && !word.starts_with("--")
        && word[1..].bytes().all(|b| b.is_ascii_alphanumeric());
    if is_combined {
        word[1..].chars().map(|c| format!("-{c}")).collect()
    } else {
        vec![word.to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progs(line: &str) -> Vec<String> {
        commands(line).into_iter().map(|c| c.program).collect()
    }

    #[test]
    fn plain_command() {
        let c = commands("rm -rf ./build");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].operands(), ["./build"]);
        assert_eq!(c[0].short_flags(), ['r', 'f']);
    }

    #[test]
    fn combined_flags_in_any_order_look_the_same() {
        for line in ["rm -rf x", "rm -fr x", "rm -r -f x", "rm -f -r x"] {
            let c = commands(line);
            let mut f = c[0].short_flags();
            f.sort_unstable();
            assert_eq!(f, ['f', 'r'], "{line}");
        }
    }

    #[test]
    fn long_flags_count_as_the_same_intent() {
        let c = commands("rm --recursive --force /x");
        assert_eq!(c[0].long_flags(), ["recursive", "force"]);
    }

    #[test]
    fn base_name_of_an_absolute_program() {
        assert_eq!(commands("/bin/rm -rf /")[0].program, "rm");
        assert_eq!(commands("/usr/bin/RM x")[0].program, "rm");
        assert_eq!(commands("bash.exe -c x")[0].program, "bash");
    }

    #[test]
    fn a_windows_path_keeps_its_backslashes() {
        let c = commands(r"Remove-Item C:\Windows\System32 -Recurse");
        assert_eq!(c[0].program, "remove-item");
        assert_eq!(c[0].operands(), [r"C:\Windows\System32"]);
        assert_eq!(c[0].line(), r"remove-item c:\windows\system32 -recurse");
    }

    #[test]
    fn separators_split_into_commands() {
        assert_eq!(progs("git status; rm -rf x"), ["git", "rm"]);
        assert_eq!(progs("a && b || c"), ["a", "b", "c"]);
        assert_eq!(progs("cat f | grep x | wc -l"), ["cat", "grep", "wc"]);
        assert_eq!(progs("make &\nrm -rf /"), ["make", "rm"]);
    }

    #[test]
    fn a_separator_inside_quotes_does_not_split() {
        let c = commands("echo 'a; b' && ls");
        assert_eq!(progs("echo 'a; b' && ls"), ["echo", "ls"]);
        assert_eq!(c[0].operands(), ["a; b"]);
    }

    #[test]
    fn wrappers_are_stripped() {
        assert_eq!(progs("sudo rm -rf /"), ["rm"]);
        assert_eq!(progs("env FOO=bar nohup rm x"), ["rm"]);
        assert_eq!(progs("time nice -n 5 make"), ["make"]);
        let c = commands("sudo rm -rf /");
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].short_flags(), ['r', 'f']);
    }

    #[test]
    fn a_nested_shell_body_is_pulled_apart() {
        assert_eq!(progs("sh -c 'rm -rf /'"), ["sh", "rm"]);
        assert_eq!(
            progs("bash -c \"git pull && rm -rf ~\""),
            ["bash", "git", "rm"]
        );
        assert_eq!(
            progs("powershell -Command \"Remove-Item x\""),
            ["powershell", "remove-item"]
        );
    }

    /// `c` anywhere in a `-c` flag word, and other options around it, still
    /// hand the body over (review r1 and r2, finding 4).
    #[test]
    fn shell_c_bodies_are_found_in_every_form() {
        for line in [
            "bash -lc 'rm -rf /'",
            "sh -xec 'mkfs.ext4 /dev/sda'",
            "bash -ec 'git pull'",
            "bash -ce 'git pull'",
            "sh -cx 'git pull'",
            "bash -c -e 'git pull'",
            "bash -c -- 'git pull'",
            "bash -o pipefail -c 'git pull'",
        ] {
            assert!(
                commands(line)
                    .iter()
                    .any(|c| c.program == "git" || c.program == "rm" || c.program == "mkfs.ext4"),
                "no inner command from {line:?}"
            );
        }
    }

    /// cmd's `/c` and PowerShell's shortened `-c`/`-Command:` bodies.
    #[test]
    fn cmd_and_powershell_bodies() {
        assert_eq!(progs("cmd /c rd /s /q C:\\"), ["cmd", "rd"]);
        assert_eq!(progs("cmd.exe /c \"del x\""), ["cmd", "del"]);
        assert_eq!(progs("pwsh -c \"Remove-Item x\""), ["pwsh", "remove-item"]);
        assert_eq!(
            progs("powershell -Command:Get-ChildItem"),
            ["powershell", "get-childitem"]
        );
    }

    /// Subshells, groups and keywords do not become the program.
    #[test]
    fn groups_and_keywords_are_seen_through() {
        assert_eq!(progs("(rm -rf ~)"), ["rm"]);
        assert_eq!(progs("( rm -rf ~ )"), ["rm"]);
        assert_eq!(progs("{ rm -rf ~; }"), ["rm"]);
        assert_eq!(progs("if true; then rm -rf ~; fi"), ["true", "rm"]);
        assert_eq!(progs("for i in 1; do rm -rf ~; done"), ["for", "rm"]);
        assert_eq!(progs("! rm -rf ~"), ["rm"]);
        assert_eq!(progs("(cd / && chmod -R 777 /)"), ["cd", "chmod"]);
    }

    #[test]
    fn command_substitution_is_pulled_apart() {
        assert_eq!(progs("echo $(rm -rf /)"), ["echo", "rm"]);
        assert_eq!(progs("echo `rm -rf /`"), ["echo", "rm"]);
        assert_eq!(progs("echo \"`rm -rf /`\""), ["echo", "rm"]);
        assert_eq!(progs("cat <(rm -rf /)"), ["cat", "rm"]);
    }

    /// A here-document fed to a shell is a script (its commands are seen); one
    /// only written to a file is data (its lines are not), but a `$( )` inside
    /// an unquoted one still runs (review r2, finding 3).
    #[test]
    fn heredocs_and_herestrings() {
        assert_eq!(progs("bash <<'EOF'\nrm -rf /\nEOF"), ["bash", "rm"]);
        assert_eq!(
            progs("cat <<'EOF' | sh\nrm -rf /\nEOF"),
            ["cat", "sh", "rm"]
        );
        assert_eq!(progs("bash <<< 'rm -rf /'"), ["bash", "rm"]);
        // Written to a file: the lines are data.
        let to_file = commands("cat > note.txt <<'EOF'\nrm -rf /\nEOF");
        assert!(to_file.iter().all(|c| c.program != "rm"), "{to_file:?}");
        // But an unquoted here-document's $( ) runs.
        assert!(
            commands("cat > out <<EOF\n$(rm -rf /)\nEOF")
                .iter()
                .any(|c| c.program == "rm")
        );
    }

    #[test]
    fn a_half_written_quote_still_yields_words() {
        let c = commands("rm -rf 'x");
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].operands(), ["x"]);
    }

    /// A line nested past the depth bound is reported as overflow instead of
    /// recursing without end (review r1, finding 1).
    #[test]
    fn deep_nesting_is_bounded_not_a_stack_overflow() {
        let bomb = format!("echo {}", "$(".repeat(100_000));
        assert_eq!(parse(&bomb).overflow, Some(Overflow::Depth));
        let ok = parse("echo $(printf '%s' $(date))");
        assert_eq!(ok.overflow, None);
        assert!(ok.commands.iter().any(|c| c.program == "date"));
    }

    /// A line with a huge number of commands overflows on the command bound,
    /// but an ordinary long script does not (review r2, finding 3).
    #[test]
    fn the_command_bound_catches_only_abuse() {
        let many = vec!["true"; MAX_COMMANDS + 50].join(";");
        let p = parse(&many);
        assert_eq!(p.overflow, Some(Overflow::Commands));
        assert!(p.commands.len() <= MAX_COMMANDS);
        let script = (0..500)
            .map(|i| format!("echo {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse(&script).overflow, None);
    }
}
