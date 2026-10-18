//! Pulling a command line apart so the blocklist sees the real commands, not
//! just the raw string (docs/dev/action-checker.md).
//!
//! A command line can hide a dangerous command behind separators, wrappers
//! and nested shells. [`commands`] splits the line into its individual
//! commands (at `;`, `&&`, `||`, `|`, newlines, and inside `$( )`, backticks
//! and `sh -c '…'` / `powershell -Command` bodies), strips wrappers (`sudo`,
//! `env A=B`, `nohup`, `command`, `exec`, `time`, `nice`, `xargs`), takes the
//! program's base name (`/bin/rm` → `rm`) and expands combined short flags
//! (`-rf` → `-r -f`) so `-rf`, `-fr` and `-r -f` all look the same.
//!
//! What it cannot see is in the docs: variables, aliases, a script written
//! then run, base64. Those the decision model and the node's own policy are
//! for.

/// One command pulled from a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program's base name, lower-cased (`/usr/bin/RM` → `rm`).
    pub program: String,
    /// Every argument after the program, in order, with combined short flags
    /// expanded (`-rf` → `-r`, `-f`).
    pub args: Vec<String>,
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
}

/// Wrapper programs that run another command: stripped so the real program is
/// seen. `env` and `xargs` also drop their `NAME=value` and flag arguments.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "command", "exec", "time", "nice", "ionice", "xargs", "setsid",
    "stdbuf", "npx", "pnpx",
];

/// Programs whose `-c` / `-Command` argument is itself a command line to pull
/// apart.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"];
const POWERSHELLS: &[&str] = &["powershell", "pwsh"];

/// The commands in `line`, each split, wrappers stripped and flags expanded.
/// Nested shells (`sh -c '…'`, `$( )`, backticks, `powershell -Command …`)
/// add their own commands too. The depth is bounded so a crafted line cannot
/// make this recurse without end.
pub fn commands(line: &str) -> Vec<Command> {
    let mut out = Vec::new();
    collect(line, 0, &mut out);
    out
}

fn collect(line: &str, depth: usize, out: &mut Vec<Command>) {
    if depth > 8 {
        return;
    }
    for segment in split_segments(line) {
        let words = match tokenize(&segment) {
            Some(w) if !w.is_empty() => w,
            _ => continue,
        };
        parse_command(&words, depth, out);
    }
}

/// One tokenized command (wrappers already to be stripped by the caller).
fn parse_command(words: &[String], depth: usize, out: &mut Vec<Command>) {
    let mut i = 0;
    // Strip leading wrappers and their own arguments.
    while i < words.len() {
        let w = base_name(&words[i]);
        if !WRAPPERS.contains(&w.as_str()) {
            break;
        }
        i += 1;
        // `env A=B`, `nice -n 5`, `sudo -u user`, `xargs -0`: drop the
        // wrapper's own words up to the command that follows. A flag that
        // takes a value (`-n 5`, `-u user`) drops that value too.
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
    if i >= words.len() {
        return;
    }
    let program = base_name(&words[i]);
    let rest = &words[i + 1..];

    // The command itself is seen first, then any nested shell it runs.
    let args = rest.iter().flat_map(|a| expand_flags(a)).collect();
    out.push(Command {
        program: program.clone(),
        args,
    });

    // A nested shell: its `-c` / `-Command` body is another command line.
    if SHELLS.contains(&program.as_str()) {
        if let Some(body) = flag_value(rest, &["-c"]) {
            collect(&body, depth + 1, out);
        }
    } else if POWERSHELLS.contains(&program.as_str())
        && let Some(body) = flag_value(rest, &["-command", "-c", "-encodedcommand"])
    {
        collect(&body, depth + 1, out);
    }
}

/// Splits a command line at the separators that start a new command:
/// `;`, `&&`, `||`, `|`, newlines, and the `&` that backgrounds one. Also
/// pulls the bodies of `$( )` and backticks out as their own segments, kept
/// after the line's own so the outer command is seen first. Quotes are
/// honoured (and kept, for the tokenizer) so a separator inside a string does
/// not split, and `$( )` inside single quotes does not expand.
fn split_segments(line: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut deferred = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            cur.push(c);
            if q == '"' && c == '$' && chars.peek() == Some(&'(') {
                chars.next();
                cur.push('(');
                let body = take_until_balanced(&mut chars, '(', ')');
                cur.push_str(&body);
                cur.push(')');
                collect_sub(&body, &mut deferred);
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
            '`' => {
                let body = take_until(&mut chars, '`');
                collect_sub(&body, &mut deferred);
            }
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                let body = take_until_balanced(&mut chars, '(', ')');
                collect_sub(&body, &mut deferred);
            }
            ';' | '\n' | '\r' | '&' | '|' => {
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
    segments.append(&mut deferred);
    segments
}

/// Adds every command inside a `$( )` or backtick body as its own segment.
fn collect_sub(body: &str, segments: &mut Vec<String>) {
    for s in split_segments(body) {
        let s = s.trim();
        if !s.is_empty() {
            segments.push(s.to_string());
        }
    }
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

/// Splits one command (no separators) into words, honouring quotes. Returns
/// `None` only for an empty line. A quote that is not closed is taken to the
/// end, so a half-written line still yields its words.
fn tokenize(segment: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    for c in segment.chars() {
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
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
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
        words.push(cur);
    }
    Some(words)
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

/// The base name of a program path, lower-cased: `/bin/rm` → `rm`,
/// `C:\Windows\System32\cmd.exe` → `cmd.exe`.
fn base_name(word: &str) -> String {
    let w = word.rsplit(['/', '\\']).next().unwrap_or(word);
    w.to_ascii_lowercase()
}

/// The value of the first of `names` found in `rest` (`-c echo hi` → the rest
/// joined from `echo`), or a `-c=…` / `-Command:…` joined form. The body is
/// everything after the flag, so `sh -c 'a; b'` already came through as one
/// word.
fn flag_value(rest: &[String], names: &[&str]) -> Option<String> {
    for (i, w) in rest.iter().enumerate() {
        let lower = w.to_ascii_lowercase();
        if let Some(eq) = lower.find(['=', ':'])
            && names.contains(&&lower[..eq])
        {
            return Some(w[eq + 1..].to_string());
        }
        if names.contains(&lower.as_str()) {
            // The body is the next word (quoted as one), else the rest joined.
            return rest.get(i + 1).map(|v| {
                if i + 2 >= rest.len() {
                    v.clone()
                } else {
                    rest[i + 1..].join(" ")
                }
            });
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
        // The wrapper's own flags do not become the command's.
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

    #[test]
    fn command_substitution_is_pulled_apart() {
        assert_eq!(progs("echo $(rm -rf /)"), ["echo", "rm"]);
        assert_eq!(progs("echo `rm -rf /`"), ["echo", "rm"]);
    }

    #[test]
    fn a_half_written_quote_still_yields_words() {
        let c = commands("rm -rf 'x");
        assert_eq!(c[0].program, "rm");
        assert_eq!(c[0].operands(), ["x"]);
    }
}
