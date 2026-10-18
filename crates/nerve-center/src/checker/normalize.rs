//! Pulling a command line apart so the blocklist sees the real commands, not
//! just the raw string (docs/dev/action-checker.md).
//!
//! A command line can hide a dangerous command behind separators, wrappers
//! and nested shells. [`parse`] splits the line into its individual commands
//! (at `;`, `&&`, `||`, `|`, newlines, and inside `$( )`, backticks and
//! `sh -c '…'` / `powershell -Command` bodies), strips wrappers (`sudo`,
//! `env A=B`, `nohup`, `command`, `exec`, `time`, `nice`, `xargs`), takes the
//! program's base name (`/bin/rm` → `rm`) and expands combined short flags
//! (`-rf` → `-r -f`) so `-rf`, `-fr` and `-r -f` all look the same.
//!
//! The whole walk is bounded: nesting (`$( )`, backticks, `-c` bodies, all
//! together) and the number of commands produced. A line that hits either
//! bound is reported as [`Parsed::overflow`], so the checker refuses it rather
//! than pass a line it could not take apart (a deeply nested `$(` can no
//! longer overflow the stack).
//!
//! What it cannot see is in the docs: variables, aliases, a script written
//! then run, base64. Those the decision model and the node's own policy are
//! for.

/// The deepest nesting the walk descends, counting `$( )`, backticks and
/// `-c` bodies together. Beyond it the line is reported as overflow.
pub const MAX_DEPTH: usize = 16;
/// The most commands the walk pulls from one line. A line with more is
/// reported as overflow (it is almost certainly an attempt to drown the
/// matcher, and in any case cannot be judged in full).
pub const MAX_COMMANDS: usize = 256;

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

/// The result of pulling a command line apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub commands: Vec<Command>,
    /// The walk hit its depth or command bound and could not take the whole
    /// line apart. The checker treats this as "cannot see" and refuses.
    pub overflow: bool,
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

/// The commands in `line`, with the overflow flag ignored. Kept for the tests
/// and callers that only want the commands.
pub fn commands(line: &str) -> Vec<Command> {
    parse(line).commands
}

/// Pulls `line` apart, bounded in depth and in the number of commands.
pub fn parse(line: &str) -> Parsed {
    let mut w = Walk {
        commands: Vec::new(),
        overflow: false,
    };
    w.collect(line, 0);
    Parsed {
        commands: w.commands,
        overflow: w.overflow,
    }
}

/// The state threaded through one walk: the commands found so far and whether
/// a bound was hit. One `Walk` per [`parse`], so the depth and command bounds
/// cover the whole line, not each nesting level on its own.
struct Walk {
    commands: Vec<Command>,
    overflow: bool,
}

impl Walk {
    fn collect(&mut self, line: &str, depth: usize) {
        if depth > MAX_DEPTH {
            self.overflow = true;
            return;
        }
        let (segments, subs) = split_segments(line);
        // The line's own commands first, then the nested ones, so the outer
        // command is seen before what it runs.
        for segment in &segments {
            if self.commands.len() >= MAX_COMMANDS {
                self.overflow = true;
                return;
            }
            if let Some(words) = tokenize(segment).filter(|w| !w.is_empty()) {
                self.parse_command(&words, depth);
                if self.overflow {
                    return;
                }
            }
        }
        for body in subs {
            self.collect(&body, depth + 1);
            if self.overflow {
                return;
            }
        }
    }

    /// One tokenized command, wrappers stripped, flags expanded; a nested
    /// shell's `-c` body is walked at `depth + 1`.
    fn parse_command(&mut self, words: &[String], depth: usize) {
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

        let args = rest.iter().flat_map(|a| expand_flags(a)).collect();
        self.commands.push(Command {
            program: program.clone(),
            args,
        });

        // A nested shell: its `-c` / `-Command` body is another command line.
        // The flag may be combined (`bash -lc '…'`, `sh -xc '…'`): any short
        // flag word that ends in `c` carries the body.
        if SHELLS.contains(&program.as_str()) {
            if let Some(body) = shell_c_body(rest) {
                self.collect(&body, depth + 1);
            }
        } else if POWERSHELLS.contains(&program.as_str())
            && let Some(body) = flag_value(rest, &["-command", "-c", "-encodedcommand"])
        {
            self.collect(&body, depth + 1);
        }
    }
}

/// Splits a command line at the separators that start a new command (`;`,
/// `&&`, `||`, `|`, newlines, `&`), and returns the `$( )` and backtick
/// bodies separately (raw, not split) so the caller walks them at the next
/// depth. Quotes are honoured (and kept, for the tokenizer) so a separator
/// inside a string does not split, and `$( )` inside single quotes does not
/// expand.
fn split_segments(line: &str) -> (Vec<String>, Vec<String>) {
    let mut segments = Vec::new();
    let mut subs = Vec::new();
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
                subs.push(body);
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
            '`' => subs.push(take_until(&mut chars, '`')),
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                subs.push(take_until_balanced(&mut chars, '(', ')'));
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
    (segments, subs)
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

/// The body a shell's `-c` carries, whether the flag stands alone (`sh -c
/// '…'`) or is combined with others (`bash -lc '…'`, `sh -xec '…'`): any
/// leading `-<letters>` word that ends in `c`.
fn shell_c_body(rest: &[String]) -> Option<String> {
    for (i, w) in rest.iter().enumerate() {
        if let Some(flags) = w.strip_prefix('-').filter(|f| {
            !f.is_empty() && !f.starts_with('-') && f.bytes().all(|b| b.is_ascii_alphabetic())
        }) && flags.ends_with('c')
        {
            return rest.get(i + 1).map(|v| {
                if i + 2 >= rest.len() {
                    v.clone()
                } else {
                    rest[i + 1..].join(" ")
                }
            });
        }
    }
    flag_value(rest, &["-c"])
}

/// The value of the first of `names` found in `rest` (`-c echo hi` → the rest
/// joined from `echo`), or a `-c=…` / `-Command:…` joined form.
fn flag_value(rest: &[String], names: &[&str]) -> Option<String> {
    for (i, w) in rest.iter().enumerate() {
        let lower = w.to_ascii_lowercase();
        if let Some(eq) = lower.find(['=', ':'])
            && names.contains(&&lower[..eq])
        {
            return Some(w[eq + 1..].to_string());
        }
        if names.contains(&lower.as_str()) {
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

    /// A combined shell flag (`bash -lc`, `sh -xec`) still hands its body over
    /// to be pulled apart (review r1, finding 2).
    #[test]
    fn a_combined_shell_flag_body_is_pulled_apart() {
        assert_eq!(progs("bash -lc 'rm -rf /'"), ["bash", "rm"]);
        assert_eq!(progs("sh -xec 'mkfs.ext4 /dev/sda'"), ["sh", "mkfs.ext4"]);
        assert_eq!(progs("bash -ec \"git pull\""), ["bash", "git"]);
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

    /// A line nested past the bound is reported as overflow instead of
    /// recursing without end (review r1, finding 1). A modestly nested real
    /// line is taken apart as before.
    #[test]
    fn deep_nesting_is_bounded_not_a_stack_overflow() {
        let bomb = format!("echo {}", "$(".repeat(100_000));
        let p = parse(&bomb);
        assert!(
            p.overflow,
            "a deeply nested line must be reported as overflow"
        );
        let ok = parse("echo $(printf '%s' $(date))");
        assert!(!ok.overflow);
        assert!(ok.commands.iter().any(|c| c.program == "date"));
    }

    /// A line with a huge number of commands is bounded too.
    #[test]
    fn too_many_commands_is_overflow() {
        let many = vec!["true"; MAX_COMMANDS + 50].join(" ; ");
        let p = parse(&many);
        assert!(p.overflow);
        assert!(p.commands.len() <= MAX_COMMANDS);
    }
}
