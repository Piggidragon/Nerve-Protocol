//! Whether the node itself runs with full rights: as root on Unix, in an
//! elevated (administrator) token on Windows. Such a node is refused unless
//! `machine.allow_root` is set, and warns when it runs anyway, since a
//! command of a center then has those rights too.

/// Who the node runs as, in the words of the warning.
#[cfg(windows)]
const WHO: &str = "an elevated administrator";
#[cfg(not(windows))]
const WHO: &str = "root";

/// What a node with full rights gets while `machine.allow_root` is unset.
pub const REFUSED: &str = "refusing to run as root; set machine.allow_root = true to allow it";

/// Whether this process is root (Unix) or has an elevated token (Windows).
pub fn full_rights() -> bool {
    #[cfg(unix)]
    {
        nerve_transport::net::euid() == 0
    }
    #[cfg(windows)]
    {
        crate::win::is_elevated()
    }
}

/// The warning for a node that runs as `who` with full rights.
pub fn warning_for(who: &str) -> String {
    format!(
        "this node runs as {who}: unless machine.user names another account, commands from a center then run with full rights on this machine, the node's keys included. You are responsible for what they do."
    )
}

/// The start-up rule for a node whose rights are `full`: refused, or the
/// warning it must log, or nothing to say.
pub fn check(full: bool, allow_root: bool) -> Result<Option<String>, String> {
    check_as(full, allow_root, WHO)
}

fn check_as(full: bool, allow_root: bool, who: &str) -> Result<Option<String>, String> {
    match (full, allow_root) {
        (false, _) => Ok(None),
        (true, false) => Err(REFUSED.into()),
        (true, true) => Ok(Some(warning_for(who))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_rights_are_refused_unless_allowed_and_then_warned_about() {
        assert_eq!(check(false, false), Ok(None));
        assert_eq!(check(false, true), Ok(None));
        assert_eq!(check(true, false), Err(REFUSED.to_string()));
        let w = check(true, true).unwrap().expect("a warning");
        assert!(w.contains(&format!("runs as {WHO}")), "{w}");
    }

    #[test]
    fn the_warning_says_what_it_means_for_both_kinds_of_node() {
        for who in ["root", "an elevated administrator"] {
            let w = check_as(true, true, who).unwrap().unwrap();
            assert!(w.contains(&format!("runs as {who}")), "{w}");
            assert!(w.contains("full rights"), "{w}");
            assert!(w.contains("You are responsible"), "{w}");
        }
    }

    /// The token check must agree with the system's own report: a process
    /// at high or system integrity (an elevated token) is the one that has
    /// full rights, and `whoami /groups` lists that level.
    #[cfg(windows)]
    #[test]
    fn full_rights_follow_the_integrity_level() {
        let out = std::process::Command::new("whoami")
            .arg("/groups")
            .output()
            .expect("whoami runs");
        assert!(out.status.success(), "whoami failed");
        let text = String::from_utf8_lossy(&out.stdout);
        let high = text.contains("S-1-16-12288") || text.contains("S-1-16-16384");
        assert_eq!(full_rights(), high, "{text}");
    }

    /// The test suite does not run as root, so a plain run is not full.
    #[cfg(unix)]
    #[test]
    fn full_rights_follow_the_effective_user() {
        assert_eq!(full_rights(), nerve_transport::net::euid() == 0);
    }
}
