//! Pairing codes (spec §3.2): valid for 10 minutes, for one successful
//! pairing, and for 10 tries in all. A wrong code counts against every open
//! code, so guessing is bounded by the tries, not by the number of codes open.
//!
//! Codes live in memory only: a restart ends every open code.

use std::time::{Duration, Instant};

pub const CODE_TTL: Duration = Duration::from_secs(600);
pub const TRIES: u32 = 10;
/// 12 characters of `a-z0-9`: about 62 bits, against 10 tries.
pub const CODE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
    /// Unknown, used, expired or out of tries: the node is told the same for
    /// all of them.
    Refused,
}

#[derive(Debug)]
struct Open {
    code: String,
    created: Instant,
    tries: u32,
}

#[derive(Debug, Default)]
pub struct Codes {
    open: Vec<Open>,
}

impl Codes {
    /// A new code, valid from `now`.
    pub fn create(&mut self, now: Instant) -> String {
        self.prune(now);
        let code = nerve_transport::keys::random_token(CODE_LEN);
        self.open.push(Open {
            code: code.clone(),
            created: now,
            tries: 0,
        });
        code
    }

    fn prune(&mut self, now: Instant) {
        self.open
            .retain(|o| now.duration_since(o.created) < CODE_TTL && o.tries < TRIES);
    }

    /// Checks `code` without using it up. A wrong code costs every open code
    /// one try.
    pub fn check(&mut self, code: &str, now: Instant) -> Result<(), CodeError> {
        self.prune(now);
        if self
            .open
            .iter()
            .any(|o| crate::util::ct_eq(o.code.as_bytes(), code.as_bytes()))
        {
            return Ok(());
        }
        for o in &mut self.open {
            o.tries += 1;
        }
        self.prune(now);
        Err(CodeError::Refused)
    }

    /// A right code whose pairing failed anyway (a taken name): it costs that
    /// code one try.
    pub fn fail(&mut self, code: &str) {
        for o in self.open.iter_mut().filter(|o| o.code == code) {
            o.tries += 1;
        }
    }

    /// Uses `code` up after a successful pairing.
    pub fn consume(&mut self, code: &str) {
        self.open.retain(|o| o.code != code);
    }

    pub fn open_count(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_works_once() {
        let mut c = Codes::default();
        let now = Instant::now();
        let code = c.create(now);
        assert_eq!(code.len(), CODE_LEN);
        assert!(nerve_proto::link::valid_code(&code));
        assert_eq!(c.check(&code, now), Ok(()));
        c.consume(&code);
        assert_eq!(c.check(&code, now), Err(CodeError::Refused));
    }

    #[test]
    fn a_code_expires_after_ten_minutes() {
        let mut c = Codes::default();
        let now = Instant::now();
        let code = c.create(now);
        assert_eq!(
            c.check(&code, now + CODE_TTL - Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(c.check(&code, now + CODE_TTL), Err(CodeError::Refused));
    }

    #[test]
    fn wrong_codes_count_against_every_open_code() {
        let mut c = Codes::default();
        let now = Instant::now();
        let a = c.create(now);
        let b = c.create(now);
        for _ in 0..TRIES - 1 {
            assert_eq!(c.check("wrong", now), Err(CodeError::Refused));
        }
        assert_eq!(c.open_count(now), 2);
        assert_eq!(c.check("wrong", now), Err(CodeError::Refused));
        // The tenth wrong try used up both codes.
        assert_eq!(c.check(&a, now), Err(CodeError::Refused));
        assert_eq!(c.check(&b, now), Err(CodeError::Refused));
    }

    #[test]
    fn a_failed_pairing_with_the_right_code_costs_a_try() {
        let mut c = Codes::default();
        let now = Instant::now();
        let code = c.create(now);
        for _ in 0..TRIES {
            assert_eq!(c.check(&code, now), Ok(()));
            c.fail(&code);
        }
        assert_eq!(c.check(&code, now), Err(CodeError::Refused));
    }
}
