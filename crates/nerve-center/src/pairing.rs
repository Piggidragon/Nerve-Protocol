//! Pairing codes (spec §3.2): valid for the lifetime the owner has set (10
//! minutes unless changed), for one successful pairing, and for 10 tries in
//! all. A code keeps the lifetime it was made with. A wrong code counts against every open
//! code, so guessing is bounded by the tries, not by the number of codes open.
//!
//! Codes live in memory only: a restart ends every open code.

use std::time::{Duration, Instant};

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
    expires: Instant,
    tries: u32,
}

/// A code [`Codes::take`] took out: used up unless given back with
/// [`Codes::fail`].
#[derive(Debug)]
pub struct Taken(Open);

#[derive(Debug, Default)]
pub struct Codes {
    open: Vec<Open>,
}

impl Codes {
    /// A new code, valid from `now` for `ttl`.
    pub fn create(&mut self, now: Instant, ttl: Duration) -> String {
        self.prune(now);
        let code = nerve_transport::keys::random_token(CODE_LEN);
        self.open.push(Open {
            code: code.clone(),
            expires: now + ttl,
            tries: 0,
        });
        code
    }

    fn prune(&mut self, now: Instant) {
        self.open.retain(|o| now < o.expires && o.tries < TRIES);
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
        Err(self.miss(now))
    }

    /// A wrong code: every open code loses one try.
    fn miss(&mut self, now: Instant) -> CodeError {
        for o in &mut self.open {
            o.tries += 1;
        }
        self.prune(now);
        CodeError::Refused
    }

    /// Takes `code` out for one pairing: checking and using it up are one
    /// step, so a second request with the same code finds it gone, however
    /// close together they come. A wrong code costs every open code one try.
    pub fn take(&mut self, code: &str, now: Instant) -> Result<Taken, CodeError> {
        self.prune(now);
        match self
            .open
            .iter()
            .position(|o| crate::util::ct_eq(o.code.as_bytes(), code.as_bytes()))
        {
            Some(i) => Ok(Taken(self.open.swap_remove(i))),
            None => Err(self.miss(now)),
        }
    }

    /// A right code whose pairing failed anyway (a taken name): it is open
    /// again, with one try less.
    pub fn fail(&mut self, taken: Taken) {
        let mut o = taken.0;
        o.tries += 1;
        self.open.push(o);
    }

    /// Whether `code` can still be used. Unlike [`Codes::check`], a code that
    /// is not open costs no try: the web UI asks this to see if the code on
    /// its screen is used up.
    pub fn is_open(&mut self, code: &str, now: Instant) -> bool {
        self.prune(now);
        self.open
            .iter()
            .any(|o| crate::util::ct_eq(o.code.as_bytes(), code.as_bytes()))
    }

    pub fn open_count(&mut self, now: Instant) -> usize {
        self.prune(now);
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEN_MINUTES: Duration = Duration::from_secs(600);
    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn a_code_works_once() {
        let mut c = Codes::default();
        let now = Instant::now();
        let code = c.create(now, TEN_MINUTES);
        assert_eq!(code.len(), CODE_LEN);
        assert!(nerve_proto::link::valid_code(&code));
        assert!(c.take(&code, now).is_ok());
        assert!(c.take(&code, now).is_err());
        assert_eq!(c.check(&code, now), Err(CodeError::Refused));
    }

    #[test]
    fn asking_if_a_code_is_open_costs_no_try() {
        let mut c = Codes::default();
        let now = Instant::now();
        let code = c.create(now, TEN_MINUTES);
        for _ in 0..TRIES {
            assert!(!c.is_open("wrong", now));
        }
        assert!(c.is_open(&code, now));
        c.take(&code, now).unwrap();
        assert!(!c.is_open(&code, now));
        let code = c.create(now, TEN_MINUTES);
        assert!(!c.is_open(&code, now + TEN_MINUTES));
    }

    #[test]
    fn a_code_expires_after_ten_minutes() {
        let mut c = Codes::default();
        let now = Instant::now();
        let code = c.create(now, TEN_MINUTES);
        assert_eq!(
            c.check(&code, now + TEN_MINUTES - Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(c.check(&code, now + TEN_MINUTES), Err(CodeError::Refused));
    }

    #[test]
    fn a_code_keeps_the_lifetime_it_was_made_with() {
        let mut c = Codes::default();
        let now = Instant::now();
        let short = c.create(now, TEN_MINUTES);
        let long = c.create(now, 24 * HOUR);
        // 20 hours on: the short one is gone, the long one still works.
        assert_eq!(c.check(&short, now + 20 * HOUR), Err(CodeError::Refused));
        assert_eq!(c.check(&long, now + 20 * HOUR), Ok(()));
        assert_eq!(
            c.check(&long, now + 24 * HOUR - Duration::from_secs(1)),
            Ok(())
        );
        assert_eq!(c.check(&long, now + 24 * HOUR), Err(CodeError::Refused));
        assert_eq!(c.open_count(now + 24 * HOUR), 0);
    }

    #[test]
    fn a_longer_code_made_later_does_not_extend_an_older_one() {
        let mut c = Codes::default();
        let now = Instant::now();
        let old = c.create(now, TEN_MINUTES);
        let _later = c.create(now, 24 * HOUR);
        assert_eq!(c.check(&old, now + TEN_MINUTES), Err(CodeError::Refused));
    }

    #[test]
    fn wrong_codes_count_against_every_open_code() {
        let mut c = Codes::default();
        let now = Instant::now();
        let a = c.create(now, TEN_MINUTES);
        let b = c.create(now, TEN_MINUTES);
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
        let code = c.create(now, TEN_MINUTES);
        for _ in 0..TRIES {
            let taken = c.take(&code, now).expect("open");
            c.fail(taken);
        }
        assert_eq!(c.check(&code, now), Err(CodeError::Refused));
    }
}
