//! Resuming a dropped link (docs/dev/spec/protocol.md §4.8): what each side
//! counts, and the frames it keeps until the other side has read them. No
//! I/O here; the node and the center wrap it around their writers.
//!
//! A resume replays only frames the other side's count shows it never read.
//! A request the node read is never sent to it again, so a call that may
//! have run does not run twice.

use std::collections::VecDeque;
use std::time::Duration;

use crate::Message;
use crate::msg::method;

/// How long each side keeps a dropped link for its resume.
pub const GRACE: Duration = Duration::from_secs(30);
/// How often a side acknowledges what it read, when it read something new.
pub const ACK_EVERY: Duration = Duration::from_secs(5);
/// The most a side keeps of the frames the other has not acknowledged. Past
/// it the oldest go, and the link cannot resume until the other side has
/// read past them.
pub const KEEP_BYTES: usize = 16 * 1024 * 1024;

/// Whether `s` is a link id: 16 random bytes as 32 lowercase hex characters.
pub fn valid_link_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether a text frame counts for the resume: every one but `ack` and `bye`,
/// which belong to one connection.
pub fn counted(m: &Message) -> bool {
    !matches!(m, Message::Notification { method: m, .. } if m == method::ACK || m == method::BYE)
}

/// One side's count of a resumable link: the frames it sent, numbered from
/// 1 over the whole link and kept until the other side acknowledges them, and
/// how many frames it read.
#[derive(Debug, Clone)]
pub struct Replay {
    /// Frames sent so far (the number of the last one).
    sent: u64,
    /// The other side read every frame up to this one.
    acked: u64,
    /// Frames read from the other side.
    got: u64,
    /// The `got` the other side last heard from this one.
    told: u64,
    /// The frames after `acked`, with their numbers; the oldest may have
    /// gone (`lost`).
    kept: VecDeque<(u64, String)>,
    bytes: usize,
    cap: usize,
    /// The last frame that went from `kept` before it was acknowledged.
    lost: u64,
}

impl Replay {
    pub fn new(cap: usize) -> Replay {
        Replay {
            sent: 0,
            acked: 0,
            got: 0,
            told: 0,
            kept: VecDeque::new(),
            bytes: 0,
            cap,
            lost: 0,
        }
    }

    pub fn sent(&self) -> u64 {
        self.sent
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }

    pub fn got(&self) -> u64 {
        self.got
    }

    /// Numbers and keeps a counted frame as it goes to the writer.
    pub fn push(&mut self, text: &str) {
        self.sent += 1;
        self.bytes += text.len();
        self.kept.push_back((self.sent, text.to_string()));
        while self.bytes > self.cap {
            let Some((n, t)) = self.kept.pop_front() else {
                break;
            };
            self.bytes -= t.len();
            self.lost = n;
        }
    }

    /// Counts a counted frame read from the other side.
    pub fn read(&mut self) {
        self.got += 1;
    }

    /// The `got` to acknowledge, when it moved since the other side last
    /// heard it.
    pub fn ack_due(&self) -> Option<u64> {
        (self.got != self.told).then_some(self.got)
    }

    /// An `ack {got}` went out.
    pub fn told(&mut self, got: u64) {
        self.told = got;
    }

    /// The other side read every frame up to `got`. A count below what it
    /// acknowledged before, or past what was sent, is an error.
    pub fn acked_to(&mut self, got: u64) -> Result<(), String> {
        if got < self.acked || got > self.sent {
            return Err(format!(
                "the other side says it read {got} frames; {} were sent and {} acknowledged",
                self.sent, self.acked
            ));
        }
        self.acked = got;
        while self.kept.front().is_some_and(|(n, _)| *n <= got) {
            let (_, t) = self.kept.pop_front().expect("checked");
            self.bytes -= t.len();
        }
        Ok(())
    }

    /// Whether every frame the other side may not have read is still kept.
    pub fn complete(&self) -> bool {
        self.lost <= self.acked
    }

    /// Resumes on a new connection: the other side read `got` frames. Gives
    /// the frames to send again first, in order; an error when `got` does
    /// not fit or one of them is no longer kept.
    pub fn resume(&mut self, got: u64) -> Result<Vec<String>, String> {
        self.acked_to(got)?;
        if !self.complete() {
            return Err(format!(
                "frames up to {} that the other side did not read are no longer kept",
                self.lost
            ));
        }
        // The other side heard this side's count in the handshake.
        self.told = self.got;
        Ok(self.kept.iter().map(|(_, t)| t.clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_resume_sends_again_exactly_what_was_not_read() {
        let mut r = Replay::new(1024);
        for t in ["a", "b", "c", "d"] {
            r.push(t);
        }
        r.acked_to(1).unwrap();
        // The other side read b too before the drop; c and d go again.
        assert_eq!(r.resume(2).unwrap(), ["c", "d"]);
        assert_eq!(r.sent(), 4);
        r.push("e");
        assert_eq!(r.resume(5).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn a_count_that_goes_back_or_past_what_was_sent_is_refused() {
        let mut r = Replay::new(1024);
        r.push("a");
        r.push("b");
        r.acked_to(2).unwrap();
        assert!(r.acked_to(1).is_err());
        assert!(r.acked_to(3).is_err());
        assert!(r.resume(1).is_err());
        assert!(r.resume(3).is_err());
        assert_eq!(r.resume(2).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn past_the_cap_the_link_resumes_only_once_the_lost_frames_were_read() {
        let mut r = Replay::new(4);
        r.push("aa");
        r.push("bb");
        r.push("cc");
        // "aa" went unread: a resume from before it cannot replay it.
        assert!(!r.complete());
        assert!(r.clone().resume(0).is_err());
        // Once the other side read past it, nothing is missing.
        r.acked_to(1).unwrap();
        assert!(r.complete());
        assert_eq!(r.resume(1).unwrap(), ["bb", "cc"]);
    }

    #[test]
    fn acks_go_out_only_when_the_count_moved() {
        let mut r = Replay::new(1024);
        assert_eq!(r.ack_due(), None);
        r.read();
        r.read();
        assert_eq!(r.ack_due(), Some(2));
        // Until the ack went out, it is still due.
        assert_eq!(r.ack_due(), Some(2));
        r.told(2);
        assert_eq!(r.ack_due(), None);
        r.read();
        r.resume(0).unwrap();
        assert_eq!(r.ack_due(), None, "the handshake told the count");
    }

    #[test]
    fn ack_and_bye_do_not_count() {
        let n = |m: &str| Message::notification(m, json!({}));
        assert!(!counted(&n(method::ACK)));
        assert!(!counted(&n(method::BYE)));
        assert!(counted(&n(method::EVENT)));
        assert!(counted(&Message::result(crate::Id::Num(1), json!({}))));
    }

    #[test]
    fn link_ids() {
        assert!(valid_link_id(&"0f".repeat(16)));
        assert!(!valid_link_id(&"0F".repeat(16)));
        assert!(!valid_link_id(&"0f".repeat(15)));
    }
}
