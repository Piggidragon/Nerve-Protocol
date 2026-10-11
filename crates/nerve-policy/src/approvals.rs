//! Approvals: the questions the node asks before a call runs (spec §7.4,
//! architecture §5.4).
//!
//! One queue per center. The first answer wins, whether it comes from the
//! center or from the owner on the node; with the approvals grant `local` the
//! center may not answer at all. An approval nobody answers in time resolves as
//! the center's policy says (`on_timeout`), and one whose link ends is
//! withdrawn.

use std::collections::BTreeMap;

use serde::Serialize;
use tokio::sync::oneshot;

use crate::config::{ApprovalsGrant, OnTimeout};
use crate::decide::Choice;

/// Who settled an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum By {
    Center,
    Local,
    Timeout,
    Pause,
    Withdrawn,
}

impl By {
    pub fn as_str(self) -> &'static str {
        match self {
            By::Center => "center",
            By::Local => "local",
            By::Timeout => "timeout",
            By::Pause => "pause",
            By::Withdrawn => "withdrawn",
        }
    }
}

/// The `approvals/requested` event's data.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Requested {
    pub id: String,
    pub cap: String,
    pub action: String,
    pub target: String,
    pub reasons: Vec<String>,
    pub preview: String,
    pub choices: Vec<&'static str>,
    pub max_minutes: u32,
    pub expires_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// The `approvals/resolved` event's data, and what the waiting call gets.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Resolved {
    pub id: String,
    /// `once`, `session`, `time` or `deny`.
    pub answer: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minutes: Option<u32>,
    pub by: By,
}

impl Resolved {
    pub fn allowed(&self) -> bool {
        self.answer != "deny" && !matches!(self.by, By::Pause | By::Withdrawn)
    }

    pub fn choice(&self) -> Option<Choice> {
        Choice::parse(self.answer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerError {
    /// No open approval has this id (it may have been answered already).
    Unknown(String),
    /// The center may not answer (`approvals = "local"`).
    Forbidden,
    /// Not an answer this approval offers, or too many minutes.
    Invalid(String),
}

impl std::fmt::Display for AnswerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnswerError::Unknown(id) => write!(f, "no open approval {id}"),
            AnswerError::Forbidden => {
                write!(f, "this node takes approvals for this center only locally")
            }
            AnswerError::Invalid(s) => write!(f, "{s}"),
        }
    }
}

struct Open {
    req: Requested,
    choices: Vec<Choice>,
    tx: oneshot::Sender<Resolved>,
}

/// The open approvals of one center.
pub struct Queue {
    next: u64,
    open: BTreeMap<String, Open>,
}

impl Default for Queue {
    fn default() -> Queue {
        Queue {
            next: 1,
            open: BTreeMap::new(),
        }
    }
}

/// What an approval asks.
#[derive(Debug, Clone)]
pub struct Ask {
    pub cap: String,
    pub action: String,
    pub target: String,
    pub reasons: Vec<String>,
    pub preview: String,
    pub choices: Vec<Choice>,
    pub max_minutes: u32,
    pub expires_ms: u64,
    pub session: Option<String>,
}

impl Queue {
    /// Opens an approval; the receiver gets its resolution.
    pub fn open(&mut self, ask: Ask) -> (Requested, oneshot::Receiver<Resolved>) {
        // Ids are unique per center for the node's lifetime; the random part
        // keeps an id from an earlier run from answering a new approval.
        let id = format!(
            "a{}-{}",
            self.next,
            nerve_transport::keys::random_token(4).to_lowercase()
        );
        self.next += 1;
        let req = Requested {
            id: id.clone(),
            cap: ask.cap,
            action: ask.action,
            target: ask.target,
            reasons: ask.reasons,
            preview: ask.preview,
            choices: ask.choices.iter().map(|c| c.as_str()).collect(),
            max_minutes: ask.max_minutes,
            expires_ms: ask.expires_ms,
            session: ask.session,
        };
        let (tx, rx) = oneshot::channel();
        self.open.insert(
            id,
            Open {
                req: req.clone(),
                choices: ask.choices,
                tx,
            },
        );
        (req, rx)
    }

    pub fn list(&self) -> Vec<Requested> {
        self.open.values().map(|o| o.req.clone()).collect()
    }

    pub fn get(&self, id: &str) -> Option<&Requested> {
        self.open.get(id).map(|o| &o.req)
    }

    /// Answers `id`. `grant` is the center's approvals grant, checked when the
    /// answer comes from the center.
    pub fn answer(
        &mut self,
        id: &str,
        choice: Choice,
        minutes: Option<u32>,
        by: By,
        grant: ApprovalsGrant,
    ) -> Result<Resolved, AnswerError> {
        if by == By::Center && grant == ApprovalsGrant::Local {
            return Err(AnswerError::Forbidden);
        }
        let open = self
            .open
            .get(id)
            .ok_or_else(|| AnswerError::Unknown(id.into()))?;
        if !open.choices.contains(&choice) {
            return Err(AnswerError::Invalid(format!(
                "{} is not an answer to {id}; it offers {}",
                choice.as_str(),
                open.req.choices.join(", ")
            )));
        }
        let minutes = match choice {
            Choice::Time => {
                let m = minutes
                    .ok_or_else(|| AnswerError::Invalid("a time answer needs minutes".into()))?;
                if m == 0 || m > open.req.max_minutes {
                    return Err(AnswerError::Invalid(format!(
                        "minutes must be 1 to {}",
                        open.req.max_minutes
                    )));
                }
                Some(m)
            }
            _ => None,
        };
        Ok(self.settle(id, choice.as_str(), minutes, by).expect("open"))
    }

    /// The timeout of `id` ran out: it resolves as `on_timeout` says.
    pub fn expire(&mut self, id: &str, on_timeout: OnTimeout) -> Option<Resolved> {
        let answer = match on_timeout {
            OnTimeout::Deny => "deny",
            OnTimeout::Allow => "once",
        };
        self.settle(id, answer, None, By::Timeout)
    }

    /// Withdraws one open approval (its call was cancelled or timed out).
    pub fn withdraw(&mut self, id: &str, by: By) -> Option<Resolved> {
        self.settle(id, "deny", None, by)
    }

    /// Withdraws every open approval (link ended, center paused, panic).
    pub fn withdraw_all(&mut self, by: By) -> Vec<Resolved> {
        let ids: Vec<String> = self.open.keys().cloned().collect();
        ids.iter()
            .filter_map(|id| self.settle(id, "deny", None, by))
            .collect()
    }

    fn settle(
        &mut self,
        id: &str,
        answer: &'static str,
        minutes: Option<u32>,
        by: By,
    ) -> Option<Resolved> {
        let open = self.open.remove(id)?;
        let r = Resolved {
            id: id.into(),
            answer,
            minutes,
            by,
        };
        // The call may have gone already (cancelled); the answer still counts.
        let _ = open.tx.send(r.clone());
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(choices: Vec<Choice>) -> Ask {
        Ask {
            cap: "fs".into(),
            action: "read".into(),
            target: "/x".into(),
            reasons: vec!["mode ask".into()],
            preview: String::new(),
            choices,
            max_minutes: 60,
            expires_ms: 0,
            session: Some("s".into()),
        }
    }

    const ALL: [Choice; 4] = [Choice::Once, Choice::Session, Choice::Time, Choice::Deny];

    #[tokio::test]
    async fn first_answer_wins() {
        let mut q = Queue::default();
        let (req, rx) = q.open(ask(ALL.to_vec()));
        let r = q
            .answer(
                &req.id,
                Choice::Session,
                None,
                By::Local,
                ApprovalsGrant::Both,
            )
            .unwrap();
        assert_eq!(r.by, By::Local);
        let late = q.answer(
            &req.id,
            Choice::Deny,
            None,
            By::Center,
            ApprovalsGrant::Both,
        );
        assert_eq!(late, Err(AnswerError::Unknown(req.id.clone())));
        let got = rx.await.unwrap();
        assert_eq!(got.answer, "session");
        assert!(got.allowed());
        assert!(q.list().is_empty());
    }

    #[tokio::test]
    async fn local_grant_forbids_the_center() {
        let mut q = Queue::default();
        let (req, rx) = q.open(ask(ALL.to_vec()));
        assert_eq!(
            q.answer(
                &req.id,
                Choice::Once,
                None,
                By::Center,
                ApprovalsGrant::Local
            ),
            Err(AnswerError::Forbidden)
        );
        assert_eq!(q.list().len(), 1);
        q.answer(
            &req.id,
            Choice::Deny,
            None,
            By::Local,
            ApprovalsGrant::Local,
        )
        .unwrap();
        assert!(!rx.await.unwrap().allowed());
    }

    #[tokio::test]
    async fn checks_choices_and_minutes() {
        let mut q = Queue::default();
        let (req, _rx) = q.open(ask(vec![Choice::Once, Choice::Deny]));
        assert!(matches!(
            q.answer(
                &req.id,
                Choice::Session,
                None,
                By::Local,
                ApprovalsGrant::Both
            ),
            Err(AnswerError::Invalid(_))
        ));
        let (req2, _rx2) = q.open(ask(ALL.to_vec()));
        assert_ne!(req.id, req2.id);
        for m in [None, Some(0), Some(61)] {
            assert!(matches!(
                q.answer(&req2.id, Choice::Time, m, By::Local, ApprovalsGrant::Both),
                Err(AnswerError::Invalid(_))
            ));
        }
        let r = q
            .answer(
                &req2.id,
                Choice::Time,
                Some(60),
                By::Center,
                ApprovalsGrant::Both,
            )
            .unwrap();
        assert_eq!(r.minutes, Some(60));
    }

    #[tokio::test]
    async fn timeout_and_withdraw() {
        let mut q = Queue::default();
        let (a, rxa) = q.open(ask(ALL.to_vec()));
        let (b, rxb) = q.open(ask(ALL.to_vec()));
        let (_c, rxc) = q.open(ask(ALL.to_vec()));
        let r = q.expire(&a.id, OnTimeout::Deny).unwrap();
        assert_eq!((r.answer, r.by), ("deny", By::Timeout));
        assert!(!rxa.await.unwrap().allowed());
        let r = q.expire(&b.id, OnTimeout::Allow).unwrap();
        assert_eq!(r.answer, "once");
        assert!(rxb.await.unwrap().allowed());
        assert!(q.expire(&b.id, OnTimeout::Allow).is_none());
        let w = q.withdraw_all(By::Withdrawn);
        assert_eq!(w.len(), 1);
        assert!(!rxc.await.unwrap().allowed());
    }
}
