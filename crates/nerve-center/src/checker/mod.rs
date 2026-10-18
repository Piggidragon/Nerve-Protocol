//! The action checker on the center (docs/dev/action-checker.md, issue #17).
//!
//! A gate that checks every tool call before it is sent to the node. The node
//! still decides afterwards; design rule 1 holds, the center can only make a
//! call stricter. For a call the checker goes, in order:
//!
//! 1. **Blocklist** (deterministic, in code and editable). A match refuses at
//!    once, no model call. The blocklist wins over everything below.
//! 2. **Saved allow rules.** A match sends the call to the node with no model
//!    call. The blocklist is not skipped.
//! 3. **Decision model** (optional, off by default). At or above the
//!    threshold it refuses. An unreachable model refuses (fail closed) unless
//!    the owner switched that to allow-and-log.
//! 4. Otherwise the call goes to the node as today.
//!
//! Each part has its own switch, all in the center's web UI, all kept in the
//! center's state.

pub mod blocklist;
pub mod config;
pub mod model;
pub mod normalize;
pub mod server;

use serde_json::{Value, json};

use nerve_proto::Effect;

pub use config::{
    AllowRule, BlockEntry, CheckerConfig, DEFAULT_HF_REPO, DEFAULT_MODEL_LICENCE, ModelConfig,
    ModelScope, ModelSource,
};
pub use model::Endpoint;

use crate::util::clip;
use blocklist::{Call, Rule};

/// Which layer made a decision, for the audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Blocklist,
    AllowRule,
    Model,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Blocklist => "blocklist",
            Layer::AllowRule => "allow rule",
            Layer::Model => "model",
        }
    }
}

/// What the checker decided about a call.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Nothing matched (or the model was below the threshold): send it to the
    /// node. `note` is a line for the debug log, if any.
    Pass { note: Option<String> },
    /// A saved allow rule matched: send it to the node, with the model
    /// skipped. Audited as allowed by the checker.
    Allowed { detail: String },
    /// Refused by the checker. `message` is for the agent; `detail` is the
    /// audit line.
    Refuse {
        layer: Layer,
        detail: String,
        message: String,
    },
}

/// The call the checker judges.
pub struct CallInfo<'a> {
    pub cap: &'a str,
    pub action: &'a str,
    pub effect: Effect,
    /// The command line, the path, or `<cap>.<action>` for an action without
    /// a target.
    pub target: &'a str,
    /// The call's other arguments, for the model's state.
    pub args: &'a serde_json::Map<String, Value>,
    pub node_id: &'a str,
    /// The node's OS (`linux`, `windows`, …), for the model's state.
    pub os: &'a str,
    pub tainted: bool,
}

/// One compiled blocklist entry, kept with its text and note for the audit.
struct Blocked {
    rule: Rule,
    text: String,
    note: String,
}

/// The checker, built from a `CheckerConfig`. Rebuilt when the config
/// changes; the running local model server is managed apart (it need not
/// restart on an unrelated change).
pub struct Checker {
    cfg: CheckerConfig,
    blocklist: Vec<Blocked>,
    allow: Vec<(Rule, Option<String>)>,
    /// The endpoint model, when the source is an endpoint with a URL. The
    /// local source's endpoint comes from the running server at check time.
    endpoint: Option<Endpoint>,
    /// A rule that did not parse, reported for the UI.
    pub rejected: Vec<String>,
}

impl Checker {
    /// Builds the checker from `cfg`. `token` is the endpoint secret, read
    /// from its file by the center. Rules that do not parse are left out and
    /// listed in `rejected`.
    pub fn build(cfg: CheckerConfig, token: Option<String>) -> Checker {
        let mut rejected = Vec::new();
        let mut blocklist = Vec::new();
        for e in cfg.blocklist.iter().filter(|e| e.on) {
            match Rule::parse(&e.rule) {
                Ok(rule) => blocklist.push(Blocked {
                    rule,
                    text: e.rule.clone(),
                    note: e.note.clone(),
                }),
                Err(why) => rejected.push(why),
            }
        }
        let mut allow = Vec::new();
        for a in &cfg.allow_rules {
            match Rule::parse(&a.rule) {
                Ok(rule) => allow.push((rule, a.node_id.clone())),
                Err(why) => rejected.push(why),
            }
        }
        let endpoint =
            if cfg.model.source == ModelSource::Endpoint && !cfg.model.endpoint_url.is_empty() {
                match Endpoint::parse(
                    &cfg.model.endpoint_url,
                    token,
                    Some(cfg.model.endpoint_model.clone()),
                ) {
                    Ok(e) => Some(e),
                    Err(why) => {
                        rejected.push(format!("the model endpoint URL: {why}"));
                        None
                    }
                }
            } else {
                None
            };
        Checker {
            cfg,
            blocklist,
            allow,
            endpoint,
            rejected,
        }
    }

    pub fn config(&self) -> &CheckerConfig {
        &self.cfg
    }

    /// Whether the model should see a call of this effect, by the scope and
    /// whether the session is tainted.
    fn model_sees(&self, effect: Effect, tainted: bool) -> bool {
        match self.cfg.model.scope {
            ModelScope::Effects => {
                matches!(effect, Effect::Write | Effect::Actuate | Effect::Execute)
            }
            ModelScope::WithReads => true,
            ModelScope::TaintedOnly => tainted,
        }
    }

    /// Runs the checker. `endpoint` is the resolved model endpoint when the
    /// model is on and reachable (the local server's, when ready); `None`
    /// means the model is on but not reachable.
    pub async fn check(&self, call: &CallInfo<'_>, endpoint: Option<&Endpoint>) -> Decision {
        let target = Call {
            cap: call.cap,
            action: call.action,
            target: call.target,
        };
        // 1. Blocklist (hard deny, wins over everything).
        if self.cfg.blocklist_on
            && let Some(b) = self.blocklist.iter().find(|b| b.rule.matches(&target))
        {
            let what = if b.note.is_empty() {
                b.text.clone()
            } else {
                format!("{} ({})", b.note, b.text)
            };
            return Decision::Refuse {
                layer: Layer::Blocklist,
                detail: b.text.clone(),
                message: format!(
                    "the center's action checker refused this call: it is on the blocklist — {what}. The owner can change the blocklist in the center's web UI (Action checker)."
                ),
            };
        }
        // 2. Saved allow rules (skip the model, not the blocklist).
        if self
            .allow
            .iter()
            .filter(|(_, node)| node.as_deref().is_none_or(|n| n == call.node_id))
            .any(|(rule, _)| rule.matches(&target))
        {
            return Decision::Allowed {
                detail: format!("a saved allow rule matched {}.{}", call.cap, call.action),
            };
        }
        // 3. Decision model.
        if self.cfg.model_on && self.model_sees(call.effect, call.tainted) {
            return self.run_model(call, endpoint).await;
        }
        Decision::Pass { note: None }
    }

    async fn run_model(&self, call: &CallInfo<'_>, endpoint: Option<&Endpoint>) -> Decision {
        let m = &self.cfg.model;
        let fail = |why: String| {
            if m.fail_closed {
                Decision::Refuse {
                    layer: Layer::Model,
                    detail: why.clone(),
                    message: format!(
                        "the center's action checker could not reach its decision model, so it refused the call (fail closed): {why}. The owner can switch the checker's model off, or to allow-and-log, in the center's web UI (Action checker)."
                    ),
                }
            } else {
                Decision::Pass {
                    note: Some(format!(
                        "the checker's model was unreachable; the call was allowed and logged (allow-and-log): {why}"
                    )),
                }
            }
        };
        let endpoint = match endpoint {
            Some(e) => e,
            None => return fail("the model is not reachable".into()),
        };
        let state = model_state(call);
        match model::ask(endpoint, m, state).await {
            Ok(score) if score >= m.threshold => Decision::Refuse {
                layer: Layer::Model,
                detail: format!("score {score:.2} ≥ threshold {:.2}", m.threshold),
                message: format!(
                    "the center's action checker's decision model judged this call dangerous (score {score:.2}, threshold {:.2}), so it refused it. The owner can change the threshold or switch the model off in the center's web UI (Action checker).",
                    m.threshold
                ),
            },
            Ok(score) => Decision::Pass {
                note: Some(format!(
                    "the checker's model allowed the call (score {score:.2} < {:.2})",
                    m.threshold
                )),
            },
            Err(e) => fail(e.to_string()),
        }
    }

    /// The endpoint for the endpoint source, if set.
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.endpoint.as_ref()
    }

    pub fn model_on(&self) -> bool {
        self.cfg.model_on
    }

    pub fn taint_on(&self) -> bool {
        self.cfg.taint_on
    }

    pub fn model_source(&self) -> ModelSource {
        self.cfg.model.source
    }
}

/// A call becomes a tainted session's one when it returned outside content: a
/// successful call with effect `Read`, `Sense` or `Execute`.
pub fn taints(effect: Effect) -> bool {
    matches!(effect, Effect::Read | Effect::Sense | Effect::Execute)
}

/// The `state` sent to the model: the call, with args bounded. The question
/// is fixed by the center, so only this ever carries the command text.
fn model_state(call: &CallInfo<'_>) -> Value {
    let args = clip(&Value::Object(call.args.clone()).to_string(), 2000);
    json!({
        "capability": call.cap,
        "action": call.action,
        "target": clip(call.target, 2000),
        "os": call.os,
        "tainted": call.tainted,
        "args": args,
    })
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use serde_json::Map;

    fn call<'a>(
        cap: &'a str,
        action: &'a str,
        effect: Effect,
        target: &'a str,
        args: &'a Map<String, Value>,
    ) -> CallInfo<'a> {
        CallInfo {
            cap,
            action,
            effect,
            target,
            args,
            node_id: "n1",
            os: "linux",
            tainted: false,
        }
    }

    #[tokio::test]
    async fn an_allow_rule_skips_the_model_but_not_the_blocklist() {
        let mut cfg = CheckerConfig::default();
        cfg.allow_rules.push(AllowRule {
            rule: "exec.run:rm *".into(),
            node_id: None,
        });
        let checker = Checker::build(cfg, None);
        let args = Map::new();
        // A plain rm matches the allow rule: allowed, no model.
        let c = call("exec", "run", Effect::Execute, "rm file.txt", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Allowed { .. }
        ));
        // But `rm -rf /` is on the blocklist, which wins over the allow rule.
        let c = call("exec", "run", Effect::Execute, "rm -rf /", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Refuse {
                layer: Layer::Blocklist,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn with_the_blocklist_off_nothing_is_refused_without_a_model() {
        let mut cfg = CheckerConfig::default();
        cfg.blocklist_on = false;
        let checker = Checker::build(cfg, None);
        let args = Map::new();
        let c = call("exec", "run", Effect::Execute, "rm -rf /", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Pass { .. }
        ));
    }

    #[tokio::test]
    async fn the_model_scope_decides_which_calls_it_sees() {
        let mut cfg = CheckerConfig::default();
        cfg.blocklist_on = false;
        cfg.model_on = true;
        cfg.model.source = ModelSource::Endpoint; // no URL -> endpoint None
        let args = Map::new();
        // Effects scope (default): a read is not seen, so it passes without a
        // model call even though the model is unreachable.
        let checker = Checker::build(cfg.clone(), None);
        let c = call("fs", "read", Effect::Read, "/x", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Pass { .. }
        ));
        // A write is seen; with no endpoint and fail-closed it is refused.
        let c = call("fs", "write", Effect::Write, "/x", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Refuse {
                layer: Layer::Model,
                ..
            }
        ));
        // With-reads scope: the read is seen too, so it is also refused.
        cfg.model.scope = ModelScope::WithReads;
        let checker = Checker::build(cfg, None);
        let c = call("fs", "read", Effect::Read, "/x", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Refuse {
                layer: Layer::Model,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn allow_and_log_lets_an_unreachable_model_through() {
        let mut cfg = CheckerConfig::default();
        cfg.blocklist_on = false;
        cfg.model_on = true;
        cfg.model.source = ModelSource::Endpoint;
        cfg.model.fail_closed = false;
        let checker = Checker::build(cfg, None);
        let args = Map::new();
        let c = call("exec", "run", Effect::Execute, "make", &args);
        assert!(matches!(
            checker.check(&c, None).await,
            Decision::Pass { note: Some(_) }
        ));
    }

    #[test]
    fn a_read_sense_or_execute_taints_a_session() {
        assert!(taints(Effect::Read));
        assert!(taints(Effect::Sense));
        assert!(taints(Effect::Execute));
        assert!(!taints(Effect::Write));
        assert!(!taints(Effect::Actuate));
    }
}
