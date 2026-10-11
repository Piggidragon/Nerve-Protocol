//! The node part: checks a node, acting as a center ([`FakeCenter`]).
//!
//! The caller gets a pairing link and must pair the node under test with it
//! and start it (`start`). The node must then dial the fake center; the part
//! drives that link and ends with `bye revoked`, after which the node must not
//! dial again.

use std::future::Future;
use std::time::Duration;

use serde_json::{Value, json};

use nerve_proto::link::PairLink;
use nerve_proto::msg::method;
use nerve_proto::{Descriptor, ErrorCode, PROTOCOL_VERSION};

use crate::fake_center::{self, FakeCenter};
use crate::wire::code_of;
use crate::{Report, ensure};

const WAIT: Duration = Duration::from_secs(15);

/// Runs every node check. `start` pairs the node under test with the link it
/// is given and starts it.
pub async fn run<F, Fut>(start: F) -> Report
where
    F: FnOnce(PairLink) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let mut r = Report::new("node");
    let mut center = match FakeCenter::start(false).await {
        Ok(c) => c,
        Err(e) => {
            r.check("4.1", "the fake center starts", Err(e.to_string()));
            return r;
        }
    };
    if let Err(e) = start(center.link()).await {
        r.check("3.2", "the node pairs", Err(e));
        return r;
    }
    let Some(paired) = center.paired() else {
        r.check(
            "3.2",
            "the node pairs",
            Err("no pair request arrived".into()),
        );
        return r;
    };
    r.check("3.2", "the node pairs", Ok(()));
    let req = &paired.request;
    r.check(
        "2.2",
        "the node name is 1 to 32 of a-z, 0-9 and -",
        ensure(nerve_proto::valid_node_name(&req.name), req.name.clone()),
    );

    let Some(mut link) = center.next_link(Duration::from_secs(30)).await else {
        r.check(
            "4.1",
            "the node dials the center",
            Err("no link within 30 s".into()),
        );
        return r;
    };
    r.check("4.1", "the node dials the center", Ok(()));
    r.check(
        "4.1",
        "the Nerve-Node header names the paired node id",
        ensure(
            link.node_header == paired.node_id,
            format!("header {}", link.node_header),
        ),
    );
    let conn = &mut link.conn;
    let hello = match fake_center::handshake(conn, &center.center_id, &paired).await {
        Ok(h) => h,
        Err(e) => {
            r.check("4.2", "the hello is signed and names version \"0\"", Err(e));
            return r;
        }
    };
    r.check(
        "4.2",
        "the hello is signed and names version \"0\"",
        ensure(
            hello.versions.iter().any(|v| v == PROTOCOL_VERSION),
            "no version 0",
        ),
    );

    // §6: the descriptor.
    let d = conn
        .call(method::DESCRIBE, json!({"detail": "full"}), WAIT)
        .await;
    r.check(
        "6",
        "describe full returns a well-formed descriptor",
        match &d {
            Ok(Ok(v)) => check_descriptor(v, &paired.node_id, hello.rev),
            Ok(Err(e)) => Err(format!("error {}", e.message)),
            Err(e) => Err(e.clone()),
        },
    );

    // §5.1: `capability` detail needs a cap.
    r.check(
        "5.1",
        "describe capability without cap is invalid_args",
        expect_code(
            conn.call(method::DESCRIBE, json!({"detail": "capability"}), WAIT)
                .await,
            ErrorCode::InvalidArgs,
        ),
    );

    // §5.2: unknown methods are refused.
    r.check(
        "5.2",
        "an unknown method is method_not_found",
        expect_code(
            conn.call("frobnicate", json!({}), WAIT).await,
            ErrorCode::MethodNotFound,
        ),
    );

    // §5.3: unknown capabilities.
    r.check(
        "5.3",
        "invoke of an unknown capability is unknown_capability",
        expect_code(
            conn.call(
                method::INVOKE,
                json!({"cap": "no-such-cap", "action": "x", "args": {}, "ctx": {}}),
                WAIT,
            )
            .await,
            ErrorCode::UnknownCapability,
        ),
    );

    // §5.2: unknown fields in ctx are refused, so context can only narrow.
    r.check(
        "5.2",
        "an unknown ctx field is invalid_args",
        expect_code(
            conn.call(
                method::INVOKE,
                json!({"cap": "approvals", "action": "list", "args": {},
                       "ctx": {"session": "s1", "full_access": true}}),
                WAIT,
            )
            .await,
            ErrorCode::InvalidArgs,
        ),
    );

    // §7.4: approvals list works on every node.
    r.check(
        "7.4",
        "approvals.list answers with a list",
        match conn
            .call(
                method::INVOKE,
                json!({"cap": "approvals", "action": "list", "args": {}, "ctx": {}}),
                WAIT,
            )
            .await
        {
            Ok(Ok(v)) => ensure(v["approvals"].is_array(), format!("got {v}")),
            Ok(Err(e)) => Err(format!("error {}: {}", code_of(&e), e.message)),
            Err(e) => Err(e),
        },
    );

    // §4.5: after `revoked` the node stops dialling.
    conn.bye("revoked").await;
    drop(link);
    r.check(
        "4.5",
        "after bye revoked the node does not dial again",
        match center.next_link(Duration::from_secs(4)).await {
            None => Ok(()),
            Some(_) => Err("the node dialled again".into()),
        },
    );
    r
}

fn expect_code(
    got: Result<Result<Value, nerve_proto::RpcError>, String>,
    want: ErrorCode,
) -> Result<(), String> {
    match got {
        Ok(Err(e)) => ensure(
            e.kind() == want,
            format!(
                "got {} ({}), expected {}",
                code_of(&e),
                e.message,
                want.as_str()
            ),
        ),
        Ok(Ok(v)) => Err(format!("succeeded with {v}")),
        Err(e) => Err(e),
    }
}

fn check_descriptor(v: &Value, node_id: &str, rev: u64) -> Result<(), String> {
    let d: Descriptor =
        serde_json::from_value(v.clone()).map_err(|e| format!("not a descriptor: {e}"))?;
    ensure(d.nerve == PROTOCOL_VERSION, format!("nerve {:?}", d.nerve))?;
    ensure(d.node.id == node_id, format!("node.id {}", d.node.id))?;
    ensure(d.rev == rev, format!("rev {} but hello said {rev}", d.rev))?;
    ensure(
        nerve_proto::descriptor::summary_words(&d.summary) < 60,
        "the summary has 60 words or more",
    )?;
    for cap in ["node", "approvals"] {
        ensure(d.capability(cap).is_some(), format!("no {cap} capability"))?;
    }
    let mut ids = std::collections::BTreeSet::new();
    for c in &d.capabilities {
        ensure(ids.insert(&c.id), format!("capability {} twice", c.id))?;
    }
    Ok(())
}
