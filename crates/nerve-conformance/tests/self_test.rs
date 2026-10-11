//! The suite checks its own pieces against each other: the center part against
//! the fake center, the node part against the echo node. If these fail, the
//! suite is broken, not the implementation under test.

use std::time::Duration;

use nerve_conformance::echo::{self, Echo};
use nerve_conformance::fake_center::FakeCenter;
use nerve_conformance::wire::Recv;
use nerve_conformance::{center_part, harness_part, node_part};
use nerve_proto::msg::method;

#[tokio::test]
async fn center_part_passes_against_the_fake_center() {
    let center = FakeCenter::start(true).await.unwrap();
    let report = center_part::run(&center.link()).await;
    assert!(report.ok(), "{report}");
}

#[tokio::test]
async fn node_part_passes_against_the_echo_node() {
    let report = node_part::run(|link| async move {
        let node = Echo::pair(&link, "echo-node").await?;
        tokio::spawn(async move {
            let Ok(mut c) = node.dial(&node.node_id).await else {
                return;
            };
            let Ok(ch) = echo::read_challenge(&mut c).await else {
                return;
            };
            let _ = c
                .notify(method::HELLO, node.hello(&ch, &["0"], false))
                .await;
            if !matches!(c.recv(Duration::from_secs(15)).await, Recv::Msg(_)) {
                return;
            }
            let d = echo::descriptor(&node.node_id, &node.name);
            // The echo node never redials: one link, served until it ends.
            echo::serve(&mut c, &d, Duration::from_secs(60)).await;
        });
        Ok(())
    })
    .await;
    assert!(report.ok(), "{report}");
}

#[test]
fn harness_part_reports_every_check_as_not_run() {
    let report = harness_part::run();
    assert_eq!(report.outcomes.len(), harness_part::PLANNED.len());
    assert!(!report.ok());
}
