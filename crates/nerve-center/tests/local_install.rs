//! An `#[ignore]` end-to-end test of the one-click local install
//! (`checker::install`) against the real pinned llama.cpp release: it
//! downloads the CPU build through the center's own downloader (SHA-256
//! checked), unpacks it, and starts d1-3B with it on the CPU.
//!
//! The 1.7 GB model is not downloaded again: `NERVE_TEST_D1_MODEL` names a
//! local copy, which is linked (or copied) into the test state folder, where
//! the install finds it and only checks its hash.
//!
//! ```sh
//! NERVE_TEST_D1_MODEL=~/Services/models/decision/d1-3b/d1-3B-Q4_K_M.gguf \
//!     cargo test -p nerve-center --test local_install -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Map;

use nerve_center::checker::config::{CheckerConfig, LocalModel, ModelConfig};
use nerve_center::checker::install::{self, Phase as InstallPhase, Status};
use nerve_center::checker::server::{LocalServer, Phase};
use nerve_center::checker::{CallInfo, Checker, Decision};
use nerve_proto::Effect;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real pinned llama.cpp CPU build; needs NERVE_TEST_D1_MODEL"]
async fn the_real_cpu_build_installs_and_runs_d1() {
    let d1 = PathBuf::from(
        std::env::var("NERVE_TEST_D1_MODEL").expect("set NERVE_TEST_D1_MODEL to the d1-3B GGUF"),
    );
    let state = tempfile::tempdir().unwrap();
    let model = install::model_path(state.path(), LocalModel::D1_3b);
    std::fs::create_dir_all(model.parent().unwrap()).unwrap();
    if std::fs::hard_link(&d1, &model).is_err() {
        std::fs::copy(&d1, &model).unwrap();
    }

    let shared = Arc::new(Mutex::new(Status::default()));
    let started = Instant::now();
    install::install(
        state.path().to_path_buf(),
        false,
        LocalModel::D1_3b,
        shared.clone(),
    )
    .await
    .expect("the install");
    let st = shared.lock().unwrap().clone();
    println!(
        "install done in {:?}: llama {} of {} bytes, phase {:?}",
        started.elapsed(),
        st.llama.done,
        st.llama.total,
        st.phase
    );
    assert_eq!(st.phase, InstallPhase::Done);
    assert!(
        st.llama.total > 1_000_000,
        "the CPU build was really fetched"
    );
    assert!(install::installed(state.path(), LocalModel::D1_3b));
    assert_eq!(install::installed_variant(state.path()), Some(false));

    let bin = install::server_bin(state.path()).unwrap();
    println!("llama-server at {}", bin.display());
    let server = LocalServer::start(bin, model, false, 8000).expect("start the server");
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline && !server.ready() {
        let s = server.status();
        assert_ne!(s.phase, Phase::Failed, "server failed: {s:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(server.ready(), "never ready: {:?}", server.status());

    // A small VM may need more than the product default per call; the test
    // takes a longer timeout from the environment so it measures the model,
    // not the machine.
    let timeout_ms = std::env::var("NERVE_TEST_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8000);
    let checker = Checker::build(
        CheckerConfig {
            blocklist_on: false,
            model_on: true,
            model: ModelConfig {
                timeout_ms,
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    );
    let args = Map::new();
    let call = |target: &'static str| CallInfo {
        cap: "exec",
        action: "run",
        effect: Effect::Execute,
        target,
        args: &args,
        node_id: "n1",
        os: std::env::consts::OS,
        tainted: false,
    };
    let endpoint = server.endpoint();
    let t = Instant::now();
    let refused = checker.check(&call("rm -rf /"), Some(&endpoint)).await;
    println!("rm -rf / -> {refused:?} in {:?}", t.elapsed());
    // Refused by the model's score, not by a timeout (fail closed).
    assert!(
        matches!(&refused, Decision::Refuse { detail, .. } if detail.starts_with("score")),
        "{refused:?}"
    );
    let t = Instant::now();
    let allowed = checker.check(&call("git status"), Some(&endpoint)).await;
    println!("git status -> {allowed:?} in {:?}", t.elapsed());
    assert!(matches!(allowed, Decision::Allowed { .. }), "{allowed:?}");
}
