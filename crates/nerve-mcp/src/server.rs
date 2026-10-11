//! Starting the center: the node listener, the web UI, the HTTP MCP
//! endpoint and the attach socket. `main` and the end-to-end tests both go
//! through [`start`].

use std::net::SocketAddr;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::attach::Lock;
use crate::center::{Center, Options};
use crate::config::{Args, McpMode, is_loopback};
use crate::listen::{self, Server};
use crate::mcp::HttpMcp;
use crate::ui::Ui;

/// A running center. Dropping it stops its listeners; call
/// [`Running::stop`] to close the links cleanly first.
pub struct Running {
    pub center: Center,
    /// Where nodes reach the center.
    pub nodes: SocketAddr,
    pub ui: Option<SocketAddr>,
    pub mcp: Option<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
    _lock: Lock,
}

impl Running {
    /// Says bye to every node and stops the listeners.
    pub async fn stop(self) {
        self.center.shutdown().await;
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Opens the center in `args.state_dir()` (whose lock the caller holds) and
/// starts its listeners. MCP over stdio is not started here; the caller
/// runs [`crate::mcp::serve_stdio`] itself.
pub async fn start(args: &Args, lock: Lock) -> Result<Running, String> {
    // The UI refuses to serve beyond loopback without a password, and then
    // only over TLS, since the password and the session cookie cross the
    // network.
    let ui_addr = (!args.ui_off()).then(|| args.ui.clone());
    let ui_password = args.ui_password.clone().filter(|p| !p.is_empty());
    if let Some(a) = &ui_addr
        && !is_loopback(a)
        && ui_password.is_none()
    {
        return Err(format!(
            "the web UI at {a} is beyond loopback; set --ui-password (NERVE_UI_PASSWORD) or use --ui 127.0.0.1:<port>"
        ));
    }

    let node_listener = listen::tcp(&args.listen).await?;
    let nodes = node_listener.local_addr().map_err(|e| e.to_string())?;
    let center = Center::open(Options {
        state_dir: args.state_dir(),
        name: args.name.clone(),
        public_url: args.public_url(nodes.port()),
        call_wait: args.call_wait(),
    })?;
    let mut tasks = Vec::new();

    let node_server = Server::from_listener(node_listener, &center, args.plain_loopback)?;
    tasks.push(tokio::spawn(listen::serve_nodes(
        center.clone(),
        node_server,
    )));

    let mut ui = None;
    if let Some(a) = ui_addr {
        let tls = !is_loopback(&a);
        let server = Server::bind(&a, &center, !tls).await?;
        ui = Some(server.local_addr());
        tasks.push(tokio::spawn(
            Ui::new(&center, ui_password, tls).serve(server),
        ));
    }

    let mut mcp = None;
    if args.mcp == McpMode::Http {
        let tls = !is_loopback(&args.mcp_listen);
        let server = Server::bind(&args.mcp_listen, &center, !tls).await?;
        mcp = Some(server.local_addr());
        let token = args.harness_token.clone().filter(|t| !t.is_empty());
        if token.is_none() && center.read(|s| s.harness_tokens.is_empty()) {
            tracing::warn!(
                "no harness token yet: the HTTP MCP endpoint refuses every client until one is made in the web UI or set with NERVE_HARNESS_TOKEN"
            );
        }
        tasks.push(tokio::spawn(HttpMcp::new(&center, token).serve(server)));
    }

    #[cfg(unix)]
    {
        let listener = crate::attach::bind(&args.state_dir())?;
        tasks.push(tokio::spawn(crate::attach::serve(center.clone(), listener)));
    }

    // State changes are batched; this writes them out now and then.
    let c = center.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            c.flush();
        }
    }));

    tracing::info!(
        "center {} ({}) for nodes at {}{}",
        center.name(),
        center.id(),
        center.public_url(),
        ui.map(|u| format!(
            ", web UI at {}://{u}",
            if is_loopback(&u.to_string()) {
                "http"
            } else {
                "https"
            }
        ))
        .unwrap_or_default()
    );
    Ok(Running {
        center,
        nodes,
        ui,
        mcp,
        tasks,
        _lock: lock,
    })
}

/// Runs `nerve-mcp` as `main` does: owner or attached, until stdin ends or
/// a signal.
pub async fn run(args: Args) -> Result<(), String> {
    nerve_transport::init_crypto();
    let state = args.state_dir();
    let Some(lock) = crate::attach::try_lock(&state)? else {
        // Another nerve-mcp owns this state folder.
        if args.mcp != McpMode::Stdio {
            return Err(format!(
                "another nerve-mcp already runs the center in {}; only a --mcp stdio instance can attach to it",
                state.display()
            ));
        }
        #[cfg(unix)]
        {
            tracing::info!("attaching to the center that runs in {}", state.display());
            return crate::attach::relay(&state).await;
        }
        #[cfg(not(unix))]
        return Err(format!(
            "another nerve-mcp already runs the center in {}",
            state.display()
        ));
    };
    let running = start(&args, lock).await?;
    match args.mcp {
        McpMode::Stdio => {
            crate::mcp::serve_stdio(running.center.clone()).await;
            // The harness that started us is gone; harnesses that attached
            // keep the center until they end too.
            while running.center.session_count() > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = signal() => break,
                }
            }
        }
        McpMode::Http | McpMode::None => signal().await,
    }
    running.stop().await;
    Ok(())
}

async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("a SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
