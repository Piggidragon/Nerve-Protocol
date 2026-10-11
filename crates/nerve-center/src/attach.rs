//! One center per state folder. The first `nerve-center` takes the lock and owns
//! the center; a second one started by another harness on the same state
//! folder attaches to it over `<state>/run/harness.sock` and only relays its
//! stdio, so both harnesses share the nodes, links and approvals.
//!
//! The socket is mode 0600 in a 0700 folder, and the owner also checks the
//! peer's uid. Windows has neither the lock nor the socket in 0.0.1: a second
//! instance there fails when it cannot bind the node port.

use std::fs::File;
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = "center.lock";
pub const RUN_DIR: &str = "run";
pub const SOCKET: &str = "harness.sock";
/// The first line an attaching process sends.
pub const HELLO: &str = "{\"role\":\"harness\"}";

pub fn socket_path(state: &Path) -> PathBuf {
    state.join(RUN_DIR).join(SOCKET)
}

/// The held center lock; dropping it releases the lock.
pub struct Lock {
    _file: File,
}

/// Takes the center lock, or `None` when another process holds it.
#[cfg(unix)]
pub fn try_lock(state: &Path) -> Result<Option<Lock>, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    nerve_transport::files::create_private_dir(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))?;
    let path = state.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    // SAFETY: flock on a file descriptor this function owns.
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(Some(Lock { _file: file }));
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(format!("cannot lock {}: {e}", path.display()))
    }
}

#[cfg(not(unix))]
pub fn try_lock(state: &Path) -> Result<Option<Lock>, String> {
    std::fs::create_dir_all(state)
        .map_err(|e| format!("cannot create {}: {e}", state.display()))?;
    let path = state.join(LOCK_FILE);
    let file = File::create(&path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    Ok(Some(Lock { _file: file }))
}

#[cfg(unix)]
mod unix {
    use std::path::Path;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    use crate::center::Center;

    use super::{HELLO, RUN_DIR};

    /// Binds the harness socket for the owner.
    pub fn bind(state: &Path) -> Result<UnixListener, String> {
        let dir = state.join(RUN_DIR);
        nerve_transport::files::create_private_dir(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let path = super::socket_path(state);
        // The lock is held, so a socket file left here is stale.
        let _ = std::fs::remove_file(&path);
        let l = UnixListener::bind(&path)
            .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        Ok(l)
    }

    /// Serves attached harnesses until the task is dropped.
    pub async fn serve(center: Center, listener: UnixListener) {
        let me = nerve_transport::net::euid();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let uid = stream.peer_cred().map(|c| c.uid()).ok();
            if uid != Some(me) && uid != Some(0) {
                tracing::warn!(?uid, "refused a harness from another user");
                continue;
            }
            let center = center.clone();
            tokio::spawn(async move {
                let (r, w) = stream.into_split();
                let mut r = BufReader::new(r);
                let mut first = String::new();
                let read = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    r.read_line(&mut first),
                )
                .await;
                if !matches!(read, Ok(Ok(_))) || first.trim() != HELLO {
                    return;
                }
                crate::mcp::serve_lines(center, r, w, "attached").await;
            });
        }
    }

    /// Relays this process's stdio to the owner until either side ends.
    pub async fn relay(state: &Path) -> Result<(), String> {
        let path = super::socket_path(state);
        let mut s = UnixStream::connect(&path).await.map_err(|e| {
            format!(
                "another nerve-center holds {} but its harness socket {} does not answer: {e}",
                state.display(),
                path.display()
            )
        })?;
        s.write_all(format!("{HELLO}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let (mut r, mut w) = s.into_split();
        let up = async {
            let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut w).await;
            let _ = w.shutdown().await;
        };
        let mut down = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut r, &mut tokio::io::stdout()).await;
        });
        // The harness closing stdin ends the session; the owner closing the
        // socket ends this process.
        tokio::select! {
            _ = up => {
                // stdin is done; let the owner finish its replies.
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut down).await;
            }
            _ = &mut down => {}
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::{bind, relay, serve};
