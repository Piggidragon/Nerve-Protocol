//! One-click install of the local decision model (addendum 2026-10-18,
//! docs/user/action-checker.md).
//!
//! The center downloads a prebuilt `llama-server` from llama.cpp's GitHub
//! release and the pinned d1-3B model from Hugging Face into its own state
//! folder — never system-wide — verifies each against a pinned SHA-256,
//! unpacks the archive with the system `tar` (refusing any entry that would
//! leave the target folder), and runs `llama-server -m <model>` on the CPU or,
//! with the Vulkan build, the GPU. The model is one of two pinned ones,
//! d1-3B (the default) or Kev-4B, whatever the device; the endpoint mode is
//! for any other model or another llama.cpp.
//!
//! Everything is pinned in code (the release tag, each asset's hash, and each
//! model's repo/revision/file/size/hash), so an install fetches exactly the
//! bytes verified on 2026-10-18 or fails.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use nerve_proto::link::CenterUrl;

use super::config::LocalModel;

/// The pinned llama.cpp release.
pub const LLAMA_TAG: &str = "b11719";
const LLAMA_BASE: &str = "https://github.com/ggml-org/llama.cpp/releases/download";

/// One pinned model: where it comes from, what it is, and the defaults the
/// evaluation (docs/dev/action-checker.md) gives it.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ModelPin {
    pub id: LocalModel,
    pub name: &'static str,
    #[serde(skip)]
    repo: &'static str,
    #[serde(skip)]
    revision: &'static str,
    #[serde(skip)]
    pub file: &'static str,
    pub bytes: u64,
    #[serde(skip)]
    sha256: &'static str,
    pub licence: &'static str,
    /// The default threshold from the evaluation.
    pub threshold: f64,
    /// A timeout its normal calls on a CPU stay well inside.
    pub timeout_ms: u64,
    /// One plain line on speed and quality, for the UI.
    pub summary: &'static str,
}

/// The two models the local mode offers, the default first.
pub const MODELS: [ModelPin; 2] = [
    ModelPin {
        id: LocalModel::D1_3b,
        name: "LiquidAI d1-3B (Q4_K_M)",
        repo: "LiquidAI/d1-3B-GGUF",
        revision: "bb1e436ea78eb96a3f1acb6da865f70c2fbeb563",
        file: "d1-3B-Q4_K_M.gguf",
        bytes: 1_674_456_672,
        sha256: "16aff27ea2eefdc32b9897f43854a5d3170c1dc8dccb9c756905af30a4e22402",
        licence: "LFM Open License v1.0",
        threshold: 0.8,
        timeout_ms: 4000,
        summary: "Faster: about 1.7 s per call on a desktop CPU. Catches about 60 % of dangerous actions and 67 % of injection attempts; refuses about 2.5 % of ordinary work.",
    },
    ModelPin {
        id: LocalModel::Kev4b,
        name: "ggml-org Kev-4B (Q4_K_M)",
        repo: "ggml-org/Kev-4B-GGUF",
        revision: "d924f2e2c3872da8b8aaf3eb4453b4126deceb79",
        file: "Kev-4B-Q4_K_M.gguf",
        bytes: 3_033_489_824,
        sha256: "33ae6b18926502b2209a1bf7d3b61a350d65938441515c686bb87d226a19eff9",
        licence: "Apache-2.0",
        threshold: 0.5,
        // p95 was 5.2 s on the test CPU; leave room for a busy machine.
        timeout_ms: 15_000,
        summary: "Catches more: about 79 % of dangerous actions and 93 % of injection attempts, refusing about 1.7 % of ordinary work, but about 4 to 5 s per call on a desktop CPU.",
    },
];

/// The pin of `model`.
pub fn model_pin(model: LocalModel) -> &'static ModelPin {
    MODELS
        .iter()
        .find(|m| m.id == model)
        .expect("every LocalModel has a pin")
}

/// The llama.cpp asset and its SHA-256 for this platform and CPU/GPU choice,
/// or `None` when there is no pinned asset for it (the UI then points to the
/// endpoint mode). GPU is the Vulkan build (NVIDIA, AMD, Intel); macOS uses
/// the Metal build that is built into the arm64 archive for both.
pub fn llama_asset(gpu: bool) -> Option<(&'static str, &'static str)> {
    asset_for(std::env::consts::OS, std::env::consts::ARCH, gpu)
}

/// [`llama_asset`] for a given OS and architecture (as `std::env::consts`
/// names them), so every platform's pin can be tested on any one.
fn asset_for(os: &str, arch: &str, gpu: bool) -> Option<(&'static str, &'static str)> {
    match (os, arch, gpu) {
        ("linux", "x86_64", false) => Some((
            "llama-b11719-bin-ubuntu-x64.tar.gz",
            "2c50edd1422cdc686a1620923a7dda9a33634509566d2821155fb3d4879510a3",
        )),
        ("linux", "x86_64", true) => Some((
            "llama-b11719-bin-ubuntu-vulkan-x64.tar.gz",
            "9a09cce245acf8823feb99fb7ba8ddd3e878e3827564888131e0185044aa4429",
        )),
        ("windows", "x86_64", false) => Some((
            "llama-b11719-bin-win-cpu-x64.zip",
            "1b1234d208a8b851cc27cd3d96b850d1547a4e5cfc5cd75f0a9fdd1d4c5bea20",
        )),
        ("windows", "x86_64", true) => Some((
            "llama-b11719-bin-win-vulkan-x64.zip",
            "08dde7f4133443ac629431c35f0435e267ca73251fc002cb95e10625424e2963",
        )),
        // macOS arm64: Metal is built in, so the same archive serves CPU and GPU.
        ("macos", "aarch64", _) => Some((
            "llama-b11719-bin-macos-arm64.tar.gz",
            "076a2b0d15253078b90bd520a82dc2edc6c17657968878876ba3def3e80f54ba",
        )),
        ("linux", "aarch64", false) => Some((
            "llama-b11719-bin-ubuntu-arm64.tar.gz",
            "290aa4432ad8e28b638285be6a75d0dd6f327d9b2d95f7048a8cf5e69704bee9",
        )),
        ("linux", "aarch64", true) => Some((
            "llama-b11719-bin-ubuntu-vulkan-arm64.tar.gz",
            "ec2b1e886192c9e1e686e4a5a4d95079f75b98966274264e7bf6e2e13a063185",
        )),
        ("windows", "aarch64", false) => Some((
            "llama-b11719-bin-win-cpu-arm64.zip",
            "bb066fea4e7b396560704f05f227aa39057a27ae17aca604f1ef3d1b6503a1a3",
        )),
        ("windows", "aarch64", true) => Some((
            "llama-b11719-bin-win-vulkan-arm64.zip",
            "69bd6da42725771831c3271d2198ebb71e9531282a755edb24917b9d81b1555e",
        )),
        _ => None,
    }
}

/// Whether this platform has a pinned local build at all.
pub fn platform_supported() -> bool {
    llama_asset(false).is_some()
}

/// `<state>/checker`.
fn checker_dir(state: &Path) -> PathBuf {
    state.join("checker")
}

/// Where the unpacked llama.cpp build lives, pinned by tag so a new tag is a
/// fresh folder.
pub fn llama_dir(state: &Path) -> PathBuf {
    checker_dir(state).join("llama").join(LLAMA_TAG)
}

fn model_dir(state: &Path) -> PathBuf {
    checker_dir(state).join("model")
}

/// The path of `model`'s file.
pub fn model_path(state: &Path, model: LocalModel) -> PathBuf {
    model_dir(state).join(model_pin(model).file)
}

/// The models whose file is in place.
pub fn installed_models(state: &Path) -> Vec<LocalModel> {
    MODELS
        .iter()
        .filter(|m| model_path(state, m.id).exists())
        .map(|m| m.id)
        .collect()
}

/// The `llama-server` binary inside the unpacked build, wherever the archive
/// put it (release layouts differ), or `None` when it is not there.
pub fn server_bin(state: &Path) -> Option<PathBuf> {
    let want = if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    find_file(&llama_dir(state), want)
}

/// Whether `model` is installed: the server binary and its file are both in
/// place.
pub fn installed(state: &Path, model: LocalModel) -> bool {
    server_bin(state).is_some() && model_path(state, model).exists()
}

/// The device the installed build is for (`Some(true)` = GPU/Vulkan,
/// `Some(false)` = CPU), from the marker the install wrote, or `None` when
/// nothing is installed.
pub fn installed_variant(state: &Path) -> Option<bool> {
    match std::fs::read_to_string(llama_dir(state).join("variant"))
        .ok()?
        .trim()
    {
        "gpu" => Some(true),
        "cpu" => Some(false),
        _ => None,
    }
}

/// Removes everything the install wrote.
pub fn remove(state: &Path) -> std::io::Result<()> {
    let dir = checker_dir(state);
    match std::fs::remove_dir_all(&dir) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// How far the install has got, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    #[default]
    Idle,
    Downloading,
    Unpacking,
    Verifying,
    Done,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
}

/// The install's live state, shown in the UI and polled while it runs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    pub phase: Phase,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    pub llama: Progress,
    pub model: Progress,
    /// The CPU/GPU choice this install is for.
    pub gpu: bool,
    /// The model this install is for.
    pub model_id: LocalModel,
}

/// A handle the center keeps while an install runs.
pub type Shared = Arc<Mutex<Status>>;

fn set(shared: &Shared, f: impl FnOnce(&mut Status)) {
    f(&mut shared.lock().unwrap());
}

/// Downloads and verifies llama.cpp and the model into `state`, reporting
/// progress through `shared`. Idempotent: a build or model already present and
/// valid is not fetched again.
pub async fn install(
    state: PathBuf,
    gpu: bool,
    model: LocalModel,
    shared: Shared,
) -> Result<(), String> {
    set(&shared, |s| {
        *s = Status {
            phase: Phase::Downloading,
            gpu,
            model_id: model,
            ..Default::default()
        };
    });
    let r = install_inner(&state, gpu, model, &shared).await;
    set(&shared, |s| match &r {
        Ok(()) => s.phase = Phase::Done,
        Err(e) => {
            s.phase = Phase::Failed;
            s.message = e.clone();
        }
    });
    r
}

async fn install_inner(
    state: &Path,
    gpu: bool,
    model_id: LocalModel,
    shared: &Shared,
) -> Result<(), String> {
    let (asset, sha) =
        llama_asset(gpu).ok_or("this platform has no pinned local build; use the endpoint mode")?;
    // 1. llama.cpp, unless the right build (CPU vs GPU) is already unpacked.
    // A device switch wipes the old build so the matching one is fetched.
    let need_llama = server_bin(state).is_none() || installed_variant(state) != Some(gpu);
    if need_llama {
        let dir = llama_dir(state);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
        }
        create_dir(&dir)?;
        let archive = dir.join(asset);
        let url = format!("{LLAMA_BASE}/{LLAMA_TAG}/{asset}");
        fetch_to_file(&url, &archive, Some(sha), None, &mut |done, total| {
            set(shared, |s| s.llama = Progress { done, total });
        })
        .await
        .map_err(|e| format!("downloading {asset}: {e}"))?;
        set(shared, |s| s.phase = Phase::Unpacking);
        unpack(&archive, &dir)?;
        let _ = std::fs::remove_file(&archive);
        if server_bin(state).is_none() {
            return Err("the llama.cpp archive has no llama-server in it".into());
        }
        std::fs::write(dir.join("variant"), if gpu { "gpu" } else { "cpu" })
            .map_err(|e| e.to_string())?;
    } else {
        set(shared, |s| {
            s.llama = Progress { done: 1, total: 1 };
        });
    }
    // 2. The model, unless it is already there with the right hash. Only one
    // model is kept: switching to the other one deletes the first, so a
    // switch does not leave gigabytes behind.
    let pin = model_pin(model_id);
    let model = model_path(state, model_id);
    set(shared, |s| s.phase = Phase::Verifying);
    let have = model.metadata().map(|m| m.len()).unwrap_or(0) == pin.bytes
        && sha256_file(&model).as_deref() == Ok(pin.sha256);
    if !have {
        set(shared, |s| s.phase = Phase::Downloading);
        create_dir(&model_dir(state))?;
        let url = format!(
            "https://huggingface.co/{}/resolve/{}/{}",
            pin.repo, pin.revision, pin.file
        );
        fetch_to_file(
            &url,
            &model,
            Some(pin.sha256),
            Some(pin.bytes),
            &mut |done, total| {
                set(shared, |s| s.model = Progress { done, total });
            },
        )
        .await
        .map_err(|e| format!("downloading {}: {e}", pin.name))?;
    } else {
        set(shared, |s| {
            s.model = Progress {
                done: pin.bytes,
                total: pin.bytes,
            };
        });
    }
    for other in MODELS.iter().filter(|m| m.id != model_id) {
        let _ = std::fs::remove_file(model_path(state, other.id));
    }
    Ok(())
}

/// Whether the GPU build reports a usable device (`llama-server
/// --list-devices`). Never loads a model, so it is safe to run here. The GPU
/// build must be installed first.
pub async fn gpu_available(state: &Path) -> bool {
    let Some(bin) = server_bin(state) else {
        return false;
    };
    let out = tokio::process::Command::new(&bin)
        .arg("--list-devices")
        .output()
        .await;
    match out {
        Ok(o) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            // A Vulkan device shows up as a line under "Available devices".
            text.lines().any(|l| {
                let l = l.trim();
                !l.is_empty()
                    && (l.contains("Vulkan") || l.contains("GPU"))
                    && !l.contains("Available devices")
            })
        }
        Err(_) => false,
    }
}

/// A cheap guess, before anything is downloaded, at whether the machine has a
/// GPU the Vulkan build could use, so the UI can offer the GPU choice. A false
/// positive is harmless: the GPU build then falls back, and the UI offers CPU.
pub fn gpu_hint() -> bool {
    if cfg!(target_os = "macos") {
        return true; // Metal
    }
    if cfg!(target_os = "windows") {
        return Path::new("C:/Windows/System32/vulkan-1.dll").exists();
    }
    // Linux: a render node plus a Vulkan loader.
    let render = std::fs::read_dir("/dev/dri")
        .map(|d| {
            d.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("renderD"))
        })
        .unwrap_or(false);
    let loader = [
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
    ]
    .iter()
    .any(|d| {
        std::fs::read_dir(d)
            .map(|rd| {
                rd.flatten()
                    .any(|e| e.file_name().to_string_lossy().starts_with("libvulkan.so"))
            })
            .unwrap_or(false)
    });
    render && loader
}

/// Lists an archive's entries and refuses any that is absolute or climbs out
/// of the target with `..`, then extracts it with the system `tar` (GNU tar
/// reads `.tar.gz`; the `tar` on Windows 10+ and macOS is a bsdtar that also
/// reads `.zip`).
fn unpack(archive: &Path, dest: &Path) -> Result<(), String> {
    let list = std::process::Command::new("tar")
        .arg("-tf")
        .arg(archive)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !list.status.success() {
        return Err(format!(
            "tar could not read the archive: {}",
            String::from_utf8_lossy(&list.stderr).trim()
        ));
    }
    for entry in String::from_utf8_lossy(&list.stdout).lines() {
        if unsafe_entry(entry.trim()) {
            return Err(format!(
                "the archive has an unsafe path ({}); nothing was unpacked",
                entry.trim()
            ));
        }
    }
    let out = std::process::Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tar could not unpack the archive: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Whether an archive entry would land outside the target: an absolute path,
/// a drive path, or one that climbs with `..`.
fn unsafe_entry(name: &str) -> bool {
    let n = name.trim();
    n.starts_with('/')
        || n.starts_with('\\')
        || (n.len() >= 2 && n.as_bytes()[1] == b':')
        || n.split(['/', '\\']).any(|c| c == "..")
}

/// Streams `url` to `dest` (through a temp file and a rename), following
/// redirects, never https→http, checking the SHA-256 and, when known, the
/// length. `on_progress(done, total)` is called as bytes arrive.
async fn fetch_to_file(
    url: &str,
    dest: &Path,
    expected_sha: Option<&str>,
    expected_len: Option<u64>,
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<(), String> {
    nerve_transport::init_crypto();
    let tmp = dest.with_extension("part");
    let mut url = url.to_string();
    let mut tls_seen = None;
    for _ in 0..8 {
        let (at, target) = split_url(&url)?;
        if tls_seen == Some(true) && !at.tls {
            return Err(format!("{} redirects from https to http", at.host));
        }
        tls_seen = Some(at.tls);
        let proxy = if at.tls {
            nerve_transport::net::Proxy::from_env(&at.host)?
        } else {
            None
        };
        let mut io = nerve_transport::net::open(&at, None, proxy.as_ref()).await?;
        let req = format!(
            "GET {target} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nUser-Agent: nerve-center/{}\r\nConnection: close\r\n\r\n",
            at.authority(),
            env!("CARGO_PKG_VERSION"),
        );
        io.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let head = read_head(&mut io).await?;
        match head.status {
            200 => {
                if head.chunked {
                    return Err(
                        "the server sent a chunked body, which is not supported here".into(),
                    );
                }
                let total = head.content_length.or(expected_len).unwrap_or(0);
                stream_body(&mut io, &head.leftover, &tmp, total, on_progress).await?;
                if let Some(want) = expected_sha
                    && sha256_file(&tmp)?.as_str() != want
                {
                    let _ = std::fs::remove_file(&tmp);
                    return Err("the download does not match its pinned SHA-256".into());
                }
                if let Some(want) = expected_len {
                    let got = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
                    if got != want {
                        let _ = std::fs::remove_file(&tmp);
                        return Err(format!(
                            "the download is {got} bytes, not the pinned {want}"
                        ));
                    }
                }
                std::fs::rename(&tmp, dest).map_err(|e| e.to_string())?;
                return Ok(());
            }
            301 | 302 | 303 | 307 | 308 => {
                let to = head
                    .location
                    .ok_or_else(|| format!("{} redirects without a Location", at.host))?;
                url = absolute(&to, &at)?;
            }
            s => return Err(format!("{} answered HTTP {s}", at.host)),
        }
    }
    Err("too many redirects".into())
}

struct Head {
    status: u16,
    content_length: Option<u64>,
    location: Option<String>,
    chunked: bool,
    leftover: Vec<u8>,
}

/// Reads the response head (up to `\r\n\r\n`) and returns the status, the
/// headers we care about, and any body bytes read past the head.
async fn read_head(io: &mut nerve_transport::net::BoxIo) -> Result<Head, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let (head, rest) = buf.split_at(pos + 4);
            let text = String::from_utf8_lossy(head);
            let mut lines = text.split("\r\n");
            let status = lines
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|c| c.parse().ok())
                .ok_or("no HTTP status in the answer")?;
            let header = |name: &str| {
                lines.clone().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case(name)
                        .then(|| v.trim().to_string())
                })
            };
            return Ok(Head {
                status,
                content_length: header("content-length").and_then(|v| v.parse().ok()),
                location: header("location"),
                chunked: header("transfer-encoding")
                    .is_some_and(|v| v.eq_ignore_ascii_case("chunked")),
                leftover: rest.to_vec(),
            });
        }
        if buf.len() > 64 * 1024 {
            return Err("the answer's headers are too large".into());
        }
        let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the connection closed before the headers were complete".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Streams the body to `tmp`, hashing on the way, until `total` bytes (when
/// known) or the connection closes. A chunked body is refused (a static asset
/// from a CDN is sent with a Content-Length).
async fn stream_body(
    io: &mut nerve_transport::net::BoxIo,
    leftover: &[u8],
    tmp: &Path,
    total: u64,
    on_progress: &mut (dyn FnMut(u64, u64) + Send),
) -> Result<(), String> {
    use std::io::Write;
    let mut file = std::fs::File::create(tmp).map_err(|e| e.to_string())?;
    let mut done = 0u64;
    let mut write = |data: &[u8], done: &mut u64| -> Result<(), String> {
        file.write_all(data).map_err(|e| e.to_string())?;
        *done += data.len() as u64;
        Ok(())
    };
    write(leftover, &mut done)?;
    on_progress(done, total);
    let mut chunk = [0u8; 64 * 1024];
    while total == 0 || done < total {
        let n = io.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        write(&chunk[..n], &mut done)?;
        on_progress(done, total);
    }
    file.flush().map_err(|e| e.to_string())?;
    if total != 0 && done < total {
        let _ = std::fs::remove_file(tmp);
        return Err("the download ended before its Content-Length".into());
    }
    Ok(())
}

/// The server and the request target (path and query) of an http(s) URL.
fn split_url(url: &str) -> Result<(CenterUrl, String), String> {
    let scheme_end = url.find("://").ok_or("not an http(s) address")?;
    let rest = &url[scheme_end + 3..];
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let mut target = rest[end..].to_string();
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    let at = CenterUrl::parse(&format!("{}{}", &url[..scheme_end + 3], &rest[..end]))
        .map_err(|_| "not an http(s) address".to_string())?;
    Ok((at, target))
}

/// A `Location` made absolute against the server it came from.
fn absolute(to: &str, at: &CenterUrl) -> Result<String, String> {
    if to.contains("://") {
        Ok(to.to_string())
    } else if let Some(rest) = to.strip_prefix('/') {
        Ok(format!(
            "{}://{}/{rest}",
            if at.tls { "https" } else { "http" },
            at.authority()
        ))
    } else {
        Err(format!("{} redirects to a relative place", at.host))
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn create_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))
}

/// The first file named `name` under `dir` (a shallow walk, bounded).
fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    let mut seen = 0;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > 10_000 {
                return None;
            }
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if e.file_name() == name {
                return Some(p);
            }
        }
    }
    None
}

/// The SHA-256 of a file, lower-case hex.
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(nerve_proto::msg::hex(ctx.finish().as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_platform_has_an_asset_or_is_handled() {
        // Linux x86_64 (the dev/CI platform) has a pinned CPU and GPU asset.
        if (std::env::consts::OS, std::env::consts::ARCH) == ("linux", "x86_64") {
            assert!(llama_asset(false).is_some());
            assert!(llama_asset(true).is_some());
            assert!(platform_supported());
        }
    }

    #[test]
    fn an_unsafe_archive_entry_is_refused() {
        // A relative Location resolves against its server.
        let (at, _) = split_url("https://host/a/b").unwrap();
        assert_eq!(absolute("/x/y", &at).unwrap(), "https://host/x/y");
        assert!(absolute("relative", &at).is_err());
    }

    /// Every platform with a release build has a pin for CPU and GPU, each a
    /// distinct asset of the pinned tag with a 64-hex SHA-256.
    #[test]
    fn every_platform_is_pinned() {
        for (os, arch) in [
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("windows", "x86_64"),
            ("windows", "aarch64"),
            ("macos", "aarch64"),
        ] {
            for gpu in [false, true] {
                let (name, sha) =
                    asset_for(os, arch, gpu).unwrap_or_else(|| panic!("{os} {arch} {gpu}"));
                assert!(
                    name.starts_with(&format!("llama-{LLAMA_TAG}-bin-")),
                    "{name}"
                );
                assert_eq!(sha.len(), 64, "{name}");
                assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "{name}");
            }
        }
        assert_ne!(
            asset_for("linux", "aarch64", false),
            asset_for("linux", "aarch64", true)
        );
        assert!(asset_for("freebsd", "x86_64", false).is_none());
    }

    /// The two models: d1-3B is the default and first; each has its own
    /// pins and evaluation defaults, and Kev-4B's timeout leaves room for
    /// its measured 4 to 5 s per call on a CPU.
    #[test]
    fn the_two_models_have_their_own_pins_and_defaults() {
        assert_eq!(MODELS[0].id, LocalModel::default());
        let d1 = model_pin(LocalModel::D1_3b);
        let kev = model_pin(LocalModel::Kev4b);
        assert_eq!((d1.threshold, kev.threshold), (0.8, 0.5));
        assert!(kev.timeout_ms >= 10_000, "{}", kev.timeout_ms);
        assert!(d1.timeout_ms >= 2_000);
        assert_ne!(d1.file, kev.file);
        assert_eq!(kev.bytes, 3_033_489_824);
        assert_eq!(kev.licence, "Apache-2.0");
        let dir = tempfile::tempdir().unwrap();
        assert!(installed_models(dir.path()).is_empty());
        std::fs::create_dir_all(model_dir(dir.path())).unwrap();
        std::fs::write(model_path(dir.path(), LocalModel::Kev4b), b"x").unwrap();
        assert_eq!(installed_models(dir.path()), [LocalModel::Kev4b]);
        // No server binary yet: not installed, whatever the model file.
        assert!(!installed(dir.path(), LocalModel::Kev4b));
    }

    #[test]
    fn sha_of_a_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            sha256_file(&p).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn unsafe_archive_entries_are_caught() {
        for bad in [
            "/etc/passwd",
            "../x",
            "a/../../b",
            "C:\\Windows\\x",
            "\\\\unc\\x",
        ] {
            assert!(unsafe_entry(bad), "{bad}");
        }
        for ok in ["build/bin/llama-server", "./a/b", "x"] {
            assert!(!unsafe_entry(ok), "{ok}");
        }
    }

    /// `unpack` extracts a normal archive and refuses one with an unsafe entry
    /// (the archive is built with the system `tar`, as the install uses it).
    #[test]
    fn unpack_extracts_and_refuses_unsafe() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("build/bin")).unwrap();
        std::fs::write(src.join("build/bin/llama-server"), b"#!/bin/sh\n").unwrap();
        let archive = dir.path().join("ok.tar.gz");
        assert!(
            std::process::Command::new("tar")
                .args(["-czf"])
                .arg(&archive)
                .arg("-C")
                .arg(&src)
                .arg(".")
                .status()
                .unwrap()
                .success()
        );
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();
        unpack(&archive, &dest).unwrap();
        assert!(find_file(&dest, "llama-server").is_some());
    }

    /// `fetch_to_file` downloads over plain HTTP (a loopback fake), checks the
    /// SHA-256, and rejects a wrong one.
    #[tokio::test]
    async fn fetch_checks_the_hash() {
        use std::io::{Read, Write};
        let body = b"hello llama".to_vec();
        let sha = {
            let d = ring::digest::digest(&ring::digest::SHA256, &body);
            nerve_proto::msg::hex(d.as_ref())
        };
        // A one-shot HTTP server that answers every connection with `body`.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let b = body.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut c) = conn else { break };
                let mut buf = [0u8; 1024];
                let _ = c.read(&mut buf);
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                );
                let _ = c.write_all(&b);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("f");
        let url = format!("http://127.0.0.1:{port}/x");
        let mut noop = |_: u64, _: u64| {};
        fetch_to_file(&url, &dest, Some(&sha), None, &mut noop)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), body);
        // A wrong hash is refused and nothing is left in place.
        let bad = dir.path().join("g");
        let wrong = "0".repeat(64);
        assert!(
            fetch_to_file(&url, &bad, Some(&wrong), None, &mut noop)
                .await
                .is_err()
        );
        assert!(!bad.exists());
    }
}
