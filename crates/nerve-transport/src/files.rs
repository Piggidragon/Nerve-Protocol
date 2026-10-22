//! Writing state files: atomically, and readable by the owner only.

use std::io::Write;
use std::path::Path;

/// Writes `data` to `path` through a temporary file in the same folder and a
/// rename, so a reader never sees half a file. On Unix the file is created
/// 0600; the folder is created 0700 when missing, and synced after the
/// rename, so the new file is there after a power cut.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    create_private_dir(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let tmp = dir.join(format!(".{name}.{}.tmp", crate::keys::random_token(8)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    // Some file systems cannot sync a folder; the file is written all the
    // same.
    #[cfg(unix)]
    if result.is_ok() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    result
}

/// Creates `dir` (and its parents) with mode 0700 on Unix.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_privately() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/state.toml");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(std::fs::read_dir(p.parent().unwrap()).unwrap().count(), 1);
    }
}
