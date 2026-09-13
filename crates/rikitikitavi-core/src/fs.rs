//! Owner-only file and directory creation for scan output.

use std::io::{self, Write as _};
use std::path::Path;

/// Write `bytes` to `path`, creating or truncating it. Mode `0o600` on Unix, existing files
/// included.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_private(path)?;
    file.write_all(bytes)?;
    file.flush()
}

/// Create `path` and any missing parents. Mode `0o700` on Unix; an existing leaf is re-chmodded,
/// existing parents are left alone.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn open_private(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    if file.metadata()?.is_file() {
        // Devices and pipes keep their mode; filesystems without modes (vfat) are tolerated.
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600))
            && !matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            )
        {
            return Err(e);
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn write_private_writes_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_private(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn write_private_truncates_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_private(&path, b"a much longer first write").unwrap();
        write_private(&path, b"short").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"short");
    }

    #[test]
    fn write_private_missing_parent_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("out.txt");
        assert!(write_private(&path, b"x").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn write_private_creates_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        write_private(&path, b"secret").unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_rechmods_existing_0644_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.txt");
        std::fs::write(&path, b"old").unwrap();
        chmod(&path, 0o644);
        assert_eq!(mode_of(&path), 0o644);
        write_private(&path, b"new").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn create_private_dir_creates_nested() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("c");
        create_private_dir(&path).unwrap();
        assert!(path.is_dir());
    }

    #[test]
    fn create_private_dir_existing_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a");
        create_private_dir(&path).unwrap();
        create_private_dir(&path).unwrap();
        assert!(path.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_creates_mode_0700_recursively() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("a");
        let path = parent.join("b");
        create_private_dir(&path).unwrap();
        assert_eq!(mode_of(&parent), 0o700);
        assert_eq!(mode_of(&path), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_rechmods_existing_0755_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("a");
        let path = parent.join("b");
        std::fs::create_dir_all(&path).unwrap();
        chmod(&parent, 0o755);
        chmod(&path, 0o755);
        create_private_dir(&path).unwrap();
        assert_eq!(mode_of(&path), 0o700);
        assert_eq!(mode_of(&parent), 0o755);
    }
    #[cfg(unix)]
    #[test]
    fn write_private_accepts_dev_null() {
        write_private(Path::new("/dev/null"), b"x").unwrap();
    }
}
