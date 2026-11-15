//! Persistent user script library: save/load/list `.rhai` scripts on disk.
//!
//! The core functions take an explicit directory (so they are trivially testable
//! without touching the real config dir); the public wrappers use the per-user
//! config location, overridable with `BEWITCHED_SCRIPT_DIR`.

use std::io;
use std::path::{Path, PathBuf};

/// The directory where user scripts live.
pub fn scripts_dir() -> PathBuf {
    if let Ok(d) = std::env::var("BEWITCHED_SCRIPT_DIR") {
        return PathBuf::from(d);
    }
    let mut p = super::config_dir();
    p.push("scripts");
    p
}

/// Strip a name to safe filename characters (no path traversal).
fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim().to_string();
    if s.is_empty() {
        "untitled".to_string()
    } else {
        s
    }
}

/// List `(name, path)` of `.rhai` scripts in `dir`, sorted by name.
pub fn list_in(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rhai") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    out.push((stem.to_string(), path));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Save `src` as `<dir>/<sanitized-name>.rhai`, returning the path.
pub fn save_in(dir: &Path, name: &str, src: &str) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.rhai", sanitize(name)));
    std::fs::write(&path, src)?;
    Ok(path)
}

pub fn load_in(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(format!("{}.rhai", sanitize(name)))).ok()
}

pub fn delete_in(dir: &Path, name: &str) -> io::Result<()> {
    std::fs::remove_file(dir.join(format!("{}.rhai", sanitize(name))))
}

// ---- convenience wrappers over the user config dir ----

pub fn list() -> Vec<(String, PathBuf)> {
    list_in(&scripts_dir())
}
pub fn save(name: &str, src: &str) -> io::Result<PathBuf> {
    save_in(&scripts_dir(), name, src)
}
pub fn load(name: &str) -> Option<String> {
    load_in(&scripts_dir(), name)
}
pub fn delete(name: &str) -> io::Result<()> {
    delete_in(&scripts_dir(), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "bewitched_scripts_{:?}_{}",
            std::thread::current().id(),
            C.fetch_add(1, Ordering::Relaxed)
        ));
        d
    }

    #[test]
    fn save_list_load_delete_roundtrip() {
        let dir = tmpdir();
        assert!(list_in(&dir).is_empty());
        save_in(&dir, "my xor", "write(0, 0xFF);").unwrap();
        save_in(&dir, "rotate", "// rot").unwrap();

        let names: Vec<String> = list_in(&dir).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["my xor", "rotate"]);
        assert_eq!(load_in(&dir, "my xor").unwrap(), "write(0, 0xFF);");

        delete_in(&dir, "rotate").unwrap();
        assert_eq!(list_in(&dir).len(), 1);
        assert!(load_in(&dir, "rotate").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_is_sanitized() {
        let dir = tmpdir();
        // path traversal characters are neutralized
        let p = save_in(&dir, "../../etc/passwd", "x").unwrap();
        assert!(p.starts_with(&dir));
        assert!(p.file_name().unwrap().to_str().unwrap().ends_with(".rhai"));
        assert!(!p.to_string_lossy().contains(".."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_name_becomes_untitled() {
        assert_eq!(sanitize("   "), "untitled");
        assert_eq!(sanitize("ok name-1"), "ok name-1");
    }
}
