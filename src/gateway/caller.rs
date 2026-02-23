// Keystone — Caller Verification
//
// Identifies the process connecting over the Unix domain socket by
// reading peer credentials and resolving /proc/<pid>/exe to compute
// a SHA-256 fingerprint of the calling binary. This provides a trust
// anchor for audit logging.

use std::fs;
use std::io;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Information about the process that connected to the UDS.
#[derive(Debug, Clone)]
pub struct CallerInfo {
    /// Process ID of the caller.
    pub pid: u32,
    /// Resolved path to the caller's executable binary.
    pub exe_path: PathBuf,
    /// SHA-256 hex digest of the caller's executable binary.
    pub exe_hash: String,
}

impl CallerInfo {
    /// Build caller info from a process ID.
    ///
    /// On Linux, reads `/proc/<pid>/exe` to resolve the binary path and
    /// computes a SHA-256 hash of the binary for fingerprinting.
    pub fn from_pid(pid: u32) -> io::Result<Self> {
        let proc_exe = format!("/proc/{}/exe", pid);
        let exe_path = fs::read_link(&proc_exe)?;

        let binary = fs::read(&exe_path)?;
        let hash = Sha256::digest(&binary);
        let exe_hash = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        Ok(Self {
            pid,
            exe_path,
            exe_hash,
        })
    }

    /// Return a short actor string for audit logging.
    pub fn actor_string(&self) -> String {
        format!(
            "pid:{} exe:{} hash:{}",
            self.pid,
            self.exe_path.display(),
            &self.exe_hash[..16] // First 16 hex chars for brevity
        )
    }
}

impl std::fmt::Display for CallerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PID {} ({}) [{}…]",
            self.pid,
            self.exe_path.display(),
            &self.exe_hash[..16]
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caller_info_for_current_process() {
        let pid = std::process::id();
        let info = CallerInfo::from_pid(pid);

        // This test only works on Linux (where /proc exists)
        if cfg!(target_os = "linux") {
            let info = info.expect("Should resolve current process");
            assert_eq!(info.pid, pid);
            assert!(!info.exe_path.as_os_str().is_empty());
            assert_eq!(info.exe_hash.len(), 64); // SHA-256 hex = 64 chars
        }
    }

    #[test]
    fn test_actor_string_format() {
        let info = CallerInfo {
            pid: 12345,
            exe_path: PathBuf::from("/usr/bin/test"),
            exe_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
        };

        let actor = info.actor_string();
        assert!(actor.contains("pid:12345"));
        assert!(actor.contains("exe:/usr/bin/test"));
        assert!(actor.contains("hash:abcdef0123456789"));
    }

    #[test]
    fn test_display_format() {
        let info = CallerInfo {
            pid: 42,
            exe_path: PathBuf::from("/usr/bin/agent"),
            exe_hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
        };

        let display = format!("{}", info);
        assert!(display.contains("PID 42"));
        assert!(display.contains("/usr/bin/agent"));
    }

    #[test]
    fn test_nonexistent_pid_fails() {
        // PID 0 is the kernel, /proc/0/exe won't be readable
        let result = CallerInfo::from_pid(0);
        assert!(result.is_err());
    }
}
