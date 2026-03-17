//! Storage backends for publishing CA artefacts (certificates, CRLs, database).
//!
//! Each backend lives in its own sub-module:
//! - [`rsync`] — uploads via `rsync -avz` over SSH
//! - [`s3`]    — uploads to AWS S3 using credentials from the `op` CLI plugin

pub mod rsync;
pub mod s3;

use std::collections::HashMap;

use log::{debug, error, info};

use crate::error::OpcaError;
use crate::op::CommandRunner;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A backend that can upload content to a remote location and verify
/// connectivity.
pub trait StorageBackend {
    /// Upload `content` to the given `uri`.
    fn upload(&self, content: &[u8], uri: &str) -> Result<(), OpcaError>;

    /// Test that the backend can reach the remote target.
    fn test_connection(&self, uri: &str) -> Result<(), OpcaError>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Parse a URI scheme and return the appropriate storage backend.
///
/// For `s3://` URIs the `runner` is used to retrieve AWS credentials from
/// the 1Password CLI plugin.  Other schemes ignore the runner.
pub fn storage_from_uri<R: CommandRunner>(
    uri: &str,
    runner: &R,
) -> Result<Box<dyn StorageBackend>, OpcaError> {
    let scheme = uri
        .split("://")
        .next()
        .unwrap_or("")
        .to_lowercase();

    match scheme.as_str() {
        "rsync" => Ok(Box::new(rsync::StorageRsync)),
        "s3" => {
            let creds = get_aws_credentials(runner)?;
            Ok(Box::new(s3::StorageS3::new(creds)))
        }
        other => Err(OpcaError::Storage(format!(
            "Unsupported storage scheme: {other}"
        ))),
    }
}

/// Like [`storage_from_uri`] but accepts pre-fetched AWS credentials,
/// avoiding a redundant `op plugin run` call when testing multiple S3 stores.
pub fn storage_from_uri_with_creds(
    uri: &str,
    aws_creds: Option<&AwsCredentials>,
) -> Result<Box<dyn StorageBackend>, OpcaError> {
    let scheme = uri
        .split("://")
        .next()
        .unwrap_or("")
        .to_lowercase();

    match scheme.as_str() {
        "rsync" => Ok(Box::new(rsync::StorageRsync)),
        "s3" => {
            let creds = aws_creds
                .ok_or_else(|| OpcaError::Storage("AWS credentials required for S3 stores".into()))?;
            Ok(Box::new(s3::StorageS3::new(creds.clone())))
        }
        other => Err(OpcaError::Storage(format!(
            "Unsupported storage scheme: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// AWS credential helpers
// ---------------------------------------------------------------------------

/// AWS credentials retrieved from the 1Password CLI plugin.
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
}

/// Retrieve AWS credentials by running `op plugin run -- aws configure
/// export-credentials --format env`.
///
/// This spawns the process directly rather than going through
/// [`CommandRunner`] because `op plugin run` can take several minutes in
/// macOS hardened-runtime builds (AMFI verification of `op` + `aws`
/// binaries, plus STS network calls).
pub fn get_aws_credentials<R: CommandRunner>(_runner: &R) -> Result<AwsCredentials, OpcaError> {
    use std::process::Command;
    use std::time::{Duration, Instant};

    info!("[storage] retrieving AWS credentials via op plugin");

    let op_bin = which::which("op")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "op".to_string());

    debug!("[storage] running: {op_bin} plugin run -- aws configure export-credentials --format env");

    let mut child = Command::new(&op_bin)
        .args(["plugin", "run", "--", "aws", "configure", "export-credentials", "--format", "env"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| OpcaError::Storage(format!("Failed to spawn op plugin: {e}")))?;

    // Allow up to 5 minutes — op plugin run chains op → aws → STS and each
    // binary gets AMFI-verified on macOS hardened-runtime builds.
    let timeout = Duration::from_secs(300);
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    error!("[storage] op plugin run timed out after {}s", timeout.as_secs());
                    return Err(OpcaError::Storage(format!(
                        "op plugin run timed out after {}s",
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(OpcaError::Storage(format!("op plugin wait error: {e}"))),
        }
    }

    let elapsed = start.elapsed();
    let output = child.wait_with_output()
        .map_err(|e| OpcaError::Storage(format!("op plugin output error: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("[storage] op plugin failed (exit {:?}) in {:.1}s: {}", output.status.code(), elapsed.as_secs_f64(), stderr.trim());
        return Err(OpcaError::Storage(format!(
            "op plugin run failed: {}",
            stderr.trim()
        )));
    }

    debug!("[storage] op plugin run succeeded in {:.1}s", elapsed.as_secs_f64());
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_aws_credentials(&stdout)
}

/// Parse AWS credentials from the `export KEY=VALUE` format output.
fn parse_aws_credentials(stdout: &str) -> Result<AwsCredentials, OpcaError> {
    let mut env: HashMap<String, String> = HashMap::new();
    for line in stdout.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((key, value)) = line.split_once('=') {
            env.insert(key.to_string(), value.to_string());
        }
    }

    let access_key_id = env
        .get("AWS_ACCESS_KEY_ID")
        .cloned()
        .ok_or_else(|| OpcaError::Storage("AWS_ACCESS_KEY_ID not found in op output".into()))?;

    let secret_access_key = env
        .get("AWS_SECRET_ACCESS_KEY")
        .cloned()
        .ok_or_else(|| {
            OpcaError::Storage("AWS_SECRET_ACCESS_KEY not found in op output".into())
        })?;

    let region = env.get("AWS_DEFAULT_REGION")
        .or_else(|| env.get("AWS_REGION"))
        .cloned();

    debug!("[storage] AWS credentials obtained (region: {:?})", region);

    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token: env.get("AWS_SESSION_TOKEN").cloned(),
        region,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::CommandOutput;

    struct MockRunner {
        stdout: String,
        success: bool,
    }

    impl CommandRunner for MockRunner {
        fn run(
            &self,
            _bin: &str,
            _args: &[&str],
            _input: Option<&str>,
            _env_vars: Option<&HashMap<String, String>>,
        ) -> Result<CommandOutput, OpcaError> {
            if self.success {
                Ok(CommandOutput {
                    stdout: self.stdout.clone(),
                    stderr: String::new(),
                    success: true,
                })
            } else {
                Err(OpcaError::Storage("mock runner failure".into()))
            }
        }
    }

    fn mock_runner() -> MockRunner {
        MockRunner {
            stdout: String::new(),
            success: true,
        }
    }

    #[test]
    fn test_storage_from_uri_rsync() {
        let runner = mock_runner();
        let backend = storage_from_uri("rsync://host/path", &runner);
        assert!(backend.is_ok());
    }

    #[test]
    fn test_storage_from_uri_unknown() {
        let runner = mock_runner();
        let result = storage_from_uri("ftp://host/path", &runner);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aws_credentials_full() {
        let output = "export AWS_ACCESS_KEY_ID=AKIA1234\nexport AWS_SECRET_ACCESS_KEY=secret123\nexport AWS_SESSION_TOKEN=tok456\nexport AWS_DEFAULT_REGION=ap-southeast-2\n";
        let creds = parse_aws_credentials(output).unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(creds.secret_access_key, "secret123");
        assert_eq!(creds.session_token.as_deref(), Some("tok456"));
        assert_eq!(creds.region.as_deref(), Some("ap-southeast-2"));
    }

    #[test]
    fn test_parse_aws_credentials_missing_key() {
        let output = "export AWS_SECRET_ACCESS_KEY=secret123\n";
        let result = parse_aws_credentials(output);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aws_credentials_empty() {
        let result = parse_aws_credentials("");
        assert!(result.is_err());
    }
}
