//! Storage backends for publishing CA artefacts (certificates, CRLs, database).
//!
//! Each backend lives in its own sub-module:
//! - [`rsync`] — uploads via `rsync -avz` over SSH
//! - [`s3`]    — uploads to AWS S3 using credentials from the `op` CLI plugin

pub mod rsync;
pub mod s3;

use std::collections::HashMap;

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
/// export-credentials --format env` through the provided command runner.
pub fn get_aws_credentials<R: CommandRunner>(runner: &R) -> Result<AwsCredentials, OpcaError> {
    let output = runner.run(
        "op",
        &[
            "plugin", "run", "--", "aws", "configure",
            "export-credentials", "--format", "env",
        ],
        None,
        None,
    )?;

    let stdout = &output.stdout;

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

    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token: env.get("AWS_SESSION_TOKEN").cloned(),
        region: env.get("AWS_DEFAULT_REGION")
            .or_else(|| env.get("AWS_REGION"))
            .cloned(),
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
    fn test_get_aws_credentials_parses_env() {
        let runner = MockRunner {
            stdout: "export AWS_ACCESS_KEY_ID=AKIA1234\nexport AWS_SECRET_ACCESS_KEY=secret123\nexport AWS_SESSION_TOKEN=tok456\nexport AWS_DEFAULT_REGION=ap-southeast-2\n".into(),
            success: true,
        };
        let creds = get_aws_credentials(&runner).unwrap();
        assert_eq!(creds.access_key_id, "AKIA1234");
        assert_eq!(creds.secret_access_key, "secret123");
        assert_eq!(creds.session_token.as_deref(), Some("tok456"));
        assert_eq!(creds.region.as_deref(), Some("ap-southeast-2"));
    }

    #[test]
    fn test_get_aws_credentials_missing_key() {
        let runner = MockRunner {
            stdout: "export AWS_SECRET_ACCESS_KEY=secret123\n".into(),
            success: true,
        };
        let result = get_aws_credentials(&runner);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_aws_credentials_runner_failure() {
        let runner = MockRunner {
            stdout: String::new(),
            success: false,
        };
        let result = get_aws_credentials(&runner);
        assert!(result.is_err());
    }
}
