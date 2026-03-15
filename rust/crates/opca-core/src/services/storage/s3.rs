//! Amazon S3 storage backend.
//!
//! Uploads content to AWS S3 buckets using the `rust-s3` crate.  Credentials
//! are obtained from 1Password via the `op` CLI plugin (see
//! [`super::get_aws_credentials`]).
//!
//! URI format: `s3://bucket/key/prefix`

use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::Region;

use crate::error::OpcaError;

use super::{AwsCredentials, StorageBackend};

/// S3-based storage backend.
pub struct StorageS3 {
    credentials: AwsCredentials,
}

impl StorageS3 {
    /// Create a new S3 backend with the given credentials.
    pub fn new(credentials: AwsCredentials) -> Self {
        Self { credentials }
    }

    /// Build a `Bucket` handle from the URI and stored credentials.
    fn bucket_from_uri(&self, uri: &str) -> Result<(Box<Bucket>, String), OpcaError> {
        let (bucket_name, key) = parse_s3_uri(uri)?;

        let region = match &self.credentials.region {
            Some(r) => r.parse::<Region>().unwrap_or(Region::ApSoutheast2),
            None => Region::ApSoutheast2,
        };

        let creds = Credentials::new(
            Some(&self.credentials.access_key_id),
            Some(&self.credentials.secret_access_key),
            self.credentials.session_token.as_deref(),
            None, // token expiry
            None, // profile
        )
        .map_err(|e| OpcaError::Storage(format!("Failed to create S3 credentials: {e}")))?;

        let bucket = Bucket::new(&bucket_name, region, creds)
            .map_err(|e| OpcaError::Storage(format!("Failed to create S3 bucket handle: {e}")))?;

        Ok((bucket, key))
    }
}

/// Run an async future on the current tokio runtime (if one exists) or
/// create a temporary one.  This avoids panicking when called from inside
/// a Tauri async command handler.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        // We are already inside a tokio runtime (e.g. Tauri).
        // Use block_in_place so we don't block an async worker.
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        // No runtime — create a lightweight one.
        tokio::runtime::Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(fut)
    }
}

impl StorageBackend for StorageS3 {
    fn upload(&self, content: &[u8], uri: &str) -> Result<(), OpcaError> {
        let (bucket, key) = self.bucket_from_uri(uri)?;

        block_on(async {
            let response = bucket
                .put_object(&key, content)
                .await
                .map_err(|e| OpcaError::Storage(format!("S3 put_object failed: {e}")))?;

            if response.status_code() >= 300 {
                return Err(OpcaError::Storage(format!(
                    "S3 put_object returned status {}",
                    response.status_code()
                )));
            }

            Ok(())
        })
    }

    fn test_connection(&self, uri: &str) -> Result<(), OpcaError> {
        let (bucket, _key) = self.bucket_from_uri(uri)?;

        block_on(async {
            // A HEAD on the bucket root verifies both credentials and bucket
            // existence.  list_page with max_keys=0 is another option but
            // HEAD is cheaper.
            let results = bucket
                .list("".to_string(), Some("/".to_string()))
                .await
                .map_err(|e| OpcaError::Storage(format!("S3 connection test failed: {e}")))?;

            // If we got here without error, the credentials and bucket are
            // valid.  We don't care about the listing contents.
            let _ = results;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// URI parsing
// ---------------------------------------------------------------------------

/// Parse an `s3://bucket/key` URI into (bucket, key).
fn parse_s3_uri(uri: &str) -> Result<(String, String), OpcaError> {
    let rest = uri
        .strip_prefix("s3://")
        .ok_or_else(|| OpcaError::Storage(format!("Invalid S3 URI: {uri}")))?;

    let (bucket, key) = rest
        .split_once('/')
        .ok_or_else(|| OpcaError::Storage(format!("S3 URI missing key path: {uri}")))?;

    if bucket.is_empty() {
        return Err(OpcaError::Storage("Empty S3 bucket name".into()));
    }

    Ok((bucket.to_string(), key.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_uri() {
        let (bucket, key) = parse_s3_uri("s3://my-bucket/prefix/file.pem").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "prefix/file.pem");
    }

    #[test]
    fn test_parse_s3_uri_root_key() {
        let (bucket, key) = parse_s3_uri("s3://my-bucket/file.pem").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "file.pem");
    }

    #[test]
    fn test_parse_s3_uri_trailing_slash() {
        let (bucket, key) = parse_s3_uri("s3://my-bucket/prefix/").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "prefix/");
    }

    #[test]
    fn test_parse_s3_uri_no_key() {
        let result = parse_s3_uri("s3://my-bucket");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_s3_uri_empty_bucket() {
        let result = parse_s3_uri("s3:///key");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_s3_uri_wrong_scheme() {
        let result = parse_s3_uri("rsync://host/path");
        assert!(result.is_err());
    }
}
