# opca/services/storage.py

import os
import subprocess
import tempfile
from abc import ABC, abstractmethod
from urllib.parse import urlparse

from opca.utils.formatting import error, warning

class StorageBackend(ABC):
    """ An abstract base class for storage """
    @abstractmethod
    def upload(self, content: str, uri: str):
        pass


class StorageRsync(StorageBackend):
    """ A Rsync storage backend """
    def upload(self, content: str, uri: str) -> bool:
        """
        Uploads content to Rsync

        Args:
            content (str): The content to upload
            uri (str): The S3 URI in the format s3://bucket/key

        Returns:
            bool: Upload status

        Raises:
            None
        """
        parsed_uri = urlparse(uri)

        if parsed_uri.scheme != 'rsync':
            warning(f'Invalid URI scheme: {parsed_uri.scheme}')
            return False

        destination = f'{parsed_uri.netloc}{parsed_uri.path}'

        try:
            with tempfile.NamedTemporaryFile('w', delete=False) as tmp_file:
                tmp_file.write(content)

            result = subprocess.run(
                ['rsync', '-avz', tmp_file.name, destination],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f'Rsync failed:\n{result.stderr}')
                return False

            return True

        except Exception as e:
            error(f'Upload failed: {e}')
            return False

        finally:
            if tmp_file.name and os.path.exists(tmp_file.name):
                try:
                    os.remove(tmp_file.name)
                except Exception as cleanup_error:
                    warning(f'Failed to delete temp file: {cleanup_error}')


class StorageS3(StorageBackend):
    """ A S3 storage backend """
    def __init__(self):
        try:
            import boto3
        except:
            error('boto3 not installed. S3 Uploads will be disabled.')

        command = ["op", "plugin", "run", "--", "aws", "configure", "export-credentials", "--format", "env"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("export "):
                    var, value = line[len("export "):].split("=", 1)
                    os.environ[var] = value

            self.s3 = boto3.client('s3')
        else:
            error(f'Error: {result.stderr}')
            self.s3 = None


    def upload(self, content: str, uri: str) -> bool:
        """
        Uploads content to S3

        Args:
            content (str): The content to upload
            uri (str): The S3 URI in the format s3://bucket/key

        Returns:
            bool: Upload status

        Raises:
            None
        """
        if not self.s3:
            error('S3 client not available. Skipping upload.')
            return False

        parsed_uri = urlparse(uri)

        if parsed_uri.scheme != 's3':
            warning(f'Invalid URI scheme: {parsed_uri.scheme}')
            return False

        bucket = parsed_uri.netloc
        key = parsed_uri.path.lstrip('/')

        try:
            self.s3.put_object(Bucket=bucket, Key=key, Body=content)
            return True
        except Exception as e:
            error(f'Upload failed: {e}')
            return False

