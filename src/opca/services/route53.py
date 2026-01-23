# opca/services/route53.py

"""AWS Route53 DNS management service."""

from __future__ import annotations

import logging
import os
import subprocess
import time

from opca.utils.formatting import error, warning

log = logging.getLogger(__name__)


class Route53Error(Exception):
    """Base exception for Route53 errors."""
    pass


class Route53NotConfiguredError(Route53Error):
    """Raised when boto3 is not installed or AWS credentials are unavailable."""
    pass


class HostedZoneNotFoundError(Route53Error):
    """Raised when no hosted zone is found for the domain."""
    pass


class MultipleHostedZonesError(Route53Error):
    """Raised when multiple hosted zones match the domain."""

    def __init__(self, message: str, zone_ids: list[str]):
        super().__init__(message)
        self.zone_ids = zone_ids


class RecordExistsError(Route53Error):
    """Raised when a DNS record already exists."""
    pass


def split_txt_value(value: str, max_len: int = 255) -> list[str]:
    """
    Split a long TXT record value into chunks for DNS.

    DNS TXT records have a 255-character limit per string. Long values
    must be split into multiple quoted strings per RFC 4408.

    Args:
        value: The TXT record value to split
        max_len: Maximum length per chunk (default 255)

    Returns:
        List of string chunks, each <= max_len characters
    """
    if len(value) <= max_len:
        return [value]

    chunks = []
    for i in range(0, len(value), max_len):
        chunks.append(value[i:i + max_len])
    return chunks


class Route53:
    """
    AWS Route53 DNS management using 1Password for credentials.

    Follows the same credential pattern as StorageS3: retrieves AWS credentials
    from 1Password using the AWS plugin integration.
    """

    def __init__(self):
        """
        Initialize the Route53 client.

        Raises:
            Route53NotConfiguredError: If boto3 is not installed or credentials fail.
        """
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            self._ClientError = ClientError
            self._NoCredentialsError = NoCredentialsError
        except ImportError:
            raise Route53NotConfiguredError(
                "boto3 is not installed. Install with: pip install opca[aws]"
            )

        # Get AWS credentials from 1Password (same pattern as StorageS3)
        command = [
            "op", "plugin", "run", "--",
            "aws", "configure", "export-credentials", "--format", "env"
        ]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            raise Route53NotConfiguredError(
                "Failed to get AWS credentials from 1Password. "
                "Ensure 1Password CLI is configured with the AWS plugin. "
                f"Error: {result.stderr}"
            )

        # Export credentials to environment
        for line in result.stdout.splitlines():
            if line.startswith("export "):
                var, value = line[len("export "):].split("=", 1)
                os.environ[var] = value

        try:
            self.client = boto3.client("route53")
            # Verify credentials work
            self.client.list_hosted_zones(MaxItems="1")
        except self._NoCredentialsError as e:
            raise Route53NotConfiguredError(
                f"AWS credentials not found or invalid: {e}"
            )
        except self._ClientError as e:
            raise Route53NotConfiguredError(
                f"Failed to connect to Route53: {e}"
            )

    def find_hosted_zone(self, domain: str) -> str:
        """
        Find the hosted zone ID for a domain.

        Walks up the domain hierarchy to find a matching hosted zone.
        For example, for 'sub.example.com', tries:
          1. sub.example.com.
          2. example.com.

        Args:
            domain: The domain name to find a hosted zone for.

        Returns:
            The hosted zone ID (e.g., 'Z1234567890').

        Raises:
            HostedZoneNotFoundError: If no hosted zone is found.
            MultipleHostedZonesError: If multiple zones match (includes zone IDs).
        """
        # Normalize domain (ensure no trailing dot for splitting)
        domain = domain.rstrip(".")
        parts = domain.split(".")

        # Walk up the domain hierarchy
        for i in range(len(parts)):
            candidate = ".".join(parts[i:]) + "."
            zones = self._list_zones_by_name(candidate)

            if zones:
                if len(zones) > 1:
                    zone_ids = [z["Id"].replace("/hostedzone/", "") for z in zones]
                    raise MultipleHostedZonesError(
                        f"Multiple hosted zones found for '{candidate}': {', '.join(zone_ids)}. "
                        "Use --zone-id to specify which zone to use.",
                        zone_ids=zone_ids,
                    )
                return zones[0]["Id"].replace("/hostedzone/", "")

        raise HostedZoneNotFoundError(
            f"No Route53 hosted zone found for domain '{domain}'. "
            "Ensure the domain is hosted in Route53."
        )

    def _list_zones_by_name(self, dns_name: str) -> list[dict]:
        """
        List hosted zones that exactly match the given DNS name.

        Args:
            dns_name: The DNS name to search for (with trailing dot).

        Returns:
            List of matching hosted zone dicts.
        """
        try:
            response = self.client.list_hosted_zones_by_name(
                DNSName=dns_name,
                MaxItems="10",
            )
        except self._ClientError as e:
            log.error(f"Failed to list hosted zones: {e}")
            return []

        # Filter to exact matches only
        return [
            zone for zone in response.get("HostedZones", [])
            if zone["Name"] == dns_name
        ]

    def txt_record_exists(self, zone_id: str, record_name: str) -> bool:
        """
        Check if a TXT record already exists.

        Args:
            zone_id: The hosted zone ID.
            record_name: The full DNS record name (e.g., 'selector._domainkey.example.com').

        Returns:
            True if the record exists, False otherwise.
        """
        # Ensure trailing dot
        if not record_name.endswith("."):
            record_name = record_name + "."

        try:
            response = self.client.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=record_name,
                StartRecordType="TXT",
                MaxItems="1",
            )
        except self._ClientError as e:
            log.error(f"Failed to check record existence: {e}")
            return False

        for record_set in response.get("ResourceRecordSets", []):
            if record_set["Name"] == record_name and record_set["Type"] == "TXT":
                return True

        return False

    def create_txt_record(
        self,
        zone_id: str,
        record_name: str,
        value: str,
        ttl: int = 300,
    ) -> bool:
        """
        Create a TXT record in Route53.

        Auto-splits values longer than 255 characters into multiple strings
        per RFC 4408.

        Args:
            zone_id: The hosted zone ID.
            record_name: The full DNS record name.
            value: The TXT record value.
            ttl: Time-to-live in seconds (default 300).

        Returns:
            True if the record was created successfully.

        Raises:
            RecordExistsError: If the record already exists.
            Route53Error: If the API call fails.
        """
        # Ensure trailing dot
        if not record_name.endswith("."):
            record_name = record_name + "."

        # Check if record exists
        if self.txt_record_exists(zone_id, record_name):
            raise RecordExistsError(
                f"TXT record '{record_name}' already exists. "
                "Delete the existing record first or use a different selector."
            )

        # Split long values into chunks
        chunks = split_txt_value(value)

        # Format as quoted strings for Route53
        # Route53 expects: "chunk1" "chunk2" "chunk3"
        formatted_value = " ".join(f'"{chunk}"' for chunk in chunks)

        change_batch = {
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": formatted_value}],
                    },
                }
            ]
        }

        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=change_batch,
            )
            log.info(f"Created TXT record: {record_name} (change ID: {response['ChangeInfo']['Id']})")
            return True
        except self._ClientError as e:
            raise Route53Error(f"Failed to create TXT record: {e}")

    def verify_dns_record(
        self,
        record_name: str,
        expected_value: str,
        timeout: int = 60,
        interval: int = 5,
    ) -> bool:
        """
        Verify that a DNS TXT record is published and contains the expected value.

        Uses Python's socket module to query DNS. Falls back to a simple check
        if dns.resolver is not available.

        Args:
            record_name: The DNS record name to query.
            expected_value: The expected TXT record value.
            timeout: Maximum time to wait in seconds (default 60).
            interval: Time between retries in seconds (default 5).

        Returns:
            True if the record is verified, False otherwise (logs warning).
        """
        # Try to use dnspython if available, otherwise use subprocess with dig
        try:
            import dns.resolver
            return self._verify_with_dnspython(
                record_name, expected_value, timeout, interval
            )
        except ImportError:
            return self._verify_with_dig(
                record_name, expected_value, timeout, interval
            )

    def _verify_with_dnspython(
        self,
        record_name: str,
        expected_value: str,
        timeout: int,
        interval: int,
    ) -> bool:
        """Verify DNS record using dnspython."""
        import dns.resolver

        start_time = time.time()
        # Extract the p= value for comparison (ignoring formatting differences)
        expected_key = self._extract_dkim_key(expected_value)

        while time.time() - start_time < timeout:
            try:
                answers = dns.resolver.resolve(record_name, "TXT")
                for rdata in answers:
                    txt_value = b"".join(rdata.strings).decode("utf-8")
                    if expected_key and expected_key in txt_value:
                        return True
                    if expected_value in txt_value:
                        return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                log.debug(f"DNS query error: {e}")

            time.sleep(interval)

        warning(f"DNS verification timed out for {record_name}")
        return False

    def _verify_with_dig(
        self,
        record_name: str,
        expected_value: str,
        timeout: int,
        interval: int,
    ) -> bool:
        """Verify DNS record using dig command."""
        start_time = time.time()
        expected_key = self._extract_dkim_key(expected_value)

        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    ["dig", "+short", "TXT", record_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    # dig returns quoted strings, remove quotes
                    txt_value = result.stdout.replace('"', "").replace("\n", "").strip()
                    if expected_key and expected_key in txt_value:
                        return True
                    if expected_value in txt_value:
                        return True
            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                warning("dig command not found, skipping DNS verification")
                return False
            except Exception as e:
                log.debug(f"dig error: {e}")

            time.sleep(interval)

        warning(f"DNS verification timed out for {record_name}")
        return False

    def _extract_dkim_key(self, value: str) -> str | None:
        """Extract the public key portion (p=...) from a DKIM record."""
        if "p=" in value:
            # Extract everything after p=
            parts = value.split("p=")
            if len(parts) > 1:
                # Take the key, stopping at any semicolon or end
                key = parts[1].split(";")[0].strip()
                return key
        return None
