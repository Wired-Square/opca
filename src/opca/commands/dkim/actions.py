# opca/commands/dkim/actions.py

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from opca.models import App
from opca.constants import (
    DEFAULT_KEY_SIZE,
    EXIT_OK,
    EXIT_FATAL,
    COLOUR_BRIGHT,
    COLOUR_OK,
    COLOUR_RESET,
    COLOUR_WARNING,
)
from opca.utils.formatting import error, print_result, title, warning

log = logging.getLogger(__name__)

# DKIM-specific constants
DKIM_ITEM_PREFIX = "DKIM"


def _deploy_to_route53(
    domain: str,
    selector: str,
    dns_record: str,
    zone_id: str | None = None,
) -> None:
    """
    Deploy DKIM record to Route53.

    Args:
        domain: The domain name.
        selector: The DKIM selector.
        dns_record: The DNS TXT record value.
        zone_id: Optional Route53 hosted zone ID.

    Raises:
        Route53NotConfiguredError: boto3 not installed or credentials unavailable.
        HostedZoneNotFoundError: Domain not in Route53.
        MultipleHostedZonesError: Multiple zones match, need --zone-id.
        RecordExistsError: TXT record already exists.
    """
    from opca.services.route53 import Route53

    r53 = Route53()
    dns_name = f"{selector}._domainkey.{domain}"

    # Find hosted zone (or use provided zone_id)
    title(f"Finding Route53 hosted zone for {COLOUR_BRIGHT}{domain}{COLOUR_RESET}", 9)
    if not zone_id:
        zone_id = r53.find_hosted_zone(domain)
    print_result(True)

    # Check if record exists (fail if so)
    title(f"Checking if TXT record exists [ {COLOUR_BRIGHT}{dns_name}{COLOUR_RESET} ]", 9)
    if r53.txt_record_exists(zone_id, dns_name):
        print_result(False)
        from opca.services.route53 import RecordExistsError
        raise RecordExistsError(f"TXT record '{dns_name}' already exists")
    print_result(True)

    # Create TXT record (auto-splits long values)
    title("Deploying TXT record to Route53", 9)
    r53.create_txt_record(zone_id, dns_name, dns_record)
    print_result(True)


def _make_dkim_item_title(domain: str, selector: str) -> str:
    """Generate the 1Password item title for a DKIM key."""
    return f"{DKIM_ITEM_PREFIX}_{domain}_{selector}"


def _generate_dkim_keypair(key_size: int) -> tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """
    Generate an RSA key pair for DKIM.

    Returns:
        tuple: (private_key_object, private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key, private_key_pem, public_key_pem


def _format_dkim_dns_record(public_key_pem: bytes) -> str:
    """
    Format the public key for DKIM DNS TXT record.

    Strips PEM headers/footers and removes newlines to create the base64 blob.
    Returns the complete DNS record value: v=DKIM1; k=rsa; p=<base64_pubkey>
    """
    pem_str = public_key_pem.decode("utf-8")

    # Remove PEM headers and footers
    lines = pem_str.strip().split("\n")
    base64_lines = [line for line in lines if not line.startswith("-----")]

    # Join without newlines
    base64_pubkey = "".join(base64_lines)

    return f"v=DKIM1; k=rsa; p={base64_pubkey}"


def handle_dkim_create(app: App) -> int:
    """
    Generate a new DKIM key pair and store it in 1Password.
    """
    domain = app.args.domain
    selector = app.args.selector
    key_size = getattr(app.args, "key_size", DEFAULT_KEY_SIZE.get("dkim", 2048))

    item_title = _make_dkim_item_title(domain, selector)
    dns_name = f"{selector}._domainkey.{domain}"

    title(f"Create DKIM Key for {COLOUR_BRIGHT}{domain}{COLOUR_RESET}", level=2)

    # Check if item already exists
    title(f"Checking for existing DKIM key [ {COLOUR_BRIGHT}{item_title}{COLOUR_RESET} ]", 9)
    if app.op.item_exists(item_title):
        print_result(False)
        error(
            f"DKIM key '{item_title}' already exists. "
            "Delete it first or use a different selector.",
            0,
        )
        return EXIT_FATAL
    print_result(True)

    # Generate key pair
    title(f"Generating {COLOUR_BRIGHT}{key_size}-bit{COLOUR_RESET} RSA key pair", 9)
    try:
        private_key, private_key_pem, public_key_pem = _generate_dkim_keypair(key_size)
        print_result(True)
    except Exception as e:
        print_result(False)
        error(f"Failed to generate key pair: {e}", 0)
        return EXIT_FATAL

    # Format DNS record
    title("Formatting DNS TXT record", 9)
    dns_record = _format_dkim_dns_record(public_key_pem)
    print_result(True)

    # Prepare 1Password attributes
    created_at = datetime.now(timezone.utc).isoformat()

    attributes = [
        f"domain[text]={domain}",
        f"selector[text]={selector}",
        f"key_size[text]={key_size}",
        f"private_key={private_key_pem.decode('utf-8')}",
        f"public_key[text]={public_key_pem.decode('utf-8')}",
        f"dns_record[text]={dns_record}",
        f"dns_name[text]={dns_name}",
        f"created_at[text]={created_at}",
    ]

    # Store in 1Password
    title(f"Storing DKIM key in 1Password [ {COLOUR_BRIGHT}{item_title}{COLOUR_RESET} ]", 9)
    result = app.op.store_item(
        item_title=item_title,
        attributes=attributes,
        action="create",
        category="Secure Note",
    )
    print_result(result.returncode == 0)

    if result.returncode != 0:
        error(f"Failed to store DKIM key: {result.stderr}", 0)
        return EXIT_FATAL

    # Deploy to Route53 if requested
    route53_deployed = False
    if getattr(app.args, "deploy_route53", False):
        zone_id = getattr(app.args, "zone_id", None)
        try:
            _deploy_to_route53(domain, selector, dns_record, zone_id)
            route53_deployed = True
        except Exception as e:
            error(str(e), 0)
            return EXIT_FATAL

    # Print summary
    if route53_deployed:
        print(f"\n{COLOUR_OK}DKIM key created and deployed successfully!{COLOUR_RESET}\n")
    else:
        print(f"\n{COLOUR_OK}DKIM key created successfully!{COLOUR_RESET}\n")

    print(f"Domain:    {COLOUR_BRIGHT}{domain}{COLOUR_RESET}")
    print(f"Selector:  {COLOUR_BRIGHT}{selector}{COLOUR_RESET}")
    print(f"Key Size:  {COLOUR_BRIGHT}{key_size} bits{COLOUR_RESET}")
    print(f"1Password: {COLOUR_BRIGHT}{item_title}{COLOUR_RESET}")

    if route53_deployed:
        print(f"Route53:   {COLOUR_OK}Deployed{COLOUR_RESET}")
        print(f"\n{COLOUR_WARNING}Note: Run 'dkim verify' to confirm DNS propagation.{COLOUR_RESET}")

    print(f"\nDNS Record Name: {COLOUR_BRIGHT}{dns_name}{COLOUR_RESET}")
    print("\nDNS TXT Record Value:")
    print(dns_record)

    return EXIT_OK


def handle_dkim_info(app: App) -> int:
    """
    Display DKIM key information from 1Password.
    """
    domain = app.args.domain
    selector = app.args.selector

    item_title = _make_dkim_item_title(domain, selector)

    title(f"DKIM Key Information for {COLOUR_BRIGHT}{domain}{COLOUR_RESET}", level=2)

    # Check if item exists
    title(f"Retrieving DKIM key [ {COLOUR_BRIGHT}{item_title}{COLOUR_RESET} ]", 9)
    if not app.op.item_exists(item_title):
        print_result(False)
        error(f"DKIM key '{item_title}' not found in 1Password.", 0)
        return EXIT_FATAL
    print_result(True)

    # Read individual fields using 1Password URLs
    dns_name_url = app.op.mk_url(item_title, "dns_name")
    dns_record_url = app.op.mk_url(item_title, "dns_record")
    key_size_url = app.op.mk_url(item_title, "key_size")
    created_at_url = app.op.mk_url(item_title, "created_at")

    # Retrieve values
    dns_name_result = app.op.read_item(dns_name_url)
    dns_record_result = app.op.read_item(dns_record_url)
    key_size_result = app.op.read_item(key_size_url)
    created_at_result = app.op.read_item(created_at_url)

    print(f"\nDomain:    {COLOUR_BRIGHT}{domain}{COLOUR_RESET}")
    print(f"Selector:  {COLOUR_BRIGHT}{selector}{COLOUR_RESET}")

    if key_size_result.returncode == 0:
        print(f"Key Size:  {COLOUR_BRIGHT}{key_size_result.stdout.strip()} bits{COLOUR_RESET}")

    if created_at_result.returncode == 0:
        print(f"Created:   {COLOUR_BRIGHT}{created_at_result.stdout.strip()}{COLOUR_RESET}")

    if dns_name_result.returncode == 0:
        print("\nDNS Record Name:")
        print(f"  {COLOUR_BRIGHT}{dns_name_result.stdout.strip()}{COLOUR_RESET}")

    if dns_record_result.returncode == 0:
        print("\nDNS TXT Record Value:")
        print(f"  {dns_record_result.stdout.strip()}")

    return EXIT_OK


def handle_dkim_deploy(app: App) -> int:
    """
    Deploy existing DKIM key from 1Password to Route53.
    """
    domain = app.args.domain
    selector = app.args.selector
    zone_id = getattr(app.args, "zone_id", None)

    item_title = _make_dkim_item_title(domain, selector)
    dns_name = f"{selector}._domainkey.{domain}"

    title(f"Deploy DKIM Key for {COLOUR_BRIGHT}{domain}{COLOUR_RESET}", level=2)

    # Check if item exists in 1Password
    title(f"Retrieving DKIM key [ {COLOUR_BRIGHT}{item_title}{COLOUR_RESET} ]", 9)
    if not app.op.item_exists(item_title):
        print_result(False)
        error(f"DKIM key '{item_title}' not found in 1Password.", 0)
        return EXIT_FATAL
    print_result(True)

    # Read the DNS record value from 1Password
    title("Reading DNS record value from 1Password", 9)
    dns_record_url = app.op.mk_url(item_title, "dns_record")
    dns_record_result = app.op.read_item(dns_record_url)

    if dns_record_result.returncode != 0:
        print_result(False)
        error("Failed to read DNS record from 1Password.", 0)
        return EXIT_FATAL

    dns_record = dns_record_result.stdout.strip()
    print_result(True)

    # Deploy to Route53
    try:
        _deploy_to_route53(domain, selector, dns_record, zone_id)
    except Exception as e:
        error(str(e), 0)
        return EXIT_FATAL

    # Print summary
    print(f"\n{COLOUR_OK}DKIM key deployed successfully!{COLOUR_RESET}\n")
    print(f"Domain:    {COLOUR_BRIGHT}{domain}{COLOUR_RESET}")
    print(f"Selector:  {COLOUR_BRIGHT}{selector}{COLOUR_RESET}")
    print(f"Route53:   {COLOUR_OK}Deployed{COLOUR_RESET}")
    print(f"\nDNS Record Name: {COLOUR_BRIGHT}{dns_name}{COLOUR_RESET}")
    print(f"\n{COLOUR_WARNING}Note: Run 'dkim verify' to confirm DNS propagation.{COLOUR_RESET}")

    return EXIT_OK


def handle_dkim_list(app: App) -> int:
    """
    List all DKIM keys stored in 1Password.
    """
    domain_filter = getattr(app.args, "domain", None)

    title("DKIM Keys", level=2)

    # List all Secure Note items in the vault
    title("Retrieving DKIM keys from 1Password", 9)
    result = app.op.item_list(categories="Secure Note")

    if result.returncode != 0:
        print_result(False)
        error("Failed to list items from 1Password.", 0)
        return EXIT_FATAL
    print_result(True)

    # Parse the JSON response
    try:
        items = json.loads(result.stdout)
    except json.JSONDecodeError:
        error("Failed to parse 1Password response.", 0)
        return EXIT_FATAL

    # Filter to DKIM items only
    dkim_items = []
    for item in items:
        item_title = item.get("title", "")
        if item_title.startswith(f"{DKIM_ITEM_PREFIX}_"):
            # Parse domain and selector from title: DKIM_domain_selector
            parts = item_title[len(f"{DKIM_ITEM_PREFIX}_"):].rsplit("_", 1)
            if len(parts) == 2:
                item_domain, item_selector = parts
                # Apply domain filter if specified
                if domain_filter and item_domain != domain_filter:
                    continue
                dkim_items.append({
                    "title": item_title,
                    "domain": item_domain,
                    "selector": item_selector,
                    "created_at": item.get("created_at", ""),
                })

    if not dkim_items:
        if domain_filter:
            print(f"\nNo DKIM keys found for domain '{domain_filter}'.")
        else:
            print("\nNo DKIM keys found.")
        return EXIT_OK

    # Sort by domain, then selector
    dkim_items.sort(key=lambda x: (x["domain"], x["selector"]))

    # Print results
    print(f"\n{'Domain':<30} {'Selector':<20} {'Created':<25}")
    print("-" * 75)

    for item in dkim_items:
        domain = item["domain"]
        selector = item["selector"]
        created = item["created_at"][:10] if item["created_at"] else "N/A"
        print(f"{domain:<30} {selector:<20} {created:<25}")

    print(f"\nTotal: {len(dkim_items)} DKIM key(s)")

    return EXIT_OK


def handle_dkim_verify(app: App) -> int:
    """
    Verify DKIM DNS record is published correctly.
    """
    domain = app.args.domain
    selector = app.args.selector

    item_title = _make_dkim_item_title(domain, selector)
    dns_name = f"{selector}._domainkey.{domain}"

    title(f"Verify DKIM Key for {COLOUR_BRIGHT}{domain}{COLOUR_RESET}", level=2)

    # Check if item exists in 1Password
    title(f"Retrieving DKIM key [ {COLOUR_BRIGHT}{item_title}{COLOUR_RESET} ]", 9)
    if not app.op.item_exists(item_title):
        print_result(False)
        error(f"DKIM key '{item_title}' not found in 1Password.", 0)
        return EXIT_FATAL
    print_result(True)

    # Read the DNS record value from 1Password
    title("Reading expected DNS record from 1Password", 9)
    dns_record_url = app.op.mk_url(item_title, "dns_record")
    dns_record_result = app.op.read_item(dns_record_url)

    if dns_record_result.returncode != 0:
        print_result(False)
        error("Failed to read DNS record from 1Password.", 0)
        return EXIT_FATAL

    expected_record = dns_record_result.stdout.strip()
    print_result(True)

    # Perform DNS lookup
    title(f"Querying DNS for [ {COLOUR_BRIGHT}{dns_name}{COLOUR_RESET} ]", 9)

    from opca.services.route53 import Route53

    r53 = Route53()
    verified = r53.verify_dns_record(dns_name, expected_record, timeout=10, interval=2)

    print_result(verified)

    # Print summary
    if verified:
        print(f"\n{COLOUR_OK}DNS record verified successfully!{COLOUR_RESET}\n")
        print(f"Domain:    {COLOUR_BRIGHT}{domain}{COLOUR_RESET}")
        print(f"Selector:  {COLOUR_BRIGHT}{selector}{COLOUR_RESET}")
        print(f"DNS Name:  {COLOUR_BRIGHT}{dns_name}{COLOUR_RESET}")
        print(f"Status:    {COLOUR_OK}Published and matching{COLOUR_RESET}")
        return EXIT_OK
    else:
        print(f"\n{COLOUR_WARNING}DNS record not found or does not match.{COLOUR_RESET}\n")
        print(f"Domain:    {COLOUR_BRIGHT}{domain}{COLOUR_RESET}")
        print(f"Selector:  {COLOUR_BRIGHT}{selector}{COLOUR_RESET}")
        print(f"DNS Name:  {COLOUR_BRIGHT}{dns_name}{COLOUR_RESET}")
        print(f"Status:    {COLOUR_WARNING}Not verified{COLOUR_RESET}")
        print(f"\nThis may be due to DNS propagation delay. Try again later.")
        return EXIT_FATAL
