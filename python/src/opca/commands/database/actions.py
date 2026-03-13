# opca/commands/database/actions.py

from __future__ import annotations

import logging

from opca.services.ca import CertificateAuthority
from opca.models import App
from opca.constants import (
    DEFAULT_OP_CONF,
    EXIT_OK,
    EXIT_FATAL,
    COLOUR,
    COLOUR_BRIGHT,
    COLOUR_RESET,
)
from opca.utils.formatting import error, print_result, title

log = logging.getLogger(__name__)


def handle_database_export(app: App) -> int:
    title("Database export", level=2)

    print(app.ca.ca_database.export_database().decode('utf-8'))

    return EXIT_OK

def handle_database_config_get(app: App) -> int:
    title("Database get config", level=2)

    print(app.ca.ca_database.get_config_attributes())

    return EXIT_OK

def handle_database_config_set(app: App) -> int:
    title("Database set config", level=2)

    config = {item.split('=')[0]: item.split('=')[1] for item in app.args.conf}

    app.ca.ca_database.update_config(config)

    app.ca.store_ca_database()

    print(app.ca.ca_database.get_config_attributes())

    return EXIT_OK

def handle_database_rebuild(app: App) -> int:
    title("Database Rebuild", level=2)

    ca_config = {
        'command': 'rebuild-ca-database',
        'next_serial': app.args.serial,
        'next_crl_serial': app.args.crl_serial,
        'crl_days': app.args.crl_days,
        'days': app.args.days,
        'ca_url': app.args.ca_url,
        'crl_url': app.args.crl_url
    }

    try:
        cert_authority = CertificateAuthority(one_password=app.op,
                            config=ca_config,
                            op_config=DEFAULT_OP_CONF)

        # Persist the (new or rebuilt) CA database to 1Password
        ok = cert_authority.store_ca_database()
        print_result(bool(ok))
        if not ok:
            return EXIT_FATAL

        title("CA database stored.", 8)
        return EXIT_OK

    except Exception as e:
        error(f"Database rebuild failed: {e}", 1)

        return EXIT_FATAL

def handle_database_upload(app: App) -> int:
    title("Database Upload", level=2)

    if app.args.store is None:
        title(f'Uploading CA Database to [ { COLOUR_BRIGHT }Private Store{ COLOUR_RESET } ]', 9)
        print_result(app.ca.upload_ca_database())

    else:
        for store_uri in app.args.store:
            title(f'Uploading CA Database to [ { COLOUR_BRIGHT }{store_uri}{ COLOUR_RESET } ]', 9)
            print_result(app.ca.upload_ca_database(store_uri))
    return EXIT_OK
