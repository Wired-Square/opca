# opca/commands/openvpn/actions.py

from __future__ import annotations

import logging
import os

from opca.models import App
from opca.constants import (
    DEFAULT_KEY_SIZE,
    DEFAULT_OP_CONF,
    EXIT_OK,
    COLOUR_BRIGHT,
    COLOUR_RESET,
)
from opca.utils.crypto import generate_dh_params, generate_ta_key, verify_dh_params, verify_ta_key
from opca.utils.files import read_bytes
from opca.utils.formatting import error, print_result, title

log = logging.getLogger(__name__)


# -----------------------------------------
# Generate
# -----------------------------------------
def handle_generate(app: App) -> int:
    """
    Dispatch composite generate actions based on flags.
    """
    selected = [
        app.args.dh,
        app.args.ta_key,
        app.args.profile,
        app.args.server]
    if not any(selected):
        app.args._parser.error("nothing selected to generate; use one or more of: --dh, --ta-key, --profile, --server")

    return_code = EXIT_OK

    if app.args.dh:
        return_code = max(return_code, handle_dh_gen(app))

    if app.args.ta_key:
        return_code = max(return_code, handle_ta_key_gen(app))

    if app.args.profile:
        if not app.args.template:
            app.args._parser.error("--profile requires --template")
        if not (app.args.cn or app.args.file):
            app.args._parser.error("--profile requires either --cn or --file")
        return_code = max(return_code, handle_profile_gen(app))

    if app.args.server:
        return_code = max(return_code, handle_server_gen(app))

    return return_code

def handle_dh_gen(app: App) -> int:
    title('Generating DH parameters', 9)
    dh_parameters_pem = generate_dh_params()
    print_result(dh_parameters_pem)

    title('Verifying DH parameters', 9)
    dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
    print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

    title('Storing the DH parameters in 1Password', 9)
    attributes = [f'{ DEFAULT_OP_CONF["dh_item"] }={ dh_parameters_pem }',
                    f'{ DEFAULT_OP_CONF["dh_key_size_item"] }={ dh_keysize}'
                ]

    result = app.op.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                        attributes=attributes)

    print_result(result.returncode == 0)

    print(dh_parameters_pem)


    return EXIT_OK

def handle_ta_key_gen(app: App) -> int:
    title('Generate the OpenVPN TLS Authentication Key', 9)
    ta_key_pem = generate_ta_key()
    print_result(ta_key_pem)

    title('Verifying the TLS Authentication Key', 9)
    ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))

    if ta_keysize >= DEFAULT_KEY_SIZE['ta']:
        print_result(True)
    else:
        print_result(False)
        error('TLS Authentication Key is not suitable', 1)

    title('Storing the TLS Authentication Key in 1Password', 9)
    attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={ ta_key_pem }',
                    f'{DEFAULT_OP_CONF["ta_key_size_item"]}={ ta_keysize }'
                    ]

    result = app.op.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                        attributes=attributes)

    print_result(result.returncode == 0)

    print(ta_key_pem)

    return EXIT_OK

def handle_profile_gen(app: App) -> int:
    profiles_to_generate = []
    ovpn_templates = {}

    if app.args.cn:
        profile_config = {
            'template': app.args.template,
            'cn': app.args.cn
        }

        profiles_to_generate.append(profile_config)
    elif app.args.file:
        for line in read_bytes(app.args.file).decode('utf-8', errors='replace').splitlines():
            line = line.strip()

            if not line:
                continue

            if line.startswith('#'):
                continue

            profile_config = {
                'template': app.args.template,
                'cn': line
            }

            profiles_to_generate.append(profile_config)
    else:
        error(f'Subcommand has not been written:  { app.args }', 1)

    for profile in profiles_to_generate:
        profile_template = profile.get('template')
        profile_cn = profile.get('cn')

        env_vars = os.environ.copy()
        env_vars['OPCA_USER'] = profile_cn

        if profile_template not in ovpn_templates:
            title('Reading VPN profile ' + \
                f'[ {COLOUR_BRIGHT}{profile_template}{COLOUR_RESET} ] from 1Password', 9)

            result = app.op.read_item(url = app.op.mk_url(
                                item_title=DEFAULT_OP_CONF["openvpn_title"],
                                value_key=f'template/{profile_template}'))

            print_result(result.returncode == 0)

            if result.returncode == 0:
                ovpn_templates[profile_template] = result.stdout
            else:
                error(result.stderr, result.returncode)

        title(f'Generating VPN profile for [ {COLOUR_BRIGHT}{profile_cn}{COLOUR_RESET} ] with template [ {COLOUR_BRIGHT}{profile_template}{COLOUR_RESET} ]', 9)
        result = app.op.inject_item(env_vars=env_vars, template=ovpn_templates[profile_template])
        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(result.stderr, result.returncode)

        if app.args.dest:
            title(f'Storing VPN profile in 1Password vault [ {COLOUR_BRIGHT}{app.args.dest}{COLOUR_RESET} ]', 9)
            result = app.op.store_document(action='create', item_title=f'VPN_{profile_cn}',
                        filename=f'{profile_cn}-{profile_template}.ovpn', str_in=result.stdout, vault=app.args.dest)
        else:
            title('Storing VPN profile in 1Password', 9)
            result = app.op.store_document(action='create', item_title=f'VPN_{profile_cn}',
                        filename=f'{profile_cn}-{profile_template}.ovpn', str_in=result.stdout)

        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(result.stderr, result.returncode)

    return EXIT_OK

def handle_server_gen(app: App) -> int:
    openvpn_title = f'{ DEFAULT_OP_CONF["openvpn_title"] }'

    title(f'Checking for existing OpenVPN object [ {COLOUR_BRIGHT}{openvpn_title}{COLOUR_RESET} ]', 9)
    exists = app.op.item_exists(openvpn_title)
    print_result(exists)

    if exists:
        return EXIT_OK

    title('Storing the sample OpenVPN configuration template', 9)

    base_url = f'op://{app.args.vault}/{{}}'
    client_url = base_url.format('$OPCA_USER/cn')
    hostname_url = base_url.format(f'{openvpn_title}/server/hostname')
    port_url = base_url.format(f'{openvpn_title}/server/port')
    cipher_url = base_url.format(f'{openvpn_title}/server/cipher')
    auth_url = base_url.format(f'{openvpn_title}/server/auth')
    ca_cert_url = base_url.format((f'{DEFAULT_OP_CONF["ca_title"]}/'
                                    f'{DEFAULT_OP_CONF["cert_item"]}'))
    cert_url = base_url.format(f'$OPCA_USER/{DEFAULT_OP_CONF["cert_item"]}')
    private_key_url = base_url.format(f'$OPCA_USER/{DEFAULT_OP_CONF["key_item"]}')
    tls_auth_url = base_url.format((f'{openvpn_title}/'
                                    f'{DEFAULT_OP_CONF["ta_item"].replace(".", "/")}'))

    attributes = ['server.hostname[text]=vpn.domain.com.au',
                'server.port[text]=1194',
                'server.cipher[text]=aes-256-gcm',
                'server.auth[text]=sha256',
                f'''template.sample[text]=#
# Client - {{{{ { client_url } }}}}
#

# Brought to you by Wired Square - www.wiredsquare.com

client
dev tun
proto udp
remote {{{{ { hostname_url } }}}} {{{{ { port_url } }}}}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher {{{{ { cipher_url } }}}}
auth {{{{ { auth_url } }}}}
verb 3
key-direction 1
mssfix 1300
<ca>
{{{{ { ca_cert_url } }}}}
</ca>
<cert>
{{{{ { cert_url } }}}}
</cert>
<key>
{{{{ { private_key_url } }}}}
</key>
<tls-auth>
{{{{ { tls_auth_url } }}}}
</tls-auth>
''']

    result = app.op.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                        action='create', attributes=attributes)

    print_result(result.returncode == 0)

    return EXIT_OK


# -----------------------------------------
# Get
# -----------------------------------------
def handle_get(app: App) -> int:
    args = app.args
    if not (args.dh or args.ta_key or args.template):
        args._parser.error("nothing selected to get; use one or both of: --dh, --ta-key, --template NAME")

    return_code = EXIT_OK
    if args.dh:
        return_code = max(return_code, handle_dh_get(app))
    if args.ta_key:
        return_code = max(return_code, handle_ta_key_get(app))
    if args.template:
        # Assumes handler reads `app.args.template` for the template name/title
        return_code = max(return_code, handle_template_get(app))
    return return_code

def handle_dh_get(app: App) -> int:
    title('Reading the DH parameters from 1Password', 9)

    url = app.op.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                    value_key=DEFAULT_OP_CONF["dh_item"].replace(".", "/"))

    result = app.op.read_item(url)
    print_result(result.returncode == 0)

    if result.returncode != 0:
        error(f'Unable to read the dh parameters from { url }', 1)

    title('Verifying DH parameters', 9)
    dh_parameters_pem = result.stdout
    dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
    print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

    print(dh_parameters_pem)

    return EXIT_OK

def handle_ta_key_get(app: App) -> int:
    title('Reading the TLS Authentication Key from 1Password', 9)

    url = app.op.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                    value_key=DEFAULT_OP_CONF["ta_item"].replace(".", "/"))

    result = app.op.read_item(url)
    print_result(result.returncode == 0)

    if result.returncode != 0:
        error(f'Unable to read the TLS Authentication Key from { url }', 1)

    title('Verifying TLS Authentication Key', 9)
    ta_key_pem = result.stdout
    ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))
    print_result(ta_keysize >= DEFAULT_KEY_SIZE['ta'])

    print(ta_key_pem)

    return EXIT_OK

def handle_template_get(app: App) -> int:
    """
    Read an OpenVPN client template (by name/title) from 1Password and print it.
    Uses: app.args.template
    """
    tmpl = getattr(app.args, "template", None)
    if not tmpl:
        app.args._parser.error("--template requires a template name")

    title(f"Reading VPN template [ {COLOUR_BRIGHT}{tmpl}{COLOUR_RESET} ] from 1Password", 9)
    url = app.op.mk_url(
        item_title=DEFAULT_OP_CONF["openvpn_title"],
        value_key=f"template/{tmpl}",
    )
    result = app.op.read_item(url)
    print_result(result.returncode == 0)

    if result.returncode != 0:
        error(f"Unable to read the OpenVPN template '{tmpl}' from {url}", result.returncode or 1)
        return result.returncode or 1

    # Emit the template content to stdout
    print(result.stdout)

    return EXIT_OK


# -----------------------------------------
# Import
# -----------------------------------------
def handle_import(app: App) -> int:
    args = app.args
    selected = [args.dh, args.ta_key]
    if not any(selected):
        args._parser.error("nothing selected to import; use one or both of: --dh, --ta-key")

    # Validate file arguments
    importing_both = args.dh and args.ta_key
    if importing_both and args.file:
        args._parser.error("when importing both --dh and --ta-key, use --dh-file and --ta-key-file instead of --file")

    # Resolve files per artifact
    dh_file = args.dh_file
    ta_file = args.ta_key_file

    if args.dh and not dh_file:
        dh_file = args.file if not importing_both else None
        if not dh_file:
            args._parser.error("--dh requires --dh-file (or --file when importing only --dh)")

    if args.ta_key and not ta_file:
        ta_file = args.file if not importing_both else None
        if not ta_file:
            args._parser.error("--ta-key requires --ta-key-file (or --file when importing only --ta-key)")

    return_code = EXIT_OK

    # Inject per-artifact file path into app.args for the existing handlers
    # (Assumes handlers read app.args.file)
    prev_file = getattr(app.args, "file", None)

    if args.dh:
        app.args.file = dh_file
        return_code = max(return_code, handle_dh_import(app))

    if args.ta_key:
        app.args.file = ta_file
        return_code = max(return_code, handle_ta_key_import(app))

    # restore
    app.args.file = prev_file

    return return_code

def handle_dh_import(app: App) -> int:
    file = app.args.file

    title('Reading the DH Parameters from file', 9)
    dh_parameters_pem = read_bytes(file).decode('utf-8', errors='replace')
    print_result(dh_parameters_pem)

    if not dh_parameters_pem:
        error(f'Unable to read the dh parameters from { file }', 1)

    title('Verifying DH parameters', 9)
    dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
    print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

    title('Storing the DH Parameters in 1Password', 9)
    attributes = [f'{DEFAULT_OP_CONF["dh_item"]}={ dh_parameters_pem }',
                f'{DEFAULT_OP_CONF["dh_key_size_item"]}={ dh_keysize }'
                ]

    result = app.op.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        attributes=attributes)

    print_result(result.returncode == 0)

    print(dh_parameters_pem)

    return EXIT_OK

def handle_ta_key_import(app: App) -> int:
    file = app.args.file

    title('Reading the TLS Authentication Key from file', 9)
    ta_key_pem = read_bytes(file).decode('utf-8', errors='replace')
    print_result(ta_key_pem)

    if not ta_key_pem:
        error(f'Unable to read the dh parameters from { file }', 1)

    title('Verifying TLS Authentication Key', 9)
    ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))
    print_result(ta_keysize >= DEFAULT_KEY_SIZE['ta'])

    print(f'The TLS Authentication Key is { ta_keysize } bits')

    title('Storing the TLS Authentication Key in 1Password', 9)
    attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={ ta_key_pem }',
                f'{DEFAULT_OP_CONF["ta_key_size_item"]}={ ta_keysize }'
                ]

    result = app.op.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        attributes=attributes)

    print_result(result.returncode == 0)

    return EXIT_OK
