"""
#
# opca_lib/command_openvpn.py
#

Handle the various openvpn commands

"""

import os
from opca_lib.alerts import error, title, print_result
from opca_lib.crypto import generate_dh_params, verify_dh_params
from opca_lib.crypto import generate_ta_key, verify_ta_key
from opca_lib.crypto import DEFAULT_KEY_SIZE
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from opca_lib.fs_io import read_file
from opca_lib.op import Op, OP_BIN, DEFAULT_OP_CONF


def handle_openvpn_action(openvpn_action, cli_args):
    """
    Handle OpenVPN Actions called from the selection

    Args:
        openvpn_action (str): Desired action
        cli_args (argparse.Namespace): Command line arguments from argparse

    Returns:
        None

    Raises:
        None
    """

    title('OpenVPN', extra=openvpn_action, level=2)

    one_password = Op(binary=OP_BIN, account=cli_args.account, vault=cli_args.vault)

    if openvpn_action == 'gen-dh':
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

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                         attributes=attributes)

        print_result(result.returncode == 0)

        print(dh_parameters_pem)

    elif openvpn_action == 'gen-ta-key':
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

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                         attributes=attributes)

        print_result(result.returncode == 0)

        print(ta_key_pem)

    elif openvpn_action == 'gen-vpn-profile':
        env_vars = os.environ.copy()
        env_vars['OPCA_USER'] = cli_args.cn

        title('Reading VPN profile ' + \
            f'[ {COLOUR_BRIGHT}{cli_args.template}{COLOUR_RESET} ] from 1Password', 9)

        result = one_password.read_item(url = one_password.mk_url(
                            item_title=DEFAULT_OP_CONF["openvpn_title"],
                            value_key=f'template/{cli_args.template}'))

        print_result(result.returncode == 0)

        if result.returncode == 0:
            ovpn_template = result.stdout
        else:
            error(result.stderr, result.returncode)

        title(f'Generating VPN profile for [ {COLOUR_BRIGHT}{cli_args.cn}{COLOUR_RESET} ]', 9)
        result = one_password.inject_item(env_vars=env_vars, template=ovpn_template)
        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(result.stderr, result.returncode)

        title('Storing VPN profile in 1Password', 9)
        one_password.store_document(action='create', item_title=f'VPN_{cli_args.cn}',
                        filename=f'{cli_args.cn}-{cli_args.template}.ovpn', str_in=ovpn_template)
        print_result(result.returncode == 0)

    elif openvpn_action == 'get-dh':
        title('Reading the DH parameters from 1Password', 9)

        url = one_password.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        value_key=DEFAULT_OP_CONF["dh_item"].replace(".", "/"))

        result = one_password.read_item(url)
        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(f'Unable to read the dh parameters from { url }', 1)

        title('Verifying DH parameters', 9)
        dh_parameters_pem = result.stdout
        dh_keysize = verify_dh_params(dh_parameters_pem.encode('utf-8'))
        print_result(dh_keysize >= DEFAULT_KEY_SIZE['dh'])

        print(dh_parameters_pem)

    elif openvpn_action == 'get-ta-key':
        title('Reading the TLS Authentication Key from 1Password', 9)

        url = one_password.mk_url(item_title=DEFAULT_OP_CONF["openvpn_title"],
                        value_key=DEFAULT_OP_CONF["ta_item"].replace(".", "/"))

        result = one_password.read_item(url)
        print_result(result.returncode == 0)

        if result.returncode != 0:
            error(f'Unable to read the TLS Authentication Key from { url }', 1)

        title('Verifying TLS Authentication Key', 9)
        ta_key_pem = result.stdout
        ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))
        print_result(ta_keysize >= DEFAULT_KEY_SIZE['ta'])

        print(ta_key_pem)

    elif openvpn_action == 'import-dh':
        file = cli_args.file

        title('Reading the DH Parameters from file', 9)
        dh_parameters_pem = read_file(file).decode('utf-8')
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

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_result(result.returncode == 0)

        print(dh_parameters_pem)

    elif openvpn_action == 'import-ta-key':
        file = cli_args.file

        title('Reading the TLS Authentication Key from file', 9)
        ta_key_pem = read_file(file).decode('utf-8')
        print_result(ta_key_pem)

        if not ta_key_pem:
            error(f'Unable to read the dh parameters from { file }', 1)

        title('Verifying TLS Authentication Key', 9)
        ta_keysize = verify_ta_key(ta_key_pem.encode('utf-8'))
        print_result(ta_keysize >= DEFAULT_KEY_SIZE['dh'])

        print(f'The TLS Authentication Key is { ta_keysize } bits')

        title('Storing the TLS Authentication Key in 1Password', 9)
        attributes = [f'{DEFAULT_OP_CONF["ta_item"]}={ ta_key_pem }',
                    f'{DEFAULT_OP_CONF["ta_key_size_item"]}={ ta_keysize }'
                    ]

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                            attributes=attributes)

        print_result(result.returncode == 0)

    elif openvpn_action == 'gen-sample-vpn-server':
        title('Storing the sample OpenVPN configuration template', 9)

        base_url = f'op://{cli_args.vault}/{{}}'
        openvpn_title = f'{ DEFAULT_OP_CONF["openvpn_title"] }'

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

        result = one_password.store_item(item_title=DEFAULT_OP_CONF["openvpn_title"],
                                          action='create', attributes=attributes)

        print_result(result.returncode == 0)

    else:
        error('This feature is not yet written', 99)
