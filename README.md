# opca - 1Password Certificate Authority

A Python private certificate authority implementation that uses pyca/cryptography (https://cryptography.io)
to generate keys and sign certificates, and then store them in 1Password.

The design contraints are
  - Limit the dependendies.
    - 1Password CLI
    - Python 3
    - Python Cryptography Library

  - Store no sensitive data on disk. Ever. 

This version of 1Password Certificate Authority represents a project with most features implemented.

Future features (not extensive):
- Implement private key passphrases

## Getting Started

The only file you need from this project is the single Python file opca.py. Put it in the executable path of your computer.

To make use of this project, you will need a [1Password][1password] account. Any account will do, although if you are using a personal account, and you have more than one account linked, you will have to pick the account on the cli each time instead of using the -a/--account option with your organisation (``myorg``).

It is highly recommended that you create a new 'vault' in 1Password specifically for this private CA (``CA-Test``).

You should also install 1Password CLI and make sure it is working. There is really good [documentation][1password-cli] on the 1Password website on how to accomplish this. Once you think you are done, you can confirm things are working by listing the available vaults. You should see your vault there.

```shell
op vault list --account myorg
ID                            NAME
eegiiZood1Eihaed7beihee1ai    Private
um2age0AzezuequaedaiChoht8    CA-Test
```

### Create a new Certificate Authority

This is done in one step, and if everything goes well, you should see two objects created in your CA vault.

- CA: The Certificate Authority certificate bundle containing the PEM encoded Private Key, Certificate and Certificate Signing Request
- CA_Database: A SQLite database for keeping track of the certificates generated and their state

```shell
opca.py -a myorg -v CA-Test ca init --ca-days 3650 --crl-days 47 --days 398 -o "Test Org" -n "Test Org CA"
```

### Create a Certificate

Certificates can have a number of uses, and x509 attributes are set accordingly. The following types are available

- vpnserver: Specific options set for a OpenVPN server certificate
- vpnclient: Specific options set for a OpenVPN client certificate
- webserver: This is what you usually want for a general certificate

```shell
opca.py -a myorg -v CA-Test cert create  -t webserver -n www.myorg.com --alt testsite.myorg.com
```

### Create a Certificate Revocation List

This is an important maintenance step. The CA_Database is updated with the current status of any certificates that may have expired since a certificate was last created, and stored into 1Password. If this is the first time generating a CRL, a new object will appear in your CA vault.

- CRL: The PEM encoded Certificate Revocation List

```shell
opca.py -a myorg -v CA-Test crl create
```

### Renew a Certificate

If you created the certificate using this tool, and the certificate bundle still has a valid ``csr``, you can renew a certificate retaining the options that were originally requested.

```shell
opca.py -a myorg -v CA-Test cert renew -n www.myorg.com
```

Once completed,
- The original certificate bundle title is renamed to the ``serial number``
- A new certificate bundle is stored with the ``cn`` as the title
- The CA_Database is updated
- The PEM encoded certificate is displayed in the terminal

### Check the Certificate Database

If you want to check the status of certificates that have been issued, you can use the ``database list`` option. You can filter on

- -a/--all: All certificates
- -e/--expired: Expired certificates
- -r/--revoked: Revoked certificates
- -x/--expiring: Certificates expiring soon
- -v/--valid: Valid certificates
- -n/--cn: A specific certificate CN
- -s/--serial: A specific certificate serial number

```shell
opca.py -a myorg -v CA-Test database list --expiring
```

## OpenVPN Credentials

This project can be used to generate and manage certificates for OpenVPN servers and clients. Once you are done, there will be a number of new objects stored in your 1Password vault.

- OpenVPN: The OpenVPN configuration object
- VPN_*: A OpenVPN profile

### Generating the OpenVPN configuration settings

Configuring [OpenVPN][openvpn] is out of scope for this document, but there is very good [documentation][openvpn-config] on their website. The idea is that you create a template of your client configuration in the OpenVPN configuration object which is used to create the VPN profile using secrets also stored in 1Password.

This step creates the basic OpenVPN configuration object, along with some sample configuration, the Diffie-Hellman parameters and a TLS Authentication key.

```shell
opca.py -a myorg -v CA-Test openvpn gen-sample-vpn-server
opca.py -a myorg -v CA-Test openvpn gen-dh
opca.py -a myorg -v CA-Test openvpn gen-ta-key
```

Once you have the OpenVPN configuration object, you can customise the ``sample`` template to match your environment. It is recommended that you copy the sample template, and create a new ``text`` field in the ``Template`` section of the OpenVPN configuration object.

### Generating a VPN profile

If everything is set up correctly, we should see some new objects being created

- vpn.myorg.com: VPN server certificate
- john.smith: VPN client certificate for ``John Smith``
- VPN_john.smith: A VPN client profile for ``John Smith`` that can be imported into the OpenVPN client

```shell
opca.py -a myorg -v CA-Test cert create -t vpnserver -n vpn.myorg.com
opca.py -a myorg -v CA-Test cert create -t vpnclient -n john.smith
opca.py -a myorg -v CA-Test openvpn gen-vpn-profile -t sample -n john.smith
```

[1password]: https://www.1password.com
[1password-cli]: https://developer.1password.com/docs/cli/get-started
[openvpn]: https://openvpn.net
[openvpn-config]: https://openvpn.net/community-resources/creating-configuration-files-for-server-and-clients