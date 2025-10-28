# opca - 1Password Certificate Authority

`opca` is a small PKI toolkit that uses [pyca/cryptography](https://cryptography.io)
to create keys, CSRs, certificates, and CRLs, then stores them securely in [1Password](https://1password.com)
via the 1Password CLI. It also includes helpers for generating OpenVPN artifacts and
client profiles from 1Password-backed templates.

- **Minimal dependencies**: Python 3.9+, `cryptography`, and the 1Password CLI (`op`)
- **No sensitive data written to disk**
- **CLI-first workflow**

---

## 📦 Installation

### Requirements

- Python 3.9+
- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started)

### Install from pypi

```shell
# install base package
pip install opca

# install with s3 publishing support
pip install 'opca[s3]'
```

### Install from source

```shell
# from the repository root
pip install .

# optional extras
pip install .[dev]   # tests, linters, mypy, build tools
pip install .[s3]    # adds S3 publishing support via boto3
```

---

## 🚀 Quick Start

It is highly recommended that you create a new 'vault' in 1Password specifically for this private CA (e.g. ``CA-Test``).

```shell
op signin --account <acct>
op vault create CA-Test --icon wrench

op vault list --account <acct>
ID                            NAME
eegiiZood1Eihaed7beihee1ai    Private
um2age0AzezuequaedaiChoht8    CA-Test
```

### 1️⃣ Create a new Certificate Authority

This is done in one step, and if everything goes well, you should see two objects created in your CA vault.

- CA — certificate bundle containing private key, CSR, and certificate
- CA_Database — SQLite database tracking issued certificates

```shell
opca -a <acct> -v CA-Test ca init \
  -o "Test Org" \
  -n "Test Org CA" \
  --ou "Web Services" \
  --city "Canberra" \
  --state "ACT" \
  --country "AU" \
  --ca-days 3650 \
  --crl-days 47 \
  --days 398 \
  --ca-url "https://ca.example.com/ca.crt" \
  --crl-url "https://ca.example.com/crl.pem"
```

### 2️⃣ Create a Certificate

Available types:

- device: Specific options set for a device client certificate
- vpnserver: Specific options set for a OpenVPN server certificate
- vpnclient: Specific options set for a OpenVPN client certificate
- webserver: This is what you usually want for a general certificate

```shell
# Server certs
opca -a <acct> -v CA-Test cert create -t webserver -n www.example.com --alt test.example.com
opca -a <acct> -v CA-Test cert create -t vpnserver -n vpn.example.com

# Client cert
opca -a <acct> -v CA-Test cert create -t vpnclient -n john.smith
```

#### 📄 Bulk Profile File Format

When using the --file option for bulk certificategeneration, each line represents one
certificate Common Name (CN) with optional --alt DNS names.
Comments and blank lines are ignored.

Example clients.txt:

```text
host.domain.com
host2.domain.com --alt www.domain.com
host3.domain.com --alt mail.domain.com --alt smtp.domain.com --alt imap.domain.com
#host99.domain.com --alt dns1.domain.com
```

Each non-comment line corresponds to one generated client profile.

The --alt entries populate Subject Alternative Names (SANs) in the certificate.

Lines starting with # are ignored.

---

### 3️⃣ Create a Certificate Revocation List
```shell
opca -a <acct> -v CA-Test crl create
```

Creates or updates items in your vault:

- CRL: The PEM encoded Certificate Revocation List

---

### Renew or Revoke a Certificate
```shell
# Renew (keeps original settings when CSR exists)
opca -a <acct> -v CA-Test cert renew -n www.example.com

# Revoke by CN or serial
opca -a <acct> -v CA-Test cert revoke -n www.example.com
opca -a <acct> -v CA-Test cert revoke -s 5
```

Updates:

- The CA_Database is updated
- The original certificate bundle title is renamed to the ``serial number``
- A new certificate bundle is stored with the ``cn`` as the title

### Database Queries
```shell
opca -a <acct> -v CA-Test database list --expiring
```

Other filers:
- -a/--all: All certificates
- -e/--expired: Expired certificates
- -r/--revoked: Revoked certificates
- -x/--expiring: Certificates expiring soon
- -v/--valid: Valid certificates
- -n/--cn: A specific certificate CN
- -s/--serial: A specific certificate serial number

## 🔐 OpenVPN Integration

Generate and manage OpenVPN artifacts stored in 1Password.

### Generate Base Configuration
```shell
opca -a <acct> -v CA-Test openvpn generate --server
opca -a <acct> -v CA-Test openvpn generate --dh
opca -a <acct> -v CA-Test openvpn generate --ta-key
```

### Retrieve or Import Artifacts
```shell
# Retrieve
opca -a <acct> -v CA-Test openvpn get --dh
opca -a <acct> -v CA-Test openvpn get --ta-key
opca -a <acct> -v CA-Test openvpn get --template sample

# Import
opca -a <acct> -v CA-Test openvpn import --dh --file dh.pem
opca -a <acct> -v CA-Test openvpn import --ta-key --file ta.key
```

### Generating OpenVPN Profiles
```shell
# Single CN
opca -a <acct> -v CA-Test openvpn generate --profile \
  --template sample \
  --cn john.smith

# Bulk (from file)
opca -a <acct> -v CA-Test openvpn generate --profile \
  --template sample \
  --file clients.txt
```

Once you have the OpenVPN configuration object, you can customise the ``sample`` template to match your environment. It is recommended that you copy the sample template, and create a new ``text`` field in the ``Template`` section of the OpenVPN configuration object.

Creates new items like VPN_john.smith in 1Password.

---

## 🧪 Testing

### Unit Tests

```shell
pytest
```

### End-to-End (real vault)

```shell
OP_ACCOUNT=<acct> pytest -m e2e
```

---

## 🧱 Project Layout
```shell
src/opca/
  cli.py                      # CLI entrypoint
  __main__.py                 # allows `python -m opca`
  constants.py
  commands/                   # subcommands (ca, cert, crl, database, openvpn)
  models/
  services/                   # 1Password, crypto, storage, etc.
  utils/                      # formatting, IO, crypto helpers
  storage/                    # static or template data
```

---

## 📄 License

MIT © Wired Square

[1password]: https://www.1password.com
[1password-cli]: https://developer.1password.com/docs/cli/get-started
[openvpn]: https://openvpn.net
[openvpn-config]: https://openvpn.net/community-resources/creating-configuration-files-for-server-and-clients