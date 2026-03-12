# opca - 1Password Certificate Authority

`opca` is a small PKI toolkit that uses [pyca/cryptography](https://cryptography.io)
to create keys, CSRs, certificates, and CRLs, then stores them securely in [1Password](https://1password.com)
via the 1Password CLI. It also includes helpers for generating OpenVPN artifacts and
client profiles from 1Password-backed templates.

- **Minimal dependencies**: Python 3.9+, `cryptography`, and the 1Password CLI (`op`)
- **No sensitive data written to disk**
- **CLI-first workflow** with an optional **interactive TUI** (terminal UI)

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

# install with interactive TUI
pip install 'opca[tui]'
```

### Install from source

```shell
# from the repository root
pip install .

# optional extras
pip install .[dev]   # tests, linters, mypy, build tools
pip install .[s3]    # adds S3 publishing support via boto3
pip install .[tui]   # interactive terminal UI via Textual
```

### AWS Authentication

If you intend to publish your CA certificate, Certificate Revocation List (CRL), or CA database
to AWS, you will need to perform some additional steps. The most obvious being that you should 
install the S3 options above.

You will also need the [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#getting-started-install-instructions) installed.

1Password has the ability to keep your AWS CLI credentials stored in a vault. [Follow the guide](https://developer.1password.com/docs/cli/shell-plugins/aws/) to set this up.

If everything went well, you will be able to export your AWS credentials to the shell environment with the following command

```shell
op plugin run -- aws configure export-credentials --format env
```

---

## 🚀 Quick Start

It is highly recommended that you create a new 'vault' in 1Password specifically for this private CA (e.g. ``CA-Test``). ``acct`` is a 1Password Account. Example: company.1password.com (default: None)

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

## 🖥️ Terminal UI (TUI)

OPCA includes an optional interactive terminal interface built with [Textual](https://textual.textualize.io/).
It provides the same functionality as the CLI in a navigable, form-driven interface.

### Launch

```shell
# requires: pip install opca[tui]
opca -a <acct> -v CA-Test tui
```

### Features

- **Sidebar navigation** — switch between CA, Certificates, CRL, CSR, DKIM, OpenVPN, and Database screens using the sidebar or keys 1–7
- **Certificate management** — create, view, renew, revoke, and export certificates with DataTable listing and filter support (All / Valid / Expiring / Expired / Revoked)
- **CA operations** — view CA info, initialize a new CA, export the CA certificate
- **CRL management** — generate, view info, and export CRLs in PEM or DER format
- **Database tools** — view and set config values, export SQL, rebuild the database
- **CSR, DKIM, OpenVPN** — create/import CSRs, manage DKIM keys, generate OpenVPN profiles
- **PKCS#12 export** — export certificates in PKCS#12 format with password protection

All long-running 1Password operations run in background workers so the UI stays responsive.

---

## 🧪 Testing

### Unit Tests

Run the full unit test suite (no external dependencies required):

```shell
pip install .[dev]
pytest
```

### End-to-End Tests (real 1Password vault)

E2E tests create a temporary vault, exercise the full CLI and TUI workflows against a
real 1Password account, and clean up afterwards. They require:

- The 1Password CLI (`op`) signed in
- The `OP_ACCOUNT` environment variable set to your 1Password account

```shell
# run all e2e tests (CA init → certs → CRL → OpenVPN → TUI)
OP_ACCOUNT=<acct> pytest -m e2e

# run only the TUI e2e tests
OP_ACCOUNT=<acct> pytest tests/e2e/test_60_tui.py -v

# run only the CLI e2e tests
OP_ACCOUNT=<acct> pytest tests/e2e/ -k "not tui" -v
```

E2E tests use `@pytest.mark.order()` to run in sequence. The TUI tests (order 60+)
expect the vault to already contain a CA and certificates from earlier tests (order 10–50).
Running the full suite ensures correct ordering.

### TUI Unit Tests

The TUI has its own unit tests using Textual's headless Pilot framework (no 1Password required):

```shell
pip install .[tui,dev]
pytest tests/unit/test_tui.py -v
```

---

## 🧱 Project Layout
```shell
src/opca/
  cli.py                      # CLI entrypoint
  __main__.py                 # allows `python -m opca`
  constants.py
  commands/                   # subcommands (ca, cert, crl, database, openvpn, tui)
  models/
  services/                   # 1Password, crypto, storage, etc.
  utils/                      # formatting, IO, crypto helpers
  storage/                    # static or template data
  tui/                        # interactive terminal UI (optional, requires textual)
    app.py                    # main Textual app
    context.py                # bridges TUI to existing services
    workers.py                # async worker helpers
    css/app.tcss              # stylesheet
    screens/                  # connect, dashboard, ca, cert_list, crl, etc.
    widgets/                  # status_bar, log_panel
```

---

## 📄 License

MIT © Wired Square

[1password]: https://www.1password.com
[1password-cli]: https://developer.1password.com/docs/cli/get-started
[openvpn]: https://openvpn.net
[openvpn-config]: https://openvpn.net/community-resources/creating-configuration-files-for-server-and-clients
