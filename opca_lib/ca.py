#!/usr/bin/env python3
"""
#
# opca_lib/ca.py
#

A class to manage a certificate authority

"""

from datetime import datetime, timedelta
import json
from cryptography import x509
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from opca_lib.alerts import error, print_result, title, warning
from opca_lib.certificate_bundle import CertificateBundle
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from opca_lib.op import DEFAULT_OP_CONF


class CertificateAuthority:
    """ Class to act as a Certificate Authority """
    def __init__(self, one_password, config, op_config):
        """
        Construct a certificate authority object.

        Args:
            one_password (OpObject): An initialised 1Password object
            command (str): How we should acquire a certificate authority key and certificate
            config (dict): Configuration items
        """
        self.ca_certbundle = None
        self.ca_config = None
        self.ca_database = None          # The equivalent of index.txt. Dict keyed by serial
        self.ca_database_cn = None       # CA Database index - Dict keyed by cn with value of serial
        self.ca_database_serial = None   # CA Database index - Dict keyed by serial with value of cn
        self.certs_revoked = None
        self.certs_expires_soon = None
        self.certs_valid = None
        self.next_serial = None
        self.one_password = one_password
        self.op_config = op_config
        self.config_attrs = (
            'org',
            'email',
            'city',
            'state',
            'country',
            'ca_url',
            'crl_url',
            'days',
            'crl_days'
        )

        if config['command'] == 'init':
            self.ca_database = []
            self.ca_database_cn = {}
            self.ca_database_serial = {}
            self.ca_config = config
            self.next_serial = int(self.ca_config['next_serial'])

            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 0)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=False,
                                      config=self.ca_config)

            self.next_serial += 1

            self.ca_database.append(self.format_db_item(self.ca_certbundle.certificate))

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'import':
            self.ca_database = []
            self.ca_database_cn = {}
            self.ca_database_serial = {}
            self.ca_config = config
            self.next_serial = int(self.ca_config['next_serial'])

            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 0)


            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=True,
                                      config=self.ca_config)

            self.ca_database.append(self.format_db_item(self.ca_certbundle.certificate))

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'retrieve':
            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 0)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            self.retrieve_ca_database()
            if self.process_ca_database():
                self.store_ca_database()

        elif config['command'] == 'rebuild-ca-database':
            self.ca_database = []
            self.ca_database_cn = {}
            self.ca_database_serial = {}
            self.ca_config = config
            self.next_serial = self.ca_config.get('next_serial')

            # If present, it needs to be cast to an int
            if self.next_serial is not None:
                self.next_serial = int(self.next_serial)

            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 0)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            if self.one_password.item_exists(self.op_config['ca_database_title']):
                error('CA database exists. Aborting', 0)

            self.ca_database.append(self.format_db_item(self.ca_certbundle.certificate))

            self.rebuild_ca_database()

        else:
            error('Unknown CA command', 0)

    def add_ca_database_item(self, certificate):
        """
        Add an item to the CA database, process and store.

        Args:
            certificate (Certfqwfwe): The certificate to add to the database
        
        Returns:
            Bool

        Raises:
            None
        """

        certificate_cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        certificate_serial = certificate.serial_number

        if certificate_serial in self.ca_database:
            return False

        self.process_ca_database()

        self.ca_database.append(self.format_db_item(certificate))
        self.store_ca_database()

        self.ca_database_cn[certificate_cn] = certificate_serial
        self.ca_database_serial[certificate_serial] = certificate_cn

        return True

    def format_datetime(self, date):
        """
        Format a datetime to match OpenSSL text

        Args:
            date (datetime): The datetime object we are working with
        
        Returns:
            str

        Raises:
            None
        """
        format_string = '%Y%m%d%H%M%SZ'

        return date.strftime(format_string)

    def format_db_item(self, certificate):
        """
        Format a certificate db item from a certificate

        Args:
            certificate: cryptography.hazmat.bindings._rust.x509.Certificate

        Returns:
            list

        Raises:
            None
        """

        expired = datetime.utcnow() > certificate.not_valid_after

        if expired:
            status = 'Expired'
        else:
            status = 'Valid'

        cert_db_item = {
            'serial': certificate.serial_number,
            'cn': certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'status': status,
            'expiry_date': self.format_datetime(certificate.not_valid_after),
            'revocation_date': '',
            'subject': certificate.subject.rfc4514_string()
        }

        return cert_db_item

    def get_certificate(self):
        """
        Returns the CA certificate in various formats

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.ca_certbundle.get_certificate()

    def generate_crl(self):
        """
        Generate a certificate revocation list in PEM format for the Certificate Authority

        Args:
            None

        Returns:
            string

        Raises:
            None
        """

        builder = x509.CertificateRevocationListBuilder()

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.ca_certbundle.get_certificate_attrib('cn')),
        ]))

        builder = builder.last_update(datetime.today())
        builder = builder.next_update(datetime.today() + timedelta(int(self.ca_config["crl_days"])))

        for cert in self.certs_revoked:
            serial_number = cert['serial']
            revocation_date = datetime.strptime(cert['revocation_date'], '%Y%m%d%H%M%SZ')

            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                serial_number).revocation_date(revocation_date).build(default_backend())
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_certbundle.private_key, hashes.SHA256(), default_backend())

        return crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def generate_certificate_bundle(self, cert_type, item_title, config):
        """
        Creates a certificate bundle from configuration

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            config (dict): A dictionary of certificate configuration items

        Returns:
            CertificateBundle

        Raises:
            None
        """
        cert_bundle = CertificateBundle(cert_type=cert_type,
                                        item_title=item_title,
                                        import_certbundle=False,
                                        config=config)

        pem_csr = cert_bundle.get_csr().encode('utf-8')
        csr = x509.load_pem_x509_csr(pem_csr, default_backend())

        signed_certificate = self.sign_certificate(csr=csr, target=cert_type)

        cert_bundle.update_certificate(signed_certificate)

        if cert_bundle.is_valid():
            self.store_certbundle(cert_bundle)

        return cert_bundle

    def import_certificate_bundle(self, cert_type, item_title, config):
        """
        Imports a certificate bundle from variables

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            config (dict): A dictionary of certificate configuration items

        Returns:
            CertificateBundle

        Raises:
            None
        """

        obj = CertificateBundle(cert_type=cert_type,
                                item_title=item_title,
                                import_certbundle=True,
                                config=config)

        if item_title is None:
            item_title = obj.get_certificate_attrib('cn')

        title(f'Checking [ { COLOUR_BRIGHT }{ item_title }{ COLOUR_RESET } ] certificate bundle', 9)

        cert_valid = obj.is_valid()

        if obj.private_key:
            #TODO: check is certificate is expiring soon
            print_result(cert_valid)
        else:
            print_result(False, failed_msg='NOPRIV')

        if item_title == DEFAULT_OP_CONF['ca_title'] and not cert_valid:
            error('CA Certificate is not valid. This is quite serious.', 1)

        return obj

    def is_valid(self):
        """
        Is the certifiate authority object valid

        Args:
            None

        Returns:
            bool

        Raises:
            None
        """

        return self.ca_certbundle.is_valid()

    def process_ca_database(self, revoke_serial=None):
        """
        Process the CA database.
         - The status of certifiates might change due to time
         - Gather a list of
           - Certificates revoked
           - Certificates expiring soon
           - Certificates valid

        Args:
            None

        Returns:
            bool: Did the database change post-processing

        Raises:
            None
        """
        changed = False
        db_error = False
        tmp_ca_db = []
        self.certs_revoked = []
        self.certs_expires_soon = []
        self.certs_valid = []

        if self.ca_database is None:
            db_error = True

        else:

            for cert in self.ca_database:
                skip = False

                try:
                    expiry_date = datetime.strptime(cert['expiry_date'], '%Y%m%d%H%M%SZ')

                    expired = datetime.utcnow() > expiry_date

                    expires_soon = datetime.utcnow() + timedelta(29) > expiry_date
                    revoked = bool(cert['revocation_date']) or (cert['status'] == 'Revoked')

                    if revoke_serial is not None:
                        if not expired and not revoked and int(revoke_serial) == cert['serial']:
                            revoked = True
                            cert['revocation_date'] = self.format_datetime(datetime.utcnow())

                except KeyError:
                    warning(f"'expiry_date' key not found for certificate { cert['serial'] }.")
                    skip = True
                    db_error = True
                except ValueError:
                    warning(f"Unable to parse 'expiry_date' for certificate { cert['serial'] }.")
                    skip = True
                    db_error = True


                if not skip:
                    if expired:
                        if cert['status'] != 'Expired':
                            changed = True
                            cert['status'] = 'Expired'
                    elif revoked:
                        if cert['status'] != 'Revoked':
                            changed = True
                            cert['status'] = 'Revoked'

                        self.certs_revoked.append(cert)

                    elif expires_soon:
                        self.certs_expires_soon.append(cert)

                    else:
                        self.certs_valid.append(cert)

                    tmp_ca_db.append(cert)

        if changed and not db_error:
            self.ca_database = tmp_ca_db
            self.store_ca_database()

        return changed

    def rebuild_ca_database(self):
        """
        Rebuild the CA certificate database from 1Password

        Args:
            None

        Returns:
            dict: The CA database as rebuilt

        Raises:
            None
        """
        result_dict = {}
        max_serial = 0

        result = self.one_password.item_list(categories=self.op_config['category'])

        if result.returncode != 0:
            error(error_msg=result.stderr, exit_code=result.returncode)

        op_items = json.loads(result.stdout)

        for op_item in op_items:
            item_title = op_item['title']

            cert_bundle = self.retrieve_certbundle(item_title)

            if cert_bundle is None:
                warning(f'{ item_title } is not a certificate. Ignoring.')
            else:
                # Actual certificate
                cert_serial = cert_bundle.get_certificate_attrib('serial')
                result_dict[cert_serial] = cert_bundle.certificate

        for serial, certificate in sorted(result_dict.items()):
            self.add_ca_database_item(certificate=certificate)

            if serial > max_serial:
                max_serial = serial + 0

        if self.next_serial:
            if max_serial >= self.next_serial:
                warning(f'The next serial is { self.next_serial } but the largest serial number seen is { max_serial }')

        else:
            self.next_serial = max_serial + 0

        title(f'Next serial is [ { COLOUR_BRIGHT }{ self.next_serial }{ COLOUR_RESET } ]', 7)
        self.store_ca_database()

    def retrieve_ca_database(self):
        """
        Retrieve the CA certificate database from 1Password

        Args:
            None

        Returns:
            dict: The CA database as retrieved

        Raises:
            None
        """
        self.ca_config = {}
        self.ca_database_cn = {}
        self.ca_database_serial = {}
        result_dict = {}
        result = self.one_password.get_item(self.op_config['ca_database_title'])

        if result.returncode == 0:
            loaded_ca_db = json.loads(result.stdout)

            for field in loaded_ca_db['fields']:
                if 'section' in field:
                    section_label = field['section']['label']
                    field_label = field['label']
                    field_value = field.get('value', '')

                    if section_label == 'config':
                        if field_label == 'next_serial':
                            self.next_serial = int(field_value)
                        elif field_label in self.config_attrs:
                            self.ca_config[field_label] = field_value
                    elif section_label not in result_dict:
                        result_dict[section_label] = {'serial': int(section_label)}

                    if section_label != 'config':
                        if field_label in ('status', 'cn', 'subject', 'expiry_date', 'revocation_date'):
                            result_dict[section_label][field_label] = field_value

                    # Build the index
                    if field_label == 'cn':
                        if field_value not in self.ca_database_cn:
                            self.ca_database_cn[field_value] = section_label
                        if section_label not in self.ca_database_serial:
                            self.ca_database_serial[section_label] = field_value

            self.ca_database = list(result_dict.values())

        return self.ca_database

    def retrieve_certbundle(self, item_title):
        """
        Imports a certificate bundle from 1Password

        Args:
            item_title (str): The 1Password object that contains a certificate bundle
            ca (bool): Is the certificate bundle our CA?

        Returns:
            CertificateBundle if the retrieved object is a certificate bundle, otherwise None

        Raises:
            None
        """
        cert_config = {}
        cert_type = None

        result = self.one_password.get_item(item_title)

        if result.returncode != 0:
            error('Something went wrong retrieving the certificate bundle', 0)

        loaded_object = json.loads(result.stdout)

        for field in loaded_object['fields']:
            if field['label'] == 'certificate':
                cert_config['certificate'] = field['value'].encode('utf-8')
            elif field['label'] == 'private_key' and 'value' in field:
                cert_config['private_key'] = field['value'].encode('utf-8')
            elif field['label'] == 'certificate_signing_request' and 'value' in field:
                cert_config['csr'] = field['value'].encode('utf-8')
            elif field['label'] == 'type':
                cert_config['cert_type'] = field['value']
                cert_type = field['value']
            elif field['label'] == 'revocation_date' and 'value' in field:
                cert_config['revocation_date'] = field['value']

        if 'certificate' not in cert_config:
            return None

        return self.import_certificate_bundle(cert_type=cert_type,
                                              item_title=item_title,
                                              config=cert_config)

    def revoke_certificate(self, cert_info):
        """
        Revokes a previously signed certificate

        Args:
            cert_info (dict): key - The certificate attribute (cn or serial)
                            value - The attribute data

        Returns:
            bool

        Raises:
            None
        """

        if 'serial' in cert_info:
            item_serial = cert_info['serial']

            if item_serial in self.ca_database_serial:
                item_title = self.ca_database_serial[item_serial]
            else:
                error(f'Certificate with serial number { item_serial } not found. Aborting', 0)


        elif 'cn' in cert_info:
            item_title = cert_info['cn']

            if item_title in self.ca_database_cn:
                item_serial = self.ca_database_cn[item_title]
            else:
                error(f'Certificate with CN { item_title } not found. Aborting', 0)

        else:
            error('Unknown certificate attribute', 0)

        print(f'Found {item_title} in CA database with serial {item_serial}')

        cert_bundle = self.retrieve_certbundle(item_title=item_title)

        if self.process_ca_database(revoke_serial=item_serial):
            print(f'Certificate serial number { item_serial } revoked in the database.')
            cert_bundle.title = f'revoked_{ item_title }'
            cert_bundle.revocation_date = self.format_datetime(datetime.utcnow())

            result = self.store_certbundle(cert_bundle)

            if result.returncode == 0:
                self.one_password.delete_item(item_title)
            else:
                error('Unable to store the certificate bundle', 0)

            return True

        return False

    def sign_certificate(self, csr, target=None):
        """
        Sign a csr to create a x509 certificate.

        Args:
            csr (cryptography x509.CertificateSigningRequest): Certificate Signing Request
            target (): The type of x509 certificate to create
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.Certificate

        Raises:
            None
        """

        certificate_serial = self.next_serial
        delta = timedelta(int(self.ca_config['days']))

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_certbundle.certificate.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + delta)
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_certbundle.private_key.public_key()),
                critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_certbundle.private_key.public_key())),
                critical=False)

        if target == 'ca':
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True)

            builder = builder.add_extension(x509.KeyUsage(
                    digital_signature=False,
                    key_encipherment=False,
                    key_agreement=False,
                    data_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False), critical=True,
                    )
        else:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=False)

            if target == 'vpnclient':
                builder = builder.add_extension(x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=False,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False), critical=True,
                        )
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        ]), critical=True)

            elif target == 'vpnserver':
                builder = builder.add_extension(x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False), critical=True,
                        )
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        ]), critical=True)

            elif target == 'webserver':
                builder = builder.add_extension(x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False), critical=True,
                        )
                builder = builder.add_extension(x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                        ]), critical=False)

                cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                dns_names = [x509.DNSName(cn)]

                try:
                    san_extension = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san = san_extension.value
                    dns_names.extend([name for name in san if isinstance(name, x509.DNSName)])

                    combined_san_extension = x509.SubjectAlternativeName(dns_names)

                    builder = builder.add_extension(combined_san_extension, critical=False)

                except x509.ExtensionNotFound:
                    builder = builder.add_extension(x509.SubjectAlternativeName(dns_names), critical=False)

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in self.ca_config:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(self.ca_config["crl_url"])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in self.ca_config:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(self.ca_config["ca_url"])
                        )
                    ]

                    builder = builder.add_extension(
                        x509.AuthorityInformationAccess(aia_access_descriptions),
                        critical=False)
            else:
                error('Unknown certificate type. Aborting.', 0)

        certificate = builder.sign(
            private_key=self.ca_certbundle.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        self.next_serial += 0

        return certificate

    def store_certbundle(self, certbundle):
        """
        Store a certificate bundle into 1Password

        Args:
            certbundle (CertificateBundle): The certificate to store

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        item_title = certbundle.get_title()
        item_serial = certbundle.certificate.serial_number

        if certbundle.is_valid() and item_title not in self.ca_database_cn:

            if str(item_serial) not in self.ca_database_serial:
                self.add_ca_database_item(certbundle.certificate)

            attributes = [f'{self.op_config["cert_type_item"]}=' + \
                                f'{certbundle.get_type()}',
                          f'{self.op_config["cn_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("cn")}',
                          f'{self.op_config["subject_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("subject")}',
                          f'{self.op_config["key_item"]}=' + \
                                f'{certbundle.get_private_key()}',
                          f'{self.op_config["cert_item"]}=' + \
                                f'{certbundle.get_certificate()}',
                          f'{self.op_config["start_date_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("not_before")}',
                          f'{self.op_config["expiry_date_item"]}=' + \
                                f'{certbundle.get_certificate_attrib("not_after")}',
                          f'{self.op_config["revocation_date_item"]}=' + \
                                f'{certbundle.revocation_date}',
                          f'{self.op_config["serial_item"]}=' + \
                                f'{ item_serial }',
                          f'{self.op_config["csr_item"]}=' + \
                                f'{certbundle.get_csr() or ""}'
            ]

            result = self.one_password.store_item(action='create',
                                     item_title=item_title,
                                     attributes=attributes)
        else:
            error('Certificate Object is invalid or already exists. Unable to store in 1Password', 1)

        return result

    def store_ca_database(self):
        """
        Store a CA certificate database into 1Password

        Args:
            None

        Returns:
            subprocess.CompletedProcess: Output from 1Password CLI

        Raises:
            None
        """

        attributes = [
            f'{DEFAULT_OP_CONF["next_serial_item"]}={self.next_serial}',
            f'{DEFAULT_OP_CONF["org_item"]}={self.ca_config.get("org", "")}',
            f'{DEFAULT_OP_CONF["email_item"]}={self.ca_config.get("email", "")}',
            f'{DEFAULT_OP_CONF["city_item"]}={self.ca_config.get("city", "")}',
            f'{DEFAULT_OP_CONF["state_item"]}={self.ca_config.get("state", "")}',
            f'{DEFAULT_OP_CONF["country_item"]}={self.ca_config.get("country", "")}',
            f'{DEFAULT_OP_CONF["ca_url_item"]}={self.ca_config.get("ca_url", "")}',
            f'{DEFAULT_OP_CONF["crl_url_item"]}={self.ca_config.get("crl_url", "")}',
            f'{DEFAULT_OP_CONF["days_item"]}={self.ca_config.get("days", "")}',
            f'{DEFAULT_OP_CONF["crl_days_item"]}={self.ca_config.get("crl_days", "")}',
        ]

        for cert in self.ca_database:
            attributes.append(f'{cert["serial"]}.cn[text]={cert["cn"]}')
            attributes.append(f'{cert["serial"]}.status[text]={cert["status"]}')
            attributes.append(f'{cert["serial"]}.expiry_date[text]={cert["expiry_date"]}')
            attributes.append(f'{cert["serial"]}.revocation_date[text]={cert["revocation_date"]}')
            attributes.append(f'{cert["serial"]}.subject[text]={cert["subject"]}')

        result = self.one_password.edit_or_create(item_title=self.op_config['ca_database_title'],
                                attributes=attributes)

        return result
