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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from opca_lib.alerts import error, title, print_result, warning
from opca_lib.certificate_bundle import CertificateBundle
from opca_lib.colour import COLOUR_BRIGHT, COLOUR_RESET
from opca_lib.crypto import DEFAULT_KEY_SIZE
from opca_lib.database import CertificateAuthorityDB
from opca_lib.date import format_datetime
from opca_lib.op import DEFAULT_OP_CONF


def prepare_cert_authority(one_password):
    """
    Prepares the certificate authority object for later consumption

    Args:
        command (str): The way we will construct the certificate authority
        config (dict): CA Configuration

    Returns:
        CertificateAuthority

    Raises:
        None
    """

    ca_config = {
        'command': 'retrieve'
    }

    cert_authority = CertificateAuthority(one_password=one_password,
                            config=ca_config,
                            op_config=DEFAULT_OP_CONF)

    return cert_authority


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
        self.one_password = one_password
        self.op_config = op_config
        self.crl = None

        if config['command'] == 'init':
            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 0)

            self.ca_database = CertificateAuthorityDB(config)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=False,
                                      config=config)

            self.ca_database.increment_serial('cert')

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'import':
            if one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority already exists. Aborting.', 0)

            self.ca_database = CertificateAuthorityDB(config)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=True,
                                      config=config)

            self.store_certbundle(self.ca_certbundle)

        elif config['command'] == 'retrieve':
            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 0)

            result = self.one_password.get_document(self.op_config['ca_database_title'])

            if result.returncode == 0:
                ca_database_sql = result.stdout

            self.ca_database = CertificateAuthorityDB(data=ca_database_sql)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

        elif config['command'] == 'rebuild-ca-database':
            if not one_password.item_exists(self.op_config['ca_title']):
                error('Certificate Authority does not exist. Aborting.', 1)

            if self.one_password.item_exists(self.op_config['ca_database_title']):
                error('CA database exists. Aborting', 1)

            self.ca_database = CertificateAuthorityDB(config)

            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            self.ca_database.update_config(self.ca_certbundle.get_config())

            self.rebuild_ca_database()

        else:
            error('Unknown CA command', 0)

    def format_db_item(self, certificate, item_title=None):
        """
        Format a certificate db item from a certificate

        Args:
            certificate: cryptography.hazmat.bindings._rust.x509.Certificate
            item_title (str): The storage title of the certificate bundle

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
            'title': item_title,
            'status': status,
            'expiry_date': format_datetime(certificate.not_valid_after),
            'subject': certificate.subject.rfc4514_string()
        }

        return cert_db_item

    def get_certificate(self):
        """
        Returns the CA certificate in PEM format

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.ca_certbundle.get_certificate()

    def get_crl(self):
        """
        Returns the Certificate Signing Request stored in 1Password in PEM format

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """

        if self.crl is None:
            result = self.one_password.get_document(self.op_config['crl_title'])

            if result.returncode == 0:
                self.crl = result.stdout

        return self.crl

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

        self.ca_database.process_ca_database()

        crl_days = self.ca_database.get_config_attributes()['crl_days']

        builder = x509.CertificateRevocationListBuilder()

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                self.ca_certbundle.get_certificate_attrib('cn')),
        ]))

        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(datetime.utcnow() + timedelta(crl_days))

        crl_serial = self.ca_database.increment_serial('crl')
        builder = builder.add_extension(x509.CRLNumber(crl_serial), critical=False)

        for cert in self.ca_database.certs_revoked:
            serial_number = cert['serial']
            revocation_date = datetime.strptime(cert['revocation_date'], '%Y%m%d%H%M%SZ')

            revoked_cert = x509.RevokedCertificateBuilder().serial_number(
                serial_number).revocation_date(revocation_date).build(default_backend())
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_certbundle.private_key, hashes.SHA256(), default_backend())

        self.crl = crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        result = self.one_password.store_document(action='auto',
                        item_title=self.op_config['crl_title'],
                        filename=self.op_config['crl_filename'],
                        str_in=self.crl)

        if result.returncode != 0:
            error(result.stderr, 1)

        result = self.store_ca_database()

        if result.returncode != 0:
            error(result.stderr, 1)

        return self.crl

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
            print_result(cert_valid)

            if obj.get_certificate_attrib('serial') in self.ca_database.certs_expires_soon:
                warning(f'Certificate { item_title } is expiring soon')
        else:
            print_result(False, failed_msg='NOPRIV')

        if item_title == DEFAULT_OP_CONF['ca_title'] and not cert_valid:
            error('CA Certificate is not valid. This is quite serious.', 1)

        return obj

    def is_cert_valid(self, certificate):
        """
        Check if a certificate is valid and was signed by the CA certificate.

        Args:
            certificate (x509.Certificate): The certificate to check.

        Returns:
            bool: True if the certificate is valid and was signed by the CA, False otherwise.
        """
        ca_cert = self.ca_certbundle.certificate

        # 1. Signature Verification
        try:
            ca_cert.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )
        except InvalidSignature:
            return False

        # 2. Date Validity
        current_date = datetime.utcnow()
        if certificate.not_valid_before <= current_date <= certificate.not_valid_after:
            return True

        return False

    def is_crl_valid(self, crl_pem):
        """
        Check if a CRL is valid.

        Args:
            crl_pem (bytes): The PEM encoded CRL.

        Returns:
            bool: True if the CRL is valid, False otherwise.
        """
        crl = x509.load_pem_x509_crl(crl_pem, default_backend())
        ca_cert = self.ca_certbundle.certificate

        # 1. Signature Verification
        try:
            ca_cert.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm
            )
        except InvalidSignature:
            return False

        # 2. Date Validity
        current_date = datetime.utcnow()
        if crl.last_update <= current_date <= crl.next_update:
            return True

        return False

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

                if cert_serial in result_dict:
                    warning(f'Duplicate serial number [ '
                            f'{ COLOUR_BRIGHT }{ cert_serial }{ COLOUR_RESET } ] in CA Database')

                result_dict[cert_serial] = {'cert': cert_bundle.certificate,
                                            'title': item_title}

        for serial, attrs in sorted(result_dict.items()):
            self.ca_database.add_cert(self.format_db_item(certificate=attrs['cert'],
                                                          item_title=attrs['title']))

            if serial > max_serial:
                max_serial = serial + 0

        next_serial = self.ca_database.get_config_attributes()['next_serial']

        if next_serial:
            if max_serial >= next_serial:
                warning(f'The next serial is { next_serial } '
                        f'but the largest serial number seen is { max_serial }')

        else:
            next_serial = max_serial + 1
            self.ca_database.update_config({'next_serial': next_serial})

        title(f'Next serial is [ { COLOUR_BRIGHT }{ next_serial }{ COLOUR_RESET } ]', 7)
        title(f'Total certificates in database is [ '
              f'{ COLOUR_BRIGHT }{ self.ca_database.count_certs() }{ COLOUR_RESET } ]', 7)

        self.store_ca_database()

    def rename_certbundle(self, src_item_title, dst_item_title):
        """
        Renames a certificate bundle in 1Password

        Args:
            src_item_title (str): The 1Password object that contains a certificate bundle
            dst_item_title (str): The new 1Password object that contains a certificate bundle

        Returns:
            bool: True if the update succeeded, False otherwise.

        Raises:
            None
        """
        db_item = self.ca_database.query_cert(cert_info={'title': src_item_title},
                                              valid_only=False)
        print(db_item)

        get_result = self.one_password.get_item(src_item_title)

        if get_result.returncode != 0:
            error(f'Unable to get the item { src_item_title }', 1)

        store_result = self.one_password.store_item(item_title=dst_item_title,
                                                    category=None,
                                                    str_in=get_result.stdout)

        if store_result.returncode != 0:
            error(f'Unable to store the item as { dst_item_title }', 1)

        db_item['title'] = dst_item_title

        if self.ca_database.update_cert(db_item) and self.store_ca_database().returncode == 0:
            return self.one_password.delete_item(src_item_title)

        return False

    def retrieve_certbundle(self, item_title):
        """
        Imports a certificate bundle from 1Password

        Args:
            item_title (str): The 1Password object that contains a certificate bundle

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

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            error(f'Certificate with { cert_info } not found. Aborting', 0)

        item_serial = cert['serial']
        item_title = cert['title']

        if self.ca_database.process_ca_database(revoke_serial=item_serial):

            self.store_ca_database()

            if item_title != str(item_serial):
                rename_result = self.rename_certbundle(src_item_title=item_title,
                                                    dst_item_title=item_serial)

                if rename_result.returncode != 0:
                    error(f'Unable to rename the certificate bundle { item_title } '
                          f'[ { item_serial }]', 1)

                return rename_result == 0

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

        ca_config = self.ca_database.get_config_attributes()
        ca_public_key = self.ca_certbundle.private_key.public_key()
        certificate_serial = self.ca_database.increment_serial('cert')
        delta = timedelta(ca_config['days'])

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_certbundle.certificate.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + delta)
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_public_key),
                critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(ca_public_key)),
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

                common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                dns_names = [x509.DNSName(common_name)]

                try:
                    san = csr.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                    dns_names.extend([name for name in san if isinstance(name, x509.DNSName)])

                    combined_san = x509.SubjectAlternativeName(dns_names)

                    builder = builder.add_extension(combined_san, critical=False)

                except x509.ExtensionNotFound:
                    builder = builder.add_extension(x509.SubjectAlternativeName(dns_names),
                                                     critical=False)

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in ca_config:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(ca_config["crl_url"])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in ca_config:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(ca_config["ca_url"])
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

        return certificate

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

        result = self.one_password.store_document(action='auto',
                        item_title=self.op_config['ca_database_title'],
                        filename=self.op_config['ca_database_filename'],
                        str_in=self.ca_database.export_database().decode('utf-8'))

        return result

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

        if not certbundle.is_valid():
            error('Certificate Bundle is not valid', 1)

        if self.ca_database.query_cert(cert_info={'cn': item_title},
                                        valid_only=True) is not None:
            error('Certificate with a duplicate name exists', 1)

        if self.ca_database.query_cert(cert_info={'serial': item_serial},
                                        valid_only=True) is not None:
            error('Certificate with a duplicate serial number exists', 1)

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
                        f'{self.op_config["serial_item"]}=' + \
                            f'{ item_serial }',
                        f'{self.op_config["csr_item"]}=' + \
                            f'{certbundle.get_csr() or ""}'
        ]

        result = self.one_password.store_item(action='create',
                                    item_title=item_title,
                                    attributes=attributes)

        if self.ca_database.add_cert(self.format_db_item(certificate=certbundle.certificate,
                                                         item_title=item_title)):
            self.store_ca_database()

        return result
