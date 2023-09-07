#!/usr/bin/env python3
"""
#
# opca_lib/certificate_bundle.py
#

A class to manage a certificate bundle

"""

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from opca_lib.alerts import error

class CertificateBundle:
    """ Class to contain x509 Certificates, Private Keys and Signing Requests """
    def __init__(self, cert_type, item_title, import_certbundle, config):
        """
        CertificateBundle - A class for dealing with x509 certificate items

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            import_certbundle (bool): Are we importing?
            config (dict): A dictionary of certificate configuration items
        """
        self.type = cert_type
        self.title = item_title
        self.config = config
        self.csr = None
        self.private_key = None
        self.private_key_passphrase = None # TODO: Implement private key passphrase
        self.certificate = None
        self.revocation_date = ''
        self.config_attrs = (
            'org',
            'city',
            'state',
            'country',
            'email'
        )

        if import_certbundle:
            # Import
            if 'private_key' in self.config:
                self.import_private_key(self.config['private_key'], self.private_key_passphrase)

            self.import_certificate(self.config['certificate'])

            if 'csr' in self.config:
                self.csr = x509.load_pem_x509_csr(self.config['csr'], default_backend())

            if 'revocation_date' in self.config:
                self.revocation_date = self.config['revocation_date']

            if not self.title:
                self.title = self.get_certificate_attrib('cn')

            # If we haven't been given these details, extract them from the certificate
            for attr in self.config_attrs:
                if attr not in self.config:
                    value = self.get_certificate_attrib(attr)
                    if value is not None:
                        self.config[attr] = value

        else:
            # Generate
            self.private_key = self.generate_private_key(key_size=config['key_size'])
            self.csr = self.generate_csr(private_key=self.private_key, cert_cn=self.config['cn'])
            self.certificate = self.sign_certificate(self.csr)

    def format_datetime(self, date, timezone='UTC'):
        """
        Format a datetime to match OpenSSL text

        Args:
            date (datetime): The datetime object we are working with
            timezone (str):  The timezone we are working with
        
        Returns:
            str

        Raises:
            None
        """
        format_string = f'%b %d %H:%M:%S %Y {timezone}'

        return date.strftime(format_string)

    def get_certificate(self):
        """
        Returns the PEM encoded certificate of the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """

        return self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    def get_certificate_attrib(self, attrib):
        """
        Returns an attribute of the stored certificate

        Args:
            attrib (str): The attribute to return
        
        Returns:
            str

        Raises:
            None
        """

        attr_value = None

        if attrib == 'cn':
            attribute = self.certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'not_before':
            attr_value = self.format_datetime(self.certificate.not_valid_before)
        elif attrib == 'not_after':
            attr_value = self.format_datetime(self.certificate.not_valid_after)
        elif attrib == 'issuer':
            attr_value = self.certificate.issuer
        elif attrib == 'subject':
            attr_value = self.certificate.subject.rfc4514_string()
        elif attrib == 'serial':
            attr_value = self.certificate.serial_number
        elif attrib == 'version':
            attr_value = self.certificate.version
        elif attrib == 'org':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.ORGANIZATION_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'email':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.EMAIL_ADDRESS)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'city':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.LOCALITY_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'state':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.STATE_OR_PROVINCE_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'country':
            attribute = self.certificate.subject.get_attributes_for_oid(
                NameOID.COUNTRY_NAME)
            if len(attribute) > 0:
                attr_value = attribute[0].value
        elif attrib == 'basic_constraints':
            attr_value = self.certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS)

        return attr_value

    def get_config(self, attr='all'):
        """
        Return the contents of a Certificate Bundle config item

        Args:
            attr (str): The attribute to return
        
        Returns:
            str or dict

        Raises:
            None
        """
        config = None

        if attr in self.config_attrs and attr in self.config:
            config = self.config[attr]

        if attr == 'all':
            config = {attr: self.config[attr] for attr in self.config_attrs if attr in self.config}

        return config

    def get_csr(self):
        """
        Returns a PEM encoded certificate signing request for the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        csr = None

        if self.csr:
            csr = self.csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        return csr

    def get_private_key(self):
        """
        Returns a PEM encoded private key for the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        if self.private_key:
            return self.private_key.private_bytes(
                Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode('utf-8')

        return ""

    def get_title(self):
        """
        Returns the title of the certificate bundle

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.title

    def get_type(self):
        """
        Returns the certificate bundle type

        Args:
            None
        
        Returns:
            str

        Raises:
            None
        """
        return self.type

    def generate_csr(self, cert_cn, private_key):
        """
        Generate a certificate signing request for the current Certificate Bundle

        Args:
            cert_cn (str): The CN to use for the CSR
            private_key (str):  The private key to use in creating a CSR
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.CertificateSigningRequest

        Raises:
            None
        """

        x509_attributes = [x509.NameAttribute(x509.NameOID.COMMON_NAME, cert_cn)]

        if 'country' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.COUNTRY_NAME, self.config['country']))

        if 'state' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, self.config['state']))

        if 'city' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.LOCALITY_NAME, self.config['city']))

        if 'org' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, self.config['org']))

        if 'email' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.EMAIL_ADDRESS, self.config['email']))

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(x509_attributes)) 

        if 'alt_dns_names' in self.config:
            san_list = [x509.DNSName(name) for name in self.config['alt_dns_names']]

            san_extension = x509.SubjectAlternativeName(san_list)

            csr_builder = csr_builder.add_extension(san_extension, critical=False)

        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        return csr

    def generate_private_key(self, key_size):
        """
        Generate and returns the RSA private key for the certificate bundle

        Args:
            None
        
        Returns:
            cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey

        Raises:
            None
        """
        public_exponent = 65537
        backend = default_backend()

        private_key = rsa.generate_private_key(
            public_exponent = public_exponent,
            key_size = key_size,
            backend = backend
        )

        return private_key

    def import_certificate(self, certificate):
        """
        Imports a PEM encoded x509 certificate into the certificate bundle

        Args:
            certificate (str): PEM encoded x509 certificate
        
        Returns:
            None

        Raises:
            None
        """
        self.certificate = x509.load_pem_x509_certificate(certificate, default_backend())

    def import_private_key(self, private_key, passphrase=None):
        """
        Imports a PEM encoded RSA private key into the certificate bundle

        Args:
            private_key (str): PEM encoded RSA private key
        
        Returns:
            None

        Raises:
            None
        """
        self.private_key = serialization.load_pem_private_key(private_key, passphrase)

    def is_ca_certificate(self):
        """
        Returns True if the x509 certificate of the certificate bundle is a CA

        Args:
            None
        
        Returns:
            bool

        Raises:
            None
        """
        return self.get_certificate_attrib("basic_constraints").value.ca

    def is_valid(self):
        """
        Returns true if the certificate budle private key and certificate are consistent

        Args:
            None
        
        Returns:
            bool

        Raises:
            None
        """
        current_time = datetime.now()

        if not self.private_key:
            # No private key, we only care about validity
            is_valid_from = self.certificate.not_valid_before <= current_time
            is_valid_to = current_time <= self.certificate.not_valid_after

            return is_valid_from and is_valid_to

        if self.private_key.public_key() != self.certificate.public_key():
            # The private key does not match the certificate
            return False

        if self.type != 'ca' and self.is_ca_certificate():
            return False

        if self.type == 'ca' and not self.is_ca_certificate():
            return False

        return self.certificate.not_valid_before <= current_time <= self.certificate.not_valid_after

    def sign_certificate(self, csr):
        """
        Sign a csr to create a x509 certificate.

        Args:
            csr (cryptography x509.CertificateSigningRequest): Certificate Signing Request
        
        Returns:
            cryptography.hazmat.bindings._rust.x509.Certificate

        Raises:
            None
        """

        if self.type == 'ca':
            certificate_serial = self.config['next_serial']
            delta = timedelta(int(self.config['ca_days']))
        else:
            certificate_serial = x509.random_serial_number()
            delta = timedelta(int(30))

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(csr.subject)
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + delta)
        builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key()),
                critical=False)
        builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key())),
                critical=False)

        if self.type == 'ca':
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

            if self.type == 'vpnclient':
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

            elif self.type == 'vpnserver':
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

            elif self.type == 'webserver':
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

                dns_names = [x509.DNSName(self.config['cn'])]

                if 'alt_dns_names' in self.config:
                    dns_names.extend([x509.DNSName(hostname) for hostname in self.config['alt_dns_names']])

                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(dns_names), critical=False,)

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in self.config:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(self.config["crl_url"])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in self.config:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(self.config["ca_url"])
                        )
                    ]

                    builder = builder.add_extension(
                        x509.AuthorityInformationAccess(aia_access_descriptions),
                        critical=False)
            else:
                error('Unknown certificate type. Aborting.', 1)

        certificate = builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate

    def update_certificate(self, certificate):
        """
        Replace the x509 certificate for the certificate bundle with the certificate provided

        Args:
            certificate (cryptography Certificate): x509 certificate
        
        Returns:
            None

        Raises:
            None
        """

        # Does the private key match the certificate?
        if self.private_key.public_key() == certificate.public_key():
            self.certificate = certificate
        else:
            error('Signed certificate does not match the private key', 1)
