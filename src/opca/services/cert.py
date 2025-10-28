# opca/services/cert.py

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Sequence, Union

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

from opca.utils.datetime import format_datetime
from opca.services.ca_errors import CAError, InvalidCertificateError


class CertificateBundle:
    """ Class to contain x509 Certificates, Private Keys and Signing Requests """
    def __init__(self,
            cert_type: str,
            item_title: str,
            import_certbundle: bool,
            config: Dict[str, Any]
        ):
        """
        CertificateBundle - A class for dealing with x509 certificate items

        Args:
            cert_type (str): Certificate Type (ca, host, vpnclient, vpnserver)
            item_title (str): The name to object will be stored as in 1Password
            import_certbundle (bool): Are we importing?
            config (dict): A dictionary of certificate configuration items
        """
        self.type = cert_type
        self.title: str = item_title
        self.config: Dict[str, Any] = config
        self.csr: Optional[x509.CertificateSigningRequest] = None
        self.private_key: Optional[
            rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | dsa.DSAPrivateKey
        ] = None
        self.private_key_passphrase: Optional[bytes] = None # TODO: Implement private key passphrase
        self.certificate: Optional[x509.Certificate] = None
        self.config_attrs = (
            'org',
            'ou',
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
            #self.certificate = self.sign_certificate(self.csr)

    def export_pkcs12(
        self,
        password: Optional[Union[str, bytes]] = None,
        name: Optional[Union[str, bytes]] = None,
        include_chain: Optional[Sequence[x509.Certificate]] = None,
    ) -> bytes:
        """
        Build a PKCS#12 blob from the private key and certificate.

        Args:
            password: Optional password (str|bytes). If provided, PKCS#12 will be encrypted.
            name: Optional friendly name for the key/cert in the bag (defaults to bundle title).
            include_chain: Optional additional certificates (e.g., issuing CA chain).

        Returns:
            bytes: The PKCS#12 archive.

        Raises:
            ValueError: if the private key is missing.
        """
        if self.private_key is None:
            raise ValueError("Cannot build PKCS#12: private key is missing.")
        if self.certificate is None:
            raise ValueError("Cannot build PKCS#12: certificate is missing.")

        bag_name: bytes = (
            name.encode("utf-8") if isinstance(name, str)
            else (name if name is not None else self.title.encode("utf-8"))
        )
        pwd_bytes: Optional[bytes] = password.encode("utf-8") if isinstance(password, str) else password

        encryption = (
            serialization.BestAvailableEncryption(pwd_bytes)
            if pwd_bytes else serialization.NoEncryption()
        )
        return pkcs12.serialize_key_and_certificates(
            name=bag_name,
            key=self.private_key,
            cert=self.certificate,
            cas=list(include_chain) if include_chain else None,
            encryption_algorithm=encryption,
        )

    def get_certificate(self, pem_format: bool = True) -> Union[str, x509.Certificate]:
        """
        Returns the certificate of the certificate bundle either PEM encoded, or as a certificate object

        Args:
            None

        Returns:
            cryptography.hazmat.bindings._rust.x509.Certificate: pem_format == False
            str: pem_format == True

        Raises:
            None
        """

        if self.certificate is None:
            raise ValueError("No certificate is set on this bundle.")
        return (
            self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            if pem_format else self.certificate
        )

    def get_certificate_attrib(self, attrib: str) -> Any:
        """
        Returns an attribute of the stored certificate

        Args:
            attrib (str): The attribute to return

        Returns:
            str

        Raises:
            None
        """

        if self.certificate is None:
            raise ValueError("No certificate is set on this bundle.")

        def get_attribute_for_oid(oid):
            attribute = self.certificate.subject.get_attributes_for_oid(oid)
            return attribute[0].value if attribute else None

        def get_subject_alt_name():
            try:
                return self.certificate.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
            except ExtensionNotFound:
                return None

        attrib_map = {
            'cn': lambda: get_attribute_for_oid(NameOID.COMMON_NAME),
            'not_before': lambda: format_datetime(self.certificate.not_valid_before_utc,
                                                  output_format='text'),
            'not_after': lambda: format_datetime(self.certificate.not_valid_after_utc,
                                                  output_format='text'),
            'issuer': self.certificate.issuer.rfc4514_string(),
            'subject': self.certificate.subject.rfc4514_string(),
            'serial': self.certificate.serial_number,
            'version': self.certificate.version,
            'org': lambda: get_attribute_for_oid(NameOID.ORGANIZATION_NAME),
            'ou': lambda: get_attribute_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME),
            'email': lambda: get_attribute_for_oid(NameOID.EMAIL_ADDRESS),
            'city': lambda: get_attribute_for_oid(NameOID.LOCALITY_NAME),
            'state': lambda: get_attribute_for_oid(NameOID.STATE_OR_PROVINCE_NAME),
            'country': lambda: get_attribute_for_oid(NameOID.COUNTRY_NAME),
            'basic_constraints': lambda: self.certificate.extensions.
                    get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS),
            'subject_alt_name': lambda: get_subject_alt_name()
        }

        func = attrib_map.get(attrib)

        return func() if callable(func) else func

    def get_config(self, attr: str = "all") -> Union[Dict[str, Any], Any, None]:
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

    def get_csr(self) -> Optional[str]:
        """
        Returns a PEM encoded certificate signing request for the certificate bundle
        """

        return (
            self.csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            if self.csr is not None else None
        )

    def get_private_key(self,
            pem_format: bool = True
    ) -> Union[str, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | dsa.DSAPrivateKey]:
        """
        Returns the private key for the certificate bundle either PEM encoded or as the private key object
        """

        if self.private_key is None:
            raise ValueError("No private key is set on this bundle.")

        return (
            self.private_key.private_bytes(
                Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode('utf-8')
            if pem_format else self.private_key
        )

    def get_public_key(self):
        """
        Returns the public key
        """

        if self.certificate is None:
            raise ValueError("No certificate is set on this bundle.")

        return self.certificate.public_key()

    def get_public_key_size(self) -> int:
        """
        Returns the key length of the private key
        """

        return self.get_public_key().key_size

    def get_public_key_type(self) -> str:
        """
        Returns the private key type
        """

        public_key = self.get_public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return "EC"
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA"
        else:
            return "Unknown"

    def get_title(self) -> str:
        """
        Returns the title of the certificate bundle
        """

        return self.title

    def get_type(self) -> str:
        """
        Returns the certificate bundle type
        """

        return self.type

    def generate_csr(self,
            cert_cn: str,
            private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | dsa.DSAPrivateKey,
        ) -> x509.CertificateSigningRequest:
        """
        Generate a certificate signing request for the current Certificate Bundle
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

        if 'ou' in self.config:
            x509_attributes.append(x509.NameAttribute(
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.config['ou']))

        if 'email' in self.config:
            x509_attributes.append(x509.NameAttribute(
                NameOID.EMAIL_ADDRESS, self.config['email']))

        csr_builder = (x509.CertificateSigningRequestBuilder()
                       .subject_name(x509.Name(x509_attributes)))

        if 'alt_dns_names' in self.config:
            san_list = [x509.DNSName(name) for name in self.config['alt_dns_names']]

            san_extension = x509.SubjectAlternativeName(san_list)

            csr_builder = csr_builder.add_extension(san_extension, critical=False)

        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        return csr

    def generate_private_key(self, key_size: int) -> rsa.RSAPrivateKey:
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

    def import_certificate(self, certificate: bytes) -> None:
        """
        Imports a PEM encoded x509 certificate into the certificate bundle
        """
        self.certificate = x509.load_pem_x509_certificate(certificate, default_backend())

    def import_private_key(self, private_key: bytes, passphrase: Optional[bytes] = None) -> None:
        """
        Imports a PEM encoded RSA private key into the certificate bundle
        """
        self.private_key = serialization.load_pem_private_key(private_key, passphrase)

    def is_ca_certificate(self) -> bool:
        """
        Returns True if the x509 certificate of the certificate bundle is a CA
        """
        return self.get_certificate_attrib("basic_constraints").value.ca

    def is_valid(self) -> bool:
        """
        Returns true if the certificate bundle private key and certificate are consistent
        """
        current_time = datetime.now(timezone.utc)
        not_valid_before = self.certificate.not_valid_before_utc.replace(tzinfo=timezone.utc)
        not_valid_after = self.certificate.not_valid_after_utc.replace(tzinfo=timezone.utc)

        if self.private_key is None:
            # No private key, we only care about validity
            return self.certificate.not_valid_before <= current_time <= self.certificate.not_valid_after

        if self.private_key.public_key() != self.certificate.public_key():
            # The private key does not match the certificate
            return False

        if self.type != 'ca' and self.is_ca_certificate():
            return False

        if self.type == 'ca' and not self.is_ca_certificate():
            return False

        return not_valid_before <= current_time <= not_valid_after

    def self_sign_ca(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        """
        Self-sign a *CA* certificate from the CSR (CA bootstrap only).
        Leaves all end-entity signing to CertificateAuthority.sign_certificate(...).
        """
        if self.type != 'ca':
            raise CAError("self_sign_ca() called on non-CA bundle")

        if self.private_key is None:
            raise CAError("Cannot self-sign CA without a private key.")

        certificate_serial: int = self.config['next_serial']
        delta = timedelta(int(self.config['ca_days']))

        builder = x509.CertificateBuilder().subject_name(csr.subject)
        builder = builder.issuer_name(csr.subject)  # self-signed
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(int(certificate_serial))
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc) + delta)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key()),
            critical=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key())
            ),
            critical=False
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                data_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        certificate = builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        self.certificate = certificate
        return certificate

    def update_certificate(self, certificate: x509.Certificate) -> bool:
        """ Replace the x509 certificate for the certificate bundle with the certificate provided """

        if self.private_key is None:
            raise InvalidCertificateError("Cannot update certificate: private key is not set.")

        if self.private_key.public_key() != certificate.public_key():
            raise InvalidCertificateError("Signed certificate does not match the private key.")

        self.certificate = certificate

        return True

