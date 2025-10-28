# opca/services/ca.pyclass CertificateAuthority:

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509 import UniformResourceIdentifier
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature

from opca.constants import DEFAULT_OP_CONF, DEFAULT_STORAGE_CONF
from opca.services.cert import CertificateBundle
from opca.services.database import CertificateAuthorityDB
from opca.services.ca_errors import (
    CAError,
    CAAlreadyExistsError,
    CANotFoundError,
    CADatabaseError,
    CAStorageError,
    InvalidCertificateError,
    DuplicateCertificateError,
    UnknownCommandError,
)
from opca.services.one_password import Op
from opca.services.storage import StorageBackend, StorageRsync, StorageS3
from opca.utils.datetime import format_datetime


class CertificateAuthority:
    """ Class to act as a Certificate Authority """
    def __init__(self, one_password, config, op_config=DEFAULT_OP_CONF):
        """
        Construct a certificate authority object.

        Args:
            one_password (OpObject): An initialised 1Password object
            command (str): How we should acquire a certificate authority key and certificate
            config (dict): Configuration items
        """
        self.ca_certbundle = None
        self.one_password: Op = one_password
        self.op_config = op_config
        self.ca_database: Optional[CertificateAuthorityDB] = None
        self.crl: Optional[str] = None

        cmd = config.get('command')

        if cmd == 'init':
            if one_password.item_exists(self.op_config['ca_title']):
                raise CAAlreadyExistsError("Certificate Authority already exists.")

            self.ca_database = CertificateAuthorityDB(config)

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=False,
                                      config=config)

            # Bootstrap: self-sign the CA cert once here
            pem_csr = self.ca_certbundle.get_csr().encode('utf-8')
            csr = x509.load_pem_x509_csr(pem_csr, default_backend())
            self.ca_certbundle.self_sign_ca(csr)

            self.ca_database.increment_serial('cert')

            self.store_certbundle(self.ca_certbundle)

        elif cmd == 'import':
            if one_password.item_exists(self.op_config['ca_title']):
                raise CAAlreadyExistsError("Certificate Authority already exists.")

            self.ca_certbundle = CertificateBundle(cert_type='ca',
                                      item_title=self.op_config['ca_title'],
                                      import_certbundle=True,
                                      config=config)

            self.ca_database = CertificateAuthorityDB(self.ca_certbundle.config)

            self.store_certbundle(self.ca_certbundle)

        elif cmd == 'retrieve':
            if not one_password.item_exists(self.op_config['ca_title']):
                raise CANotFoundError("Certificate Authority does not exist.")

            result = self.one_password.get_document(self.op_config['ca_database_title'])

            if result.returncode != 0:
                raise CADatabaseError(result.stderr or "Failed to retrieve CA database.")

            ca_database_sql = result.stdout
            self.ca_database = CertificateAuthorityDB(data=ca_database_sql)
            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            if self.ca_certbundle is None:
                raise CANotFoundError("CA certificate bundle not found.")

        elif cmd == 'rebuild-ca-database':
            if not one_password.item_exists(self.op_config['ca_title']):
                raise CANotFoundError("Certificate Authority does not exist.")

            if self.one_password.item_exists(self.op_config['ca_database_title']):
                raise CAAlreadyExistsError("CA database exists.")

            self.ca_database = CertificateAuthorityDB(config)
            self.ca_certbundle = self.retrieve_certbundle(item_title=self.op_config['ca_title'])

            if self.ca_certbundle is None:
                raise CANotFoundError("CA certificate bundle not found.")

            self.ca_database.update_config(self.ca_certbundle.get_config())
            self.rebuild_ca_database()

        else:
            raise UnknownCommandError(f"Unknown CA command: {cmd!r}")

    def delete_certbundle(self, item_title, archive=True):
        """
        Delete a certificate bundle in 1Password

        Args:
            item_title (str): The 1Password object that contains a certificate bundle
            archive (bool): Archive the item in 1Password. Defaults to True

        Returns:
            bool: True if the update succeeded, False otherwise.

        Raises:
            None
        """
        db_item = self.ca_database.query_cert(cert_info={'title': item_title},
                                              valid_only=False)

        if self.ca_database.update_cert(db_item):
            return self.one_password.delete_item(item_title=item_title, archive=archive)

        return False

    def format_db_item(self, certificate: x509.Certificate, item_title: Optional[str] = None) -> dict:
        """
        Format a certificate db item from a certificate

        Args:
            certificate: cryptography.hazmat.bindings._rust.x509.Certificate
            item_title (str): The storage title of the certificate bundle
        """

        expired = datetime.now(timezone.utc) > certificate.not_valid_after_utc

        if expired:
            status = 'Expired'
        else:
            status = 'Valid'

        cert_db_item = {
            'serial': certificate.serial_number,
            'cn': certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'title': item_title,
            'status': status,
            'expiry_date': format_datetime(certificate.not_valid_after_utc),
            'subject': certificate.subject.rfc4514_string()
        }

        return cert_db_item

    # ----------------
    # Read methods
    # ----------------
    def get_certificate(self) -> str:
        """
        Returns the CA certificate in PEM format
        """
        if not self.ca_certbundle:
            raise CANotFoundError("CA certificate bundle not loaded.")

        return self.ca_certbundle.get_certificate()

    def get_cert_cn_from_serial(self, serial: int, valid_only: bool=True) -> str:
        """
        Searches for a certificate by serial number and returns the certificate name
        """

        cert_info = {'serial': serial}

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=valid_only)

        if not cert:
            raise CANotFoundError(f"Certificate with serial={serial} not found.")

        return cert['cn']

    def get_cert_serial_from_cn(self, cn: str, *, valid_only: bool=True) -> int:
        """
        Searches for a certificate by certificate name and returns the serial number
        """

        cert_info = {'cn': cn}

        try:
            _ = self.ca_database.process_ca_database()
        except Exception:
            pass

        if valid_only:
            candidate_serials = (
                self.ca_database.certs_valid |
                self.ca_database.certs_expires_soon
            )
        else:
            candidate_serials = (
                self.ca_database.certs_valid |
                self.ca_database.certs_expires_soon |
                self.ca_database.certs_expired |
                self.ca_database.certs_revoked
            )

        matches = []
        for serial in candidate_serials:
            row = self.ca_database.query_cert(cert_info={'serial': serial}, valid_only=False)
            if row and row.get('cn') == cn:
                matches.append(int(serial))

        if not matches:
            raise CANotFoundError(f"Certificate with CN={cn!r} not found.")

        return max(matches)

    def get_crl(self) -> Optional[str]:
        """
        Returns the Certificate Revocation List stored in 1Password in PEM format
        """

        if self.crl is None:
            result = self.one_password.get_document(self.op_config['crl_title'])

            if result.returncode != 0:
                return None

            self.crl = result.stdout

        return self.crl

    def get_crl_bytes(self, fmt: str = "pem") -> bytes:
        """
        Return the current CRL as bytes in the requested format ('pem' or 'der').
        Always returns bytes. Validates/normalises via cryptography when possible.
        """
        crl_pem = self.get_crl()

        if not crl_pem:
            raise CANotFoundError("CRL not found.")

        # Ensure we have PEM bytes
        pem_bytes = crl_pem.encode("utf-8") if isinstance(crl_pem, str) else crl_pem

        # Try to normalise/convert using cryptography
        try:
            crl_obj = x509.load_pem_x509_crl(pem_bytes, default_backend())
        except Exception:
            # If the stored content isn't parseable PEM, return as-is for 'pem',
            # but we cannot build DER without a proper parse.
            if fmt.lower() == "pem":
                return pem_bytes
            raise InvalidCertificateError("Stored CRL is not valid PEM; cannot export DER.")

        if fmt.lower() == "pem":
            return crl_obj.public_bytes(Encoding.PEM)
        elif fmt.lower() == "der":
            return crl_obj.public_bytes(Encoding.DER)
        else:
            raise ValueError(f"Unsupported CRL format: {fmt!r}")

    def get_crl_info(self) -> dict:
        """
        Returns information about the Certificate Revocation List stored in 1Password in PEM format
        """

        crl_pem = self.get_crl()

        if not crl_pem:
            raise CANotFoundError("CRL not found.")
        
        crl_bytes = crl_pem.strip().encode('utf-8')
        crl_x509 = x509.load_pem_x509_crl(crl_bytes, backend=default_backend())

        crl_info = {
            "valid": self.is_crl_valid(crl_bytes),
            "issuer": crl_x509.issuer.rfc4514_string(),
            "last_update": crl_x509.last_update_utc,
            "next_update": crl_x509.next_update_utc,
            "expired": crl_x509.next_update_utc < datetime.now(timezone.utc),
            "revoked": list(crl_x509),
        }
        try:
            crl_info["crl_number"] = crl_x509.extensions.get_extension_for_oid(
                ExtensionOID.CRL_NUMBER
            ).value.crl_number
        except x509.ExtensionNotFound:
            crl_info["crl_number"] = None

        return crl_info

    def get_private_key(self) -> str:
        """
        Returns the CA private key in PEM format.
        """
        if not self.ca_certbundle:
            raise CANotFoundError("CA certificate bundle not loaded.")
        return self.ca_certbundle.get_private_key()

    # ----------------
    # Generation / update methods
    # ----------------
    def generate_crl(self) -> str:
        """
        Generate a certificate revocation list in PEM format for the Certificate Authority
        """

        self.ca_database.process_ca_database()
        crl_days = self.ca_database.get_config_attributes()['crl_days']

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_certbundle.certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(crl_days))
        crl_serial = self.ca_database.increment_serial('crl')
        builder = builder.add_extension(x509.CRLNumber(crl_serial), critical=False)

        for cert_serial in self.ca_database.certs_revoked:
            cert_info = {
                'serial': cert_serial
            }

            cert_db_record = self.ca_database.query_cert(
                cert_info=cert_info, valid_only=False
            )
            revocation_date = datetime.strptime(
                cert_db_record['revocation_date'], '%Y%m%d%H%M%SZ'
            )
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(cert_serial))
                .revocation_date(revocation_date)
                .build(default_backend())
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        crl = builder.sign(self.ca_certbundle.private_key, hashes.SHA256(), default_backend())
        self.crl = crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        result = self.one_password.store_document(action='auto',
                        item_title=self.op_config['crl_title'],
                        filename=self.op_config['crl_filename'],
                        str_in=self.crl)

        if result.returncode != 0:
            raise CAStorageError(result.stderr or "Failed to store CRL in 1Password.")

        result = self.store_ca_database()

        if result.returncode != 0:
            raise CADatabaseError(result.stderr or "Failed to store CA database.")

        if self.ca_database.get_config_attributes()['ca_public_store']:
            self.upload_crl()

        return self.crl

    def generate_certificate_bundle(self, cert_type: str, item_title: str, config: dict) -> CertificateBundle:
        """
        Creates a certificate bundle from configuration
        """
        cert_bundle = CertificateBundle(
            cert_type=cert_type,
            item_title=item_title,
            import_certbundle=False,
            config=config
        )
        pem_csr = cert_bundle.get_csr().encode('utf-8')
        csr = x509.load_pem_x509_csr(pem_csr, default_backend())
        signed_certificate = self.sign_certificate(csr=csr, target=cert_type)
        cert_bundle.update_certificate(signed_certificate)

        self.store_certbundle(cert_bundle)

        return cert_bundle

    def import_certificate_bundle(self, cert_type: str, item_title: Optional[str], config: dict) -> CertificateBundle:
        """
        Imports a certificate bundle from variables
        """

        obj = CertificateBundle(cert_type=cert_type,
                                item_title=item_title,
                                import_certbundle=True,
                                config=config)

        if item_title is None:
            item_title = obj.get_certificate_attrib('cn')

        if item_title == DEFAULT_OP_CONF['ca_title'] and not obj.is_valid():
            raise InvalidCertificateError("CA certificate is not valid.")

        return obj

    def is_cert_valid(self, certificate: x509.Certificate) -> bool:
        """
        Check if a certificate is valid and was signed by the CA certificate.
        """
        ca_cert = self.ca_certbundle.certificate
        now = datetime.now(timezone.utc)

        try:
            ca_cert.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )
        except InvalidSignature:
            return False

        return certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc

    def is_crl_valid(self, crl_pem: bytes) -> bool:
        """
        Check if a CRL is valid.
        """
        crl = x509.load_pem_x509_crl(crl_pem, default_backend())
        ca_cert = self.ca_certbundle.certificate
        now = datetime.now(timezone.utc)

        try:
            ca_cert.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm
            )
        except InvalidSignature:
            return False

        return crl.last_update_utc <= now <= crl.next_update_utc

    def is_valid(self) -> bool:
        """
        Is the certifiate authority object valid
        """

        return self.ca_certbundle.is_valid()

    def rebuild_ca_database(self) -> dict:
        """
        Rebuild the CA certificate database from 1Password
        """
        result_dict = {}
        max_serial = 0

        result = self.one_password.item_list(categories=self.op_config['category'])

        if result.returncode != 0:
            raise CADatabaseError(result.stderr or "Failed to list 1Password items.")

        op_items = json.loads(result.stdout)

        for op_item in op_items:
            item_title = op_item['title']

            cert_bundle = self.retrieve_certbundle(item_title)

            if cert_bundle is None:
                continue

            cert_serial = cert_bundle.get_certificate_attrib('serial')

            if cert_serial in result_dict:
                raise DuplicateCertificateError(f"Duplicate serial {cert_serial} in CA database.")

            result_dict[cert_serial] = {
                'cert': cert_bundle.certificate,
                'title': item_title
            }

        for serial, attrs in sorted(result_dict.items()):
            self.ca_database.add_cert(self.format_db_item(certificate=attrs['cert'],
                                                          item_title=attrs['title']))

            if serial > max_serial:
                max_serial = serial

        next_serial = self.ca_database.get_config_attributes()['next_serial']

        if next_serial and max_serial >= next_serial:
            pass
        else:
            next_serial = (max_serial or 0) + 1
            self.ca_database.update_config({'next_serial': next_serial})

        result = self.store_ca_database()
        if result.returncode != 0:
            raise CADatabaseError(result.stderr or "Failed to store CA database.")

        return {"next_serial": next_serial, "count": self.ca_database.count_certs()}

    def rename_certbundle(self, src_item_title: str, dst_item_title: str) -> bool:
        """
        Renames a certificate bundle in 1Password
        """
        db_item = self.ca_database.query_cert(
            cert_info={'title': src_item_title},
            valid_only=False
        )
        if not db_item:
            raise CANotFoundError(f"Certificate with title {src_item_title!r} not found.")

        db_item['title'] = dst_item_title

        result = self.one_password.rename_item(
            src_title=src_item_title,
            dst_title=dst_item_title
        )

        if result.returncode != 0:
            raise CAStorageError(f"Unable to rename the item {src_item_title} to {dst_item_title}.")

        if self.ca_database.update_cert(db_item) and self.store_ca_database().returncode == 0:
            return True

        raise CADatabaseError("Rename succeeded in 1Password but database update failed.")

    def renew_certificate_bundle(self, cert_info: dict) -> str:
        """
        Renew a previously signed certificate from the stored CSR
        """
        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            raise CANotFoundError(f"Certificate with {cert_info} not found.")

        item_serial = cert['serial']
        item_title = cert['title']

        if item_title == str(item_serial):
            raise CAError("Cannot renew a certificate that has already been acted on.")

        cert_bundle = self.retrieve_certbundle(item_title=item_title)

        if cert_bundle is None:
            raise CANotFoundError(f"Certificate bundle {item_title!r} not found.")

        csr_pem = cert_bundle.get_csr()
        if not csr_pem:
            raise CAError(
                f"CSR not found for certificate '{item_title}' (serial {item_serial}); cannot renew."
            )

        pem_csr = csr_pem.encode('utf-8')
        cert_type = cert_bundle.get_type()
        csr = x509.load_pem_x509_csr(pem_csr, default_backend())
        signed_cert = self.sign_certificate(csr=csr, target=cert_type)

        cert_bundle.update_certificate(signed_cert)

        if item_title != str(item_serial):
            self.rename_certbundle(
                src_item_title=item_title,
                dst_item_title=str(item_serial)
            )
        else:
            raise CAError("Item title and serial are the same; unexpected state.")

        result = self.store_certbundle(certbundle=cert_bundle)

        if result.returncode != 0:
            raise CAStorageError("Unable to store the new certificate bundle.")

        result = self.store_ca_database()
        
        if result.returncode != 0:
            raise CADatabaseError("Unable to store the CA Database.")

        return cert_bundle.get_certificate()

    def retrieve_certbundle(self, item_title: str) -> CertificateBundle | None:
        """
        Imports a certificate bundle from 1Password
        """
        result = self.one_password.get_item(item_title)

        if result.returncode != 0:
            raise CAStorageError("Failed to retrieve certificate bundle from 1Password.")

        cert_config = {}
        cert_type = None
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

    def revoke_certificate(self, cert_info: dict) -> bool:
        """
        Revokes a previously signed certificate
        """

        cert = self.ca_database.query_cert(cert_info=cert_info, valid_only=True)

        if not cert:
            raise CANotFoundError(f"Certificate with {cert_info} not found.")

        item_serial = cert['serial']
        item_title = cert['title']

        if self.ca_database.process_ca_database(revoke_serial=item_serial):

            self.store_ca_database()

            if item_title != str(item_serial):
                result = self.rename_certbundle(src_item_title=item_title,
                                                dst_item_title=str(item_serial))

                if not result:
                    raise CAError(f"Unable to rename the certificate bundle {item_title} [{item_serial}]")

            return True

        raise CADatabaseError("Failed to process CA database for revocation.")

    def sign_certificate(self, csr: x509.CertificateSigningRequest, target: str | None = None) -> x509.Certificate:
        """
        Sign a csr to create a x509 certificate.

        target: One of {'ca','device','vpnclient','vpnserver','webserver'} (or None for a generic end-entity)

        """

        if self.ca_database is None or self.ca_certbundle is None:
            raise CAError("CA not initialized.")

        # Validate CSR signature (supports RSA/EC/DSA)
        pub = csr.public_key()

        try:
            if self._is_rsa_key(pub):
                pub.verify(
                    csr.signature,
                    csr.tbs_certrequest_bytes,
                    padding.PKCS1v15(),
                    csr.signature_hash_algorithm
                )
            #elif isinstance(pub, ec.EllipticCurvePublicKey):
            elif self._is_ec_key(pub):
                pub.verify(csr.signature, csr.tbs_certrequest_bytes,
                        ec.ECDSA(csr.signature_hash_algorithm))
            #elif isinstance(pub, dsa.DSAPublicKey):
            elif self._is_dsa_key(pub):
                pub.verify(csr.signature, csr.tbs_certrequest_bytes,
                        csr.signature_hash_algorithm)
            else:
                # Unknown key type – let cryptography do the sign later; but we consider this invalid here
                raise InvalidCertificateError(f"Unsupported CSR public key type: {type(pub).__name__}")
        except InvalidSignature as e:
            raise InvalidCertificateError("CSR signature invalid.") from e

        ca_config = self.ca_database.get_config_attributes()
        certificate_serial = self.ca_database.increment_serial('cert')
        validity = timedelta(ca_config['days'])
        now = datetime.now(timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_certbundle.certificate.subject)
            .public_key(pub)
            .serial_number(int(certificate_serial))
            .not_valid_before(now)
            .not_valid_after(now + validity)
        )

        # SKI: from SUBJECT (the new cert’s) public key  ✅
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub),
            critical=False,
        )

        # AKI: from ISSUER (the CA) public key  ✅
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.ca_certbundle.private_key.public_key()
            ),
            critical=False,
        )

        if target == 'ca':
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True)

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
                ), critical=True,
            )
        else:
            builder = builder.add_extension(
                x509.BasicConstraints(
                    ca=False,
                    path_length=None
                ),
                critical=False
            )

            if target == 'device':
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=self._is_rsa_key(pub),
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True,
                )
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]),
                    critical=False
                )
            
                common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                dns_names = [x509.DNSName(common_name)]

                try:
                    san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                    dns_names.extend([name for name in san if isinstance(name, x509.DNSName)])

                    combined_san = x509.SubjectAlternativeName(dns_names)

                    builder = builder.add_extension(combined_san, critical=False)

                except x509.ExtensionNotFound:
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(dns_names),
                        critical=False
                    )

            elif target == 'vpnclient':
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=False,
                        key_agreement=False,
                        data_encipherment=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        content_commitment=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True,
                )
                builder = builder.add_extension(
                    x509.ExtendedKeyUsage([
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]),
                    critical=True
                )

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

            elif target == 'webserver' or target is None:
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
                    builder = builder.add_extension(
                        x509.SubjectAlternativeName(dns_names),
                        critical=False
                    )

                # The CA and CRL URLs are stored in the CA config. When this object is instantiated
                # it will self sign and not have those variables. If it is signed by a CA, the URLs
                # will be pulled from the config.
                if 'crl_url' in ca_config and ca_config['crl_url']:
                    crl_distribution_points = [
                        x509.DistributionPoint(
                            full_name=[UniformResourceIdentifier(ca_config['crl_url'])],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None
                        )
                    ]

                    builder = builder.add_extension(
                        x509.CRLDistributionPoints(crl_distribution_points),
                        critical=False)

                if 'ca_url' in ca_config and ca_config['ca_url']:
                    aia_access_descriptions = [
                        x509.AccessDescription(
                            access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                            access_location=x509.UniformResourceIdentifier(ca_config['ca_url'])
                        )
                    ]

                    builder = builder.add_extension(
                        x509.AuthorityInformationAccess(aia_access_descriptions),
                        critical=False)
            else:
                raise InvalidCertificateError(f"Unknown certificate target: {target!r}")

        certificate = builder.sign(
            private_key=self.ca_certbundle.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        return certificate

    # ----------------
    # Persistence / upload methods
    # ----------------
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

        if self.ca_database.get_config_attributes()['ca_private_store']:
            self.upload_ca_database()

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
            raise InvalidCertificateError("Certificate Bundle is not valid.")

        if self.ca_database.query_cert(cert_info={"title": item_title}, valid_only=True) is not None:
            raise DuplicateCertificateError("Certificate with a duplicate name exists.")

        if self.ca_database.query_cert(cert_info={"serial": item_serial}, valid_only=True) is not None:
            raise DuplicateCertificateError("Certificate with a duplicate serial number exists.")

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

    # ----------------
    # Upload helpers
    # ----------------
    def get_storage_from_uri(self, uri: str) -> "StorageBackend":
        scheme = urlparse(uri).scheme

        if scheme == 's3':
            return StorageS3()
        if scheme == 'rsync':
            return StorageRsync()
        else:
            raise ValueError(f'Unsupported URI scheme: {scheme}')

    def upload_content(self, content: str | bytes, store_uri: str) -> bool:
        """ Generic content upload wrapper """

        storage = self.get_storage_from_uri(store_uri)

        ok = storage.upload(content, store_uri)
        if not ok:
            raise CAStorageError(f"Failed to upload content to {store_uri}")

        return True

    def upload_ca_database(self, store_uri: str = "") -> bool:
        """
        Upload the CA database (binary SQLite) to the private store,
        or to the provided store_uri.
        """
        if store_uri:
            ca_db_uri = store_uri
        else:
            cfg_store = self.ca_database.get_config_attributes().get('ca_private_store')
            if not cfg_store:
                raise CAStorageError(
                    "No private store configured for CA database. "
                    "Set 'ca_private_store' in the CA config or pass --store URI."
                )
            vault_name = (self.one_password.vault or "default").strip().lower()
            ca_db_uri = f"{cfg_store.rstrip('/')}/{vault_name}.sqlite"

        binary_db = self.ca_database.export_database_binary()

        return self.upload_content(binary_db, ca_db_uri)

    def upload_ca_cert(self, store_uri: str = "") -> bool:
        """
        Upload the CA Certificate to public store, or to the provided store_uri.
        """
        if store_uri:
            ca_cert_uri = store_uri
        else:
            cfg_store = self.ca_database.get_config_attributes().get('ca_public_store')
            if not cfg_store:
                raise CAStorageError(
                    "No public store configured for CA certificate. "
                    "Set 'ca_public_store' in the CA config or pass --store URI."
                )
            ca_cert_uri = f"{cfg_store.rstrip('/')}/{DEFAULT_STORAGE_CONF['ca_cert_file']}"

        return self.upload_content(self.get_certificate(), ca_cert_uri)

    def upload_crl(self, store_uri: str = "") -> bool:
        """
        Upload the CRL to public store, or to the provided store_uri.
        """
        if store_uri:
            crl_uri = store_uri
        else:
            cfg_store = self.ca_database.get_config_attributes().get('ca_public_store')
            if not cfg_store:
                raise CAStorageError(
                    "No public store configured for CRL. "
                    "Set 'ca_public_store' in the CA config or pass --store URI."
                )
            crl_uri = f"{cfg_store.rstrip('/')}/{DEFAULT_STORAGE_CONF['crl_file']}"

        crl = self.get_crl()
        if crl is None:
            raise CANotFoundError("CRL not found.")

        return self.upload_content(crl, crl_uri)

    # ----------------
    # Key helpers
    # ----------------
    @staticmethod
    def _is_rsa_key(key) -> bool:
        return isinstance(key, rsa.RSAPublicKey)

    @staticmethod
    def _is_ec_key(key) -> bool:
        return isinstance(key, ec.EllipticCurvePublicKey)

    @staticmethod
    def _is_dsa_key(key) -> bool:
        return isinstance(key, dsa.DSAPublicKey)

def prepare_cert_authority(one_password: Op) -> CertificateAuthority:
    """
    Prepares the certificate authority object for later consumption

    Args:
        command (str): The way we will construct the certificate authority
        config (dict): CA Configuration
    """

    ca_config = { 'command': 'retrieve' }

    return CertificateAuthority(one_password=one_password,
                            config=ca_config,
                            op_config=DEFAULT_OP_CONF)
