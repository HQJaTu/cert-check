from OpenSSL import crypto  # pip3 install pyOpenSSL
from OpenSSL._util import (
    ffi as _ffi,
    lib as _lib,
)
from cryptography.x509 import (
    base as x509,
    extensions as x509_extensions,
    oid as x509_oid,
    DNSName, IPAddress, UniformResourceIdentifier
)
from cryptography.hazmat.primitives import (
    serialization,
    hashes,
    asymmetric
)
from cryptography.hazmat.backends import (
    default_backend
)
from cryptography.hazmat.backends.openssl.backend import (
    backend as x509_openssl_backend
)
import cryptography.exceptions
import socket
import ssl
import datetime
from pyasn1.codec.ber import decoder as asn1_decoder
from .ocsp_check import OcspChecker
from .requests import RequestsSession
from .exceptions import *
from requests import exceptions as requests_exceptions


class CertChecker:
    DEFAULT_TIMEOUT: int = 5
    connection_timeout = DEFAULT_TIMEOUT

    cert = None
    cert_from_disc = False
    cert_from_host = False
    cert_from_host_conn_proto = None
    cert_from_host_conn_cipher = None
    cert_from_host_conn_cipher_bits = None

    # Extensions of cert
    aia_ext = None
    alt_name_ext = None
    key_id_ext = None

    # Request results
    last_ocsp_response = None
    last_certificate_pem = None
    last_issuer_certificate_pem = None

    def __init__(self):
        self.cert = None

    def has_cert(self):
        return self.cert is not None

    def load_pem_from_file(self, certfile):
        st_cert = open(certfile, 'rb').read()

        self.cert = x509_openssl_backend.load_pem_x509_certificate(st_cert)
        self._process_extensions()
        self.last_certificate_pem = None

        self.cert_from_disc = True
        self.cert_from_host = False
        self.cert_from_host_conn_proto = None
        self.cert_from_host_conn_cipher = None
        self.cert_from_host_conn_cipher_bits = None

    def load_pem_from_host(self, hostname, port, verbose=False):
        self.cert = None

        # Debug: Print the supported SSL and TLS protocols
        if False:
            print("SSL v3: %s" % ssl.HAS_SSLv3)
            print("TLS v1: %s" % ssl.HAS_TLSv1)
            print("TLS v1.1: %s" % ssl.HAS_TLSv1_1)
            print("TLS v1.2: %s" % ssl.HAS_TLSv1_2)
            print("TLS v1.3: %s" % ssl.HAS_TLSv1_3)

        # Initialize context
        # Context: The one with hostname verifiction
        # ctx = ssl.create_default_context()
        # Context: The one without hostname verifiction
        ctx = ssl._create_unverified_context()
        tls_versions = [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1]
        if False:
            print("Info: Going for %s in %d" % (hostname, port))
        for tls_version in tls_versions:
            ctx.minimum_version = tls_version
            a_socket = socket.socket()
            a_socket.settimeout(CertChecker.connection_timeout)
            tls_socket = ctx.wrap_socket(a_socket, server_hostname=hostname)
            try:
                tls_socket.connect((hostname, port))
            except OSError:
                raise ConnectionException(
                    "Failed to load certificate from %s:%d. OS error." % (hostname, port))
            except socket.timeout:
                raise ConnectionException(
                    "Failed to load certificate from %s:%d. Connection timed out." % (hostname, port))
            except ssl.SSLError as exc:
                tls_socket = None
                message = exc.args[1]
                if 'SSL: TLSV1_ALERT_PROTOCOL_VERSION' in message:
                    # Decrease TLS-version and go again
                    continue
                raise ConnectionException("Failed to load certificate from %s:%d. OpenSSL failed: %s" %
                                          (hostname, port, message)) from None

        if not tls_socket:
            raise ConnectionException("Failed to load certificate from %s:%d. No TLS-version allowed connection." %
                                      (hostname, port))

        server_cert_bytes = tls_socket.getpeercert(binary_form=True)
        host_ip_addr = tls_socket.getpeername()[0]
        cipher_name, tls_version, cipher_secret_size_bits = tls_socket.cipher()

        if False:
            print("Protocol: %s, %d-bit %s" % (tls_version, cipher_secret_size_bits, cipher_name))
        self.cert = x509.load_der_x509_certificate(server_cert_bytes, x509_openssl_backend)
        self._process_extensions(verbose=verbose)
        self.last_certificate_pem = self.cert.public_bytes(serialization.Encoding.PEM)

        self.cert_from_disc = False
        self.cert_from_host = host_ip_addr
        self.cert_from_host_conn_proto = tls_version
        self.cert_from_host_conn_cipher = cipher_name
        self.cert_from_host_conn_cipher_bits = cipher_secret_size_bits

    def _process_extensions(self, verbose=False):
        self.aia_ext = None
        self.alt_name_ext = None
        self.key_id_ext = None

        extensions = x509_extensions.Extensions(self.cert.extensions)
        try:
            self.aia_ext = extensions.get_extension_for_class(x509_extensions.AuthorityInformationAccess)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have AuthorityInformationAccess extension")

        try:
            self.alt_name_ext = extensions.get_extension_for_class(x509_extensions.SubjectAlternativeName)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have SubjectAlternativeName extension")

        try:
            self.key_id_ext = extensions.get_extension_for_class(x509_extensions.SubjectKeyIdentifier)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have SubjectKeyIdentifier extension")

    def verify(self, ocsp=True, verbose=False):
        if not self.cert:
            raise ConnectionException("Need cert! Cannot do.")

        issuer = self.cert.issuer
        subject = self.cert.subject
        serial_nro = self.cert.serial_number
        sig_algo = self.cert.signature_hash_algorithm.__class__.__name__.lower()
        valid_from = self.cert.not_valid_before
        valid_to = self.cert.not_valid_after
        now = datetime.datetime.utcnow()
        if now < valid_from or now > valid_to:
            is_expired = True
        else:
            is_expired = False

        issuer_info = {}
        subject_info = {}
        for issuer_compo in issuer:
            issuer_info[issuer_compo.oid._name] = issuer_compo.value
        for subject_compo in subject:
            subject_info[subject_compo.oid._name] = subject_compo.value

        cert_public_key = self.cert.public_key()
        cert_key = cert_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                )
        cert_key_asn1, _remainder = asn1_decoder.decode(cert_key)
        cert_key_bytes = cert_key_asn1[1].asOctets()
        public_key_type = cert_public_key.__class__.__name__

        dns_names = []
        ip_addresses = []
        urls = []
        if self.alt_name_ext:
            for alt_name in self.alt_name_ext.value:
                if isinstance(alt_name, DNSName):
                    dns_names.append(alt_name.value)
                elif isinstance(alt_name, IPAddress):
                    ip_addresses.append(alt_name.value)
                elif isinstance(alt_name, UniformResourceIdentifier):
                    urls.append(alt_name.value)

        ocsp_uri = None
        ca_issuer = None
        if self.aia_ext:
            for aia in self.aia_ext.value:
                if aia.access_method == x509_oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(aia.access_location, UniformResourceIdentifier):
                        ocsp_uri = aia.access_location.value
                if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(aia.access_location, UniformResourceIdentifier):
                        ca_issuer = aia.access_location.value

            if ocsp:
                ocsp_stat, ocsp_data = self._verify_ocsp(verbose=verbose)
            else:
                ocsp_stat = None
                ocsp_data = {}
        else:
            ocsp_stat = None
            ocsp_data = {}

        if self.cert_from_host:
            connection_info = {
                'host_ip': self.cert_from_host,
                'protocol': self.cert_from_host_conn_proto,
                'cipher_name': self.cert_from_host_conn_cipher,
                'cipher_secret_size_bits': self.cert_from_host_conn_cipher_bits
            }
        else:
            connection_info = None
        verify_data = {
            'certificate_from_disc': self.cert_from_disc,
            'certificate_from_host': connection_info,
            'certificate': {
                'expired': is_expired,
                'valid_from': valid_from,
                'valid_to': valid_to,
                'issuer': issuer_info,
                'subject': subject_info,
                'serial_nro': serial_nro,
                'signature_algorithm': sig_algo,
                'dns_names': dns_names,
                'ip_addresses': ip_addresses,
                'urls': urls,
                'issuer_cert_url': ca_issuer,
                'ocsp_url': ocsp_uri,
                'public_key': cert_key_bytes,
                'public_key_type': public_key_type[1:]
            },
            'ocsp_run': not ocsp_stat == None,
            'ocsp_ok': ocsp_stat,
            'ocsp': ocsp_data
        }

        return not is_expired and ocsp_stat, verify_data

    def issuer_cert_uri(self):
        ca_issuer = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ca_issuer = aia.access_location.value

        return ca_issuer

    def ocsp_uri(self):
        ocsp_uri = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.OCSP:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ocsp_uri = aia.access_location.value

        return ocsp_uri

    def _verify_ocsp(self, verbose=False):
        ocsp_uri = self.ocsp_uri()
        if not ocsp_uri:
            raise OCSPUrlException("Cannot do get OCSP URI! Cert has no URL in AIA.")

        issuer_cert = self._load_issuer_cert()
        if not issuer_cert:
            return None, {}

        ocsp = OcspChecker(self.cert, issuer_cert)
        ocsp_stat, ocsp_data = ocsp.request(ocsp_uri, verbose=verbose)
        self.last_ocsp_response = ocsp.last_ocsp_response

        issuer_cert_public_key = issuer_cert.public_key()
        issuer_cert_key = issuer_cert_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                              )
        issuer_cert_key_asn1, _remainder = asn1_decoder.decode(issuer_cert_key)
        issuer_cert_key_bytes = issuer_cert_key_asn1[1].asOctets()
        issuer_public_key_type = issuer_cert_public_key.__class__.__name__
        ocsp_data['issuer_public_key'] = issuer_cert_key_bytes
        ocsp_data['issuer_public_key_type'] = issuer_public_key_type[1:]

        if not ocsp_data['response_status_ok']:
            return False, ocsp_data

        # Response verify process:
        # RFC 2560, 3.2  Signed Response Acceptance Requirements:
        # 1) The certificate identified in a received response corresponds to
        #    that which was identified in the corresponding request;
        # 2) The signature on the response is valid;
        # 3) The identity of the signer matches the intended recipient of the request.
        # 4) The signer is currently authorized to sign the response.
        # 5) The time at which the status being indicated is known to be correct (thisUpdate) is sufficiently recent.
        # 6) When available, the time at or before which newer information will be available
        #    about the status of the certificate (nextUpdate) is greater than the current time.

        # Steps:
        # 1) Serial number check
        # 2) RSA verify with issuer key
        # 3) If issuer hash present, matched
        # 4) (assumption) Issuer signs the response. For more information see RFC 6960 below
        # 5) to-do
        # 6) to-do

        # Response verify 1:
        # To-do: Verify signature

        # RFC 6960, 4.2.2.2. Authorized Responders, https://tools.ietf.org/html/rfc6960
        # Three rules for the signature of an Authorized Responder:
        #    1. Matches a local configuration of OCSP signing authority for the
        #       certificate in question, or
        #    2. Is the certificate of the CA that issued the certificate in
        #       question, or
        #    3. Includes a value of id-kp-OCSPSigning in an extended key usage
        #       extension and is issued by the CA that issued the certificate in
        #       question as stated above.
        # JaTu's notes on RFC 6960, 4.2.2.2.:
        #    1. There is no local configuration for anybody!! Never seen one in wild world.
        #    2. This is the typical scenario covered in above code. Issuer cert handles also OCSP responses.
        #    3. Code is missing for this scenario.
        #    3.1. Response MUST have 'responder_key_hash'. Not all OCSP responses do.
        #    3.2. If 'responder_key_hash' matches issuer key hash, then this is case 2.
        #    3.3. For non-matching responder keys, we MUST get our hands to the responder certificate. From where?
        #    3.4. Responder certificate must have extended key usage of: OCSP-responder enabled in it.

        signature = ocsp_data['signature']

        # Perform the verification.
        signature_verifies_ok = None
        if issuer_public_key_type == '_RSAPublicKey':
            try:
                issuer_cert_public_key.verify(
                    signature,
                    ocsp_data['tbs_response_bytes'],
                    asymmetric.padding.PKCS1v15(),
                    ocsp_data['signature_hash_algorithm'],
                )
                signature_verifies_ok = True
            except cryptography.exceptions.InvalidSignature:
                signature_verifies_ok = False
        elif issuer_public_key_type == '_DSAPublicKey':
            pass
        elif issuer_public_key_type == '_EllipticCurvePublicKey':
            ecdsa_algorithm = asymmetric.ec.ECDSA(ocsp_data['signature_hash_algorithm'])
            try:
                issuer_cert_public_key.verify(
                    signature,
                    ocsp_data['tbs_response_bytes'],
                    ecdsa_algorithm
                )
                signature_verifies_ok = True
            except cryptography.exceptions.InvalidSignature:
                signature_verifies_ok = False
        elif issuer_public_key_type == '_DHPublicKey':
            pass
        elif issuer_public_key_type == '_Ed25519PublicKey':
            pass
        elif issuer_public_key_type == '_X448PublicKey':
            pass
        elif issuer_public_key_type == '_X25519PublicKey':
            pass
        elif issuer_public_key_type == '_Ed448PublicKey':
            pass
        else:
            raise UnsupportedPublicKeyAlgorithmException("Unsupported key type: %s" % issuer_public_key_type)

        if verbose:
            if signature_verifies_ok:
                print('%s: Signature verification success: Payload and signature files verify' %
                      issuer_public_key_type)
            else:
                print('%s: Signature verification fail: Payload and/or signature files failed verification!' %
                      issuer_public_key_type)

        ocsp_data['signature_verify_status'] = signature_verifies_ok

        # Response verify 2:
        # Make sure response certificate serial number matches our target certificate serial
        serial_nro = self.cert.serial_number
        if serial_nro == ocsp_data['serial_number']:
            ocsp_data['serial_number_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['serial_number_match'] = False

        # Response verify 3:
        # Make sure response issuer key hash matches target certificate issuer certificate key hash.
        # Debug: https://lapo.it/asn1js/ or https://holtstrom.com/michael/tools/asn1decoder.php will be handy
        if ocsp_data['hash_algorithm'].lower() == 'sha1':
            issuer_cert_key_hash = hashes.Hash(hashes.SHA1(), backend=issuer_cert._backend)
        elif ocsp_data['hash_algorithm'].lower() == 'sha256':
            issuer_cert_key_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._backend)
        else:
            raise OCSPHashException(
                "Cannot verify OCSP-response! Information hashed with a '%s' and I don't know how to handle it." %
                ocsp_data['hash_algorithm'])

        issuer_cert_key_hash.update(issuer_cert_key_bytes)
        issuer_cert_key_hash_bytes = issuer_cert_key_hash.finalize()

        if issuer_cert_key_hash_bytes == ocsp_data['issuer_key_hash']:
            ocsp_data['issuer_key_hash_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['issuer_key_hash_match'] = False

        # Response verify 4:
        # Make sure response name hash matches target certificate issuer hashed certificate name.
        certificate_asn1_bytes = issuer_cert.public_bytes(serialization.Encoding.DER)
        cert_as_openssl = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_asn1_bytes)
        cert_as_openssl_subject = cert_as_openssl.get_subject()
        subject_bytes = cert_as_openssl_subject.der()

        if ocsp_data['hash_algorithm'].lower() == 'sha1':
            subject_hash = hashes.Hash(hashes.SHA1(), backend=issuer_cert._backend)
        elif ocsp_data['hash_algorithm'].lower() == 'sha256':
            subject_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._backend)
        else:
            raise OCSPHashException(
                "Cannot verify OCSP-response! Information hashed with a '%s' and I don't know how to handle it." %
                ocsp_data['hash_algorithm'])

        subject_hash.update(subject_bytes)
        subject_hash_bytes = subject_hash.finalize()

        ocsp_data['issuer_name_seen'] = subject_bytes
        if subject_hash_bytes == ocsp_data['issuer_name_hash']:
            ocsp_data['issuer_name_hash_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['issuer_name_hash_match'] = False

        # Verify done!

        return ocsp_stat, ocsp_data

    def _load_issuer_cert(self):
        ca_issuer_url = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ca_issuer_url = aia.access_location.value
        if not ca_issuer_url:
            raise IssuerCertificateException("Cannot do get issuer certificate! Cert has no URL in AIA.")

        # Go get the issuer certificate from indicated URI
        session = RequestsSession.get_requests_retry_session(retries=2)
        try:
            response = session.get(ca_issuer_url, timeout=CertChecker.connection_timeout / 10)
            response.raise_for_status()
        except requests_exceptions.ConnectTimeout:
            return None

        issuer_cert = None
        if 'content-type' in response.headers:
            contentType = response.headers['content-type']
        else:
            # No Content-Type given. Let's guess!
            try:
                issuer_cert = x509.load_der_x509_certificate(response.content, x509_openssl_backend)
                response.headers['content-type'] = 'application/x-x509-ca-cert'
            except TypeError:
                issuer_cert = None
            if not issuer_cert:
                try:
                    issuer_cert = x509.load_pem_x509_certificate(response.content, x509_openssl_backend)
                except TypeError:
                    raise IssuerCertificateException(
                        'Cannot do get issuer certificate! No idea on how to process response from %s' % ca_issuer_url)

        if not issuer_cert:
            if contentType in ['application/x-x509-ca-cert', 'application/pkix-cert']:
                # This is a basic DER-formatted certificate
                issuer_cert = x509.load_der_x509_certificate(response.content, x509_openssl_backend)
            elif contentType == 'application/pkcs7-mime':
                # This is a DER-formatted certificate wrapped into PKCS#7

                # DANGER! DANGER! DANGER!
                # Digging into guts of OpenSSL isn't smart. It's stupid. Very stupid.
                # For extracting a certificate out of a PKCS#7 there is no ready-made solution and this is the only
                # applicable way (for now). I'll be standing by for OpenSSL-team to come up with a proper interface for
                # certificate extraction.
                pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, response.content)

                certs = _ffi.NULL
                if pkcs7.type_is_signed():
                    certs = pkcs7._pkcs7.d.sign.cert
                elif pkcs7.type_is_enveloped():
                    certs = pkcs7._pkcs7.d.enveloped.cert
                elif pkcs7.type_is_signedAndEnveloped():
                    certs = pkcs7._pkcs7.d.signed_and_enveloped.cert

                num_certs_in_pkcs7 = _lib.sk_X509_num(certs)
                if num_certs_in_pkcs7 != 1:
                    raise PKCS7Exception(
                        'Found PKCS#7 certificate with multiple certificates! Cannot decide which one to load.')

                cert_data_ptr = _lib.X509_dup(_lib.sk_X509_value(certs, 0))
                interim_issuer_cert = crypto.X509._from_raw_x509_ptr(cert_data_ptr)
                # end DANGER! DANGER! DANGER! end

                issuer_cert = interim_issuer_cert.to_cryptography()
            else:
                raise MimeTypeException(
                    "Certificate loaded from %s has content type %s. Don't know how to process it." %
                    (ca_issuer_url, contentType))

        # Store the issuer certificate also in PEM-format for possible use.
        self.last_issuer_certificate_pem = issuer_cert.public_bytes(serialization.Encoding.PEM)

        return issuer_cert
