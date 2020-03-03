from OpenSSL import crypto, SSL  # pip3 install pyOpenSSL
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
    hashes
)
from cryptography.hazmat.backends import (
    default_backend
)
from cryptography.hazmat.backends.openssl.backend import (
    backend as x509_openssl_backend
)
import requests
import socket
import datetime
from pyasn1.codec.ber import decoder as asn1_decoder
from .ocsp_check import OcspChecker


class CertChecker:
    cert = None
    cert_from_disc = False
    cert_from_host = False
    cert_from_host_conn_proto = None

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

    def load_pem_from_host(self, hostname, port, verbose=False):
        self.cert = None
        server_cert = None

        # Initialize context
        ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        tls_version = None
        ocsp_assertion = None

        def _info_cb(conn, where_at, return_code):
            # print("_info_cb: %d" % where_at)
            pass

        def _connection_cb(conn, cert, errnum, depth, ok):
            nonlocal tls_version
            nonlocal server_cert
            # print("_connection_cb, cert: %s" % cert)
            tls_version = conn.get_protocol_version_name()
            # print("_connection_cb, tls_version: %s" % tls_version)
            server_cert = cert

            return True

        def _ocsp_cb(conn, assertion, data):
            nonlocal ocsp_assertion
            ocsp_assertion = assertion
            # print("_ocsp_cb: %d" % len(assertion))
            # print(assertion)

            return True

        ctx.set_verify(SSL.VERIFY_PEER, _connection_cb)
        ctx.set_info_callback(_info_cb)
        ctx.set_ocsp_client_callback(callback=_ocsp_cb, data=None)

        tcp_conn = socket.create_connection((hostname, port))
        host_ip_addr = tcp_conn.getpeername()[0]
        ssl_conn = SSL.Connection(ctx, tcp_conn)
        ssl_conn.set_tlsext_host_name(hostname.encode())
        ssl_conn.request_ocsp()
        ssl_conn.set_connect_state()
        ssl_conn.do_handshake()

        if not server_cert:
            raise ValueError("Failed to load certificate from %s:%d" % (hostname, port))

        if verbose:
            print("TLS-version used in connection: %s" % tls_version)
            print("OCSP assertion length: %d" % len(ocsp_assertion))
        self.cert = server_cert.to_cryptography()
        self._process_extensions(verbose=verbose)
        self.last_certificate_pem = self.cert.public_bytes(serialization.Encoding.PEM)

        self.cert_from_disc = False
        self.cert_from_host = host_ip_addr
        self.cert_from_host_conn_proto = tls_version

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
            raise ValueError("Need cert! Cannot do.")

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

        verify_data = {
            'certificate_from_disc': self.cert_from_disc,
            'certificate_from_host': self.cert_from_host,
            'certificate_from_connection_proto': self.cert_from_host_conn_proto,
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
                'public_key': cert_key_bytes
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
            raise ValueError("Cannot do get OCSP URI! Cert has no URL in AIA.")

        issuer_cert = self._load_issuer_cert()
        ocsp = OcspChecker(self.cert, issuer_cert)
        ocsp_stat, ocsp_data = ocsp.verify(ocsp_uri, verbose=verbose)
        self.last_ocsp_response = ocsp.last_ocsp_response

        if not ocsp_data['response_status_ok']:
            return False, ocsp_data

        # Response verify 1:
        # Make sure response certificate serial number matches our target certificate serial
        serial_nro = self.cert.serial_number
        if serial_nro == ocsp_data['serial_number']:
            ocsp_data['serial_number_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['serial_number_match'] = False

        # Response verify 2:
        # Make sure response issuer key hash matches target certificate issuer certificate key hash.
        # Debug: https://lapo.it/asn1js/ or https://holtstrom.com/michael/tools/asn1decoder.php will be handy
        issuer_cert_public_key = issuer_cert.public_key()
        issuer_cert_key = issuer_cert_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                              )
        issuer_cert_key_asn1, _remainder = asn1_decoder.decode(issuer_cert_key)
        issuer_cert_key_bytes = issuer_cert_key_asn1[1].asOctets()

        if ocsp_data['hash_algorithm'].lower() == 'sha1':
            issuer_cert_key_hash = hashes.Hash(hashes.SHA1(), backend=issuer_cert._backend)
        elif ocsp_data['hash_algorithm'].lower() == 'sha256':
            issuer_cert_key_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._backend)
        else:
            raise ValueError(
                "Cannot verify OCSP-response! Information hashed with a '%s' and I don't know how to handle it." %
                ocsp_data['hash_algorithm'])

        issuer_cert_key_hash.update(issuer_cert_key_bytes)
        issuer_cert_key_hash_bytes = issuer_cert_key_hash.finalize()

        ocsp_data['issuer_public_key'] = issuer_cert_key_bytes
        if issuer_cert_key_hash_bytes == ocsp_data['issuer_key_hash']:
            ocsp_data['issuer_key_hash_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['issuer_key_hash_match'] = False

        # OBSOLETE! begin using SHA-1 hashed SubjectKeyIdentifier
        if False:
            issuer_key_id_ext = None
            extensions = x509_extensions.Extensions(issuer_cert.extensions)
            try:
                issuer_key_id_ext = extensions.get_extension_for_class(x509_extensions.SubjectKeyIdentifier)
            except x509_extensions.ExtensionNotFound:
                pass
            if issuer_key_id_ext:
                issuer_cert_key_hash = issuer_key_id_ext.value
                print("Extension issuer key hash : %s" % issuer_cert_key_hash.digest.hex())
                if issuer_cert_key_hash.digest == ocsp_data['issuer_key_hash']:
                    ocsp_data['issuer_key_hash_match'] = True
                else:
                    ocsp_stat = False
                    ocsp_data['issuer_key_hash_match'] = False
            else:
                ocsp_stat = False
        # OBSOLETE! ends here

        # Response verify 3:
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
            raise ValueError(
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

        return ocsp_stat, ocsp_data

    def _load_issuer_cert(self):
        ca_issuer = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ca_issuer = aia.access_location.value
        if not ca_issuer:
            raise ValueError("Cannot do get issuer certificate! Cert has no URL in AIA.")

        # Go get the issuer certificate from indicated URI
        r = requests.get(ca_issuer)
        r.raise_for_status()

        contentType = r.headers['content-type']

        if contentType in ['application/x-x509-ca-cert', 'application/pkix-cert']:
            # This is a basic DER-formatted certificate
            issuer_cert = x509.load_der_x509_certificate(r.content, x509_openssl_backend)
        elif contentType == 'application/pkcs7-mime':
            # This is a DER-formatted certificate wrapped into PKCS#7

            # DANGER! DANGER! DANGER!
            # Digging into guts of OpenSSL isn't smart. It's stupid. Very stupid.
            # For extracting a certificate out of a PKCS#7 there is no ready-made solution and this is the only
            # applicable way (for now). I'll be standing by for OpenSSL-team to come up with a proper interface for
            # certificate extraction.
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, r.content)

            certs = _ffi.NULL
            if pkcs7.type_is_signed():
                certs = pkcs7._pkcs7.d.sign.cert
            elif pkcs7.type_is_enveloped():
                certs = pkcs7._pkcs7.d.enveloped.cert
            elif pkcs7.type_is_signedAndEnveloped():
                certs = pkcs7._pkcs7.d.signed_and_enveloped.cert

            num_certs_in_pkcs7 = _lib.sk_X509_num(certs)
            if num_certs_in_pkcs7 != 1:
                raise ValueError(
                    'Found PKCS#7 certificate with multiple certificates! Cannot decide which one to load.')

            cert_data_ptr = _lib.X509_dup(_lib.sk_X509_value(certs, 0))
            interim_issuer_cert = crypto.X509._from_raw_x509_ptr(cert_data_ptr)
            # end DANGER! DANGER! DANGER! end

            issuer_cert = interim_issuer_cert.to_cryptography()
        else:
            raise ValueError("Certificate loaded from %s has content type %s. Don't know how to process it." %
                             (ca_issuer, contentType))
        self.last_issuer_certificate_pem = issuer_cert.public_bytes(serialization.Encoding.PEM)

        return issuer_cert
