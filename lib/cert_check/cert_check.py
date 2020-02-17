from OpenSSL import crypto, SSL  # pip3 install pyOpenSSL
from cryptography.x509 import DNSName, IPAddress, UniformResourceIdentifier, AccessDescription, ObjectIdentifier
from cryptography.x509 import extensions as x509_extensions
from cryptography.x509 import oid as x509_oid
import socket
import datetime
from .ocsp_check import OcspChecker


class CertChecker:
    cert = None
    aia_ext = None
    alt_name_ext = None

    def __init__(self):
        self.cert = None

    def has_cert(self):
        return self.cert is not None

    def load_pem_from_file(self, certfile):
        st_cert = open(certfile, 'rt').read()

        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, st_cert)
        self._process_extensions()

    def load_pem_from_host(self, hostname, port, verbose=False):
        self.cert = None

        # Initialize context
        ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        tls_version = None
        ocsp_assertion = None

        def _info_cb(conn, where_at, return_code):
            #print("_info_cb: %d" % where_at)
            pass

        def _connection_cb(conn, cert, errnum, depth, ok):
            nonlocal tls_version
            #print("_connection_cb, cert: %s" % cert)
            tls_version = conn.get_protocol_version_name()
            #print("_connection_cb, tls_version: %s" % tls_version)
            self.cert = cert

            return True

        def _ocsp_cb(conn, assertion, data):
            nonlocal ocsp_assertion
            ocsp_assertion = assertion
            #print("_ocsp_cb: %d" % len(assertion))
            #print(assertion)

            return True

        ctx.set_verify(SSL.VERIFY_PEER, _connection_cb)
        ctx.set_info_callback(_info_cb)
        ctx.set_ocsp_client_callback(callback=_ocsp_cb, data=None)

        tcp_conn = socket.create_connection((hostname, port))
        ssl_conn = SSL.Connection(ctx, tcp_conn)
        ssl_conn.set_tlsext_host_name(hostname.encode())
        ssl_conn.request_ocsp()
        ssl_conn.set_connect_state()
        ssl_conn.do_handshake()

        if self.cert:
            if verbose:
                print("TLS-version used in connection: %s" % tls_version)
                print("OCSP assertion length: %d" % len(ocsp_assertion))
            self._process_extensions()

    def _process_extensions(self):
        cert = self.cert.to_cryptography()
        extensions = x509_extensions.Extensions(cert.extensions)
        self.aia_ext = extensions.get_extension_for_class(x509_extensions.AuthorityInformationAccess)
        self.alt_name_ext = extensions.get_extension_for_class(x509_extensions.SubjectAlternativeName)

    def verify(self, verbose=False):
        if not self.cert:
            raise ValueError("Need cert! Cannot do.")

        is_expired = self.cert.has_expired()
        issuer = self.cert.get_issuer()
        subject = self.cert.get_subject()
        serial_nro = self.cert.get_serial_number()
        sig_algo = self.cert.get_signature_algorithm().decode('ascii')
        valid_from = self.cert.get_notBefore().decode('ascii')
        valid_from = datetime.datetime.strptime(valid_from, '%Y%m%d%H%M%SZ')
        valid_to = self.cert.get_notAfter().decode('ascii')
        valid_to = datetime.datetime.strptime(valid_to, '%Y%m%d%H%M%SZ')

        issuer_info = ""
        subject_info = ""
        for issuer_compo in issuer.get_components():
            issuer_info += "\n    %s=%s" % (issuer_compo[0].decode('ascii'), issuer_compo[1].decode('ascii'))
        for subject_compo in subject.get_components():
            subject_info += "\n    %s=%s" % (subject_compo[0].decode('ascii'), subject_compo[1].decode('ascii'))

        if verbose:
            print("Cert %s expired" % ('has' if is_expired else 'not'))
            print("    %s - %s" % (valid_from, valid_to))
            print("Issuer: %s" % issuer_info)
            print("Subject: %s" % subject_info)
            print("Serial #: %s" % serial_nro)
            print("Signature algo: %s" % sig_algo)

        if verbose and self.alt_name_ext:
            dns_names = []
            ip_addresses = []
            urls = []
            for alt_name in self.alt_name_ext.value:
                if isinstance(alt_name, DNSName):
                    dns_names.append(alt_name.value)
                elif isinstance(alt_name, IPAddress):
                    ip_addresses.append(alt_name.value)
                elif isinstance(alt_name, UniformResourceIdentifier):
                    urls.append(alt_name.value)

            if dns_names or dns_names or urls:
                print("Alternate names:")
            if dns_names:
                print("    DNS-names: %s" % ', '.join(dns_names))
            if ip_addresses:
                print("    IP-addresses: %s" % ', '.join(ip_addresses))
            if urls:
                print("    URIs: %s" % ', '.join(urls))

        if self.aia_ext:
            ocsp_uri = None
            ca_issuer = None
            for aia in self.aia_ext.value:
                if aia.access_method == x509_oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(aia.access_location, UniformResourceIdentifier):
                        ocsp_uri = aia.access_location.value
                if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(aia.access_location, UniformResourceIdentifier):
                        ca_issuer = aia.access_location.value

            if verbose:
                print("Authority Information Access (AIA):")
                print("    Issuer: %s" % ca_issuer)
                print("    OCSP: %s" % ocsp_uri)

            ocsp_stat = self._verify_ocsp(verbose=verbose)
        else:
            ocsp_stat = True

        return not is_expired and ocsp_stat

    def _verify_ocsp(self, verbose=False):
        ocsp_uri = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.OCSP:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ocsp_uri = aia.access_location.value
        if not ocsp_uri:
            raise ValueError("Cannot do get OCSP URI! Cert has no URL in AIA.")

        issuer_cert = self._load_issuer_cert()
        ocsp = OcspChecker(self.cert, issuer_cert)
        ocsp_stat, ocsp_data = ocsp.verify(ocsp_uri)

        if verbose:
            print("OCSP status:")
            print("    Response hash algorithm: %s" % ocsp_data['hash_algorithm'])
            print("    Response signature hash algorithm: %s" % ocsp_data['signature_hash_algorithm'])
            print("    Certificate status: %s" % ocsp_data['certificate_status'].name)
            print("    Revocation time: %s" % ocsp_data['revocation_time'])
            print("    Revocation reason: %s" % ocsp_data['revocation_reason'])
            print("    Produced at: %s" % ocsp_data['produced_at'])
            print("    This update: %s" % ocsp_data['this_update'])
            print("    Next update: %s" % ocsp_data['next_update'])

        return ocsp_stat

    def _load_issuer_cert(self):
        ca_issuer = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ca_issuer = aia.access_location.value
        if not ca_issuer:
            raise ValueError("Cannot do get issuer certificate! Cert has no URL in AIA.")

        issuer_cert_bytes = OcspChecker.load_issuer_cert_from_url(ca_issuer)
        issuer_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, issuer_cert_bytes)

        return issuer_cert