from OpenSSL import crypto, SSL  # pip3 install pyOpenSSL
from py509.extensions import SubjectAltName, AuthorityInformationAccess, SubjectKeyIdentifier, AuthorityKeyIdentifier
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

    def load_pem_from_host(self, hostname, port):
        self.cert = None

        # Initialize context
        #SSL._create_default_https_context = SSL._create_unverified_context
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
            print("TLS-version used in connection: %s" % tls_version)
            print("OCSP assertion length: %d" % len(ocsp_assertion))
            self._process_extensions()

    def _process_extensions(self):
        # Note: Using OpenSSL we can extract the bytes for each extension. What we cannot do is decode the ASN-data.
        # Note 2: py509 has capability of decoding ASN-information for known extensions.
        extension_count = self.cert.get_extension_count()
        for ext_idx in range(extension_count):
            ext = self.cert.get_extension(ext_idx)
            ext_name = ext.get_short_name().decode('ascii')
            # print("XXX %d: %s" % (ext_idx, ext_name))
            if ext_name == 'authorityInfoAccess':
                self.aia_ext = AuthorityInformationAccess(ext.get_data())
            elif ext_name == 'subjectAltName':
                self.alt_name_ext = SubjectAltName(ext.get_data())

    def verify(self):
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

        print("Cert %s expired" % ('has' if is_expired else 'not'))
        print("    %s - %s" % (valid_from, valid_to))
        print("Issuer: %s" % issuer_info)
        print("Subject: %s" % subject_info)
        print("Serial #: %s" % serial_nro)
        print("Signature algo: %s" % sig_algo)

        if self.alt_name_ext:
            print("Alternate names")
            if self.alt_name_ext.dns:
                print("    DNS-names: %s" % ', '.join(self.alt_name_ext.dns))
            if self.alt_name_ext.ips:
                print("    IP-addresses: %s" % ', '.join(self.alt_name_ext.ips))
            if self.alt_name_ext.uris:
                print("    URIs: %s" % ', '.join(self.alt_name_ext.uris))

        if self.aia_ext:
            print("Authority Information Access (AIA)")
            ocsp_uri = self.aia_ext.ocsp
            if ocsp_uri:
                ocsp_uri = ocsp_uri.decode('ascii')
            else:
                ocsp_uri = None
            ca_issuer = self.aia_ext.ca_issuer
            if ca_issuer:
                ca_issuer = ca_issuer.decode('ascii')
            else:
                ca_issuer = None
            print("    Issuer: %s" % ca_issuer)
            print("    OCSP: %s" % ocsp_uri)

        self._verify_ocsp()

    def _verify_ocsp(self):
        cert_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, self.cert)
        issuer_cert_bytes = self._get_issuer_cert()

        ocsp_uri = self.aia_ext.ocsp
        if ocsp_uri:
            ocsp_uri = ocsp_uri.decode('ascii')
        else:
            raise ValueError("Cannot do get OCSP URI! Cert has no URL in OCSP.")

        ocsp = OcspChecker(cert_bytes, issuer_cert_bytes)
        ocsp.verify(ocsp_uri)

    def _get_issuer_cert(self):
        ca_issuer = self.aia_ext.ca_issuer
        if ca_issuer:
            ca_issuer = ca_issuer.decode('ascii')
        else:
            raise ValueError("Cannot do get issuer certificate! Cert has no URL in AIA.")

        issuer_cert_bytes = OcspChecker.load_issuer_cert_from_url(ca_issuer)
        issuer_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, issuer_cert_bytes)
        issuer_cert_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, issuer_cert)

        return issuer_cert_bytes