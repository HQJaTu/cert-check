from OpenSSL import crypto  # pip3 install pyOpenSSL
from py509.extensions import SubjectAltName, AuthorityInformationAccess, SubjectKeyIdentifier, AuthorityKeyIdentifier
import datetime


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

        c = crypto
        self.cert = c.load_certificate(c.FILETYPE_PEM, st_cert)
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
            ocsp_uri = self.aia_ext.ocsp.decode('ascii')
            ca_issuer = self.aia_ext.ca_issuer.decode('ascii')
            print("    Issuer: %s" % ca_issuer)
            print("    OCSP: %s" % ocsp_uri)
