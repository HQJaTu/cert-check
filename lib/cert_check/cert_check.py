from OpenSSL import crypto  # pip3 install pyOpenSSL
from py509.extensions import SubjectAltName, AuthorityInformationAccess, SubjectKeyIdentifier, AuthorityKeyIdentifier
import datetime


class CertChecker:
    cert = None

    def __init__(self):
        self.cert = None

    def has_cert(self):
        return self.cert is not None

    def load_pem_from_file(self, certfile):
        st_cert = open(certfile, 'rt').read()

        c = crypto
        self.cert = c.load_certificate(c.FILETYPE_PEM, st_cert)

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

        extension_count = self.cert.get_extension_count()
        for ext_idx in range(extension_count):
            if not ext_idx in [2, 7]:
                continue
            ext = self.cert.get_extension(ext_idx)
            ext_name = ext.get_short_name().decode('ascii')
            print("%d: %s" % (ext_idx, ext_name))
            if ext_name == 'authorityInfoAccess':
                aia = AuthorityInformationAccess(ext.get_data())
                ocsp_uri = aia.ocsp.decode('ascii')
                ca_issuer = aia.ca_issuer.decode('ascii')
                print("    Issuer: %s" % ca_issuer)
                print("    OCSP: %s" % ocsp_uri)
            elif ext_name == 'subjectAltName':
                altName = SubjectAltName(ext.get_data())
                if altName.dns:
                    print("    DNS: %s" % ', '.join(altName.dns))
                if altName.ips:
                    print(altName.ips)
                if altName.uris:
                    print(altName.uris)
