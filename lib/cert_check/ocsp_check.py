from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder, OCSPResponseBuilder
import requests
from base64 import b64encode


class OcspChecker:

    ocsp_request = None

    def __init__(self, cert_bytes, issuer_cert_bytes):
        subject_cert = asymmetric.load_certificate(cert_bytes)
        issuer_cert = asymmetric.load_certificate(issuer_cert_bytes)

        builder = OCSPRequestBuilder(subject_cert, issuer_cert)
        self.ocsp_request = builder.build()

    def verify(self, url):
        ocsp_request = self.ocsp_request.dump()

        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/ocsp-request'
        }
        r = requests.post(url, headers=headers, data = ocsp_request)
        r.raise_for_status()

        print(url)
        print(r.content)

    @staticmethod
    def load_issuer_cert_from_url(url):
        r = requests.get(url)
        r.raise_for_status()

        return r.content