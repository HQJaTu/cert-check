from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization
import requests


class OcspChecker:
    ocsp_request = None

    def __init__(self, subject_cert, issuer_cert):
        # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(subject_cert.to_cryptography(),
                                          issuer_cert.to_cryptography(),
                                          ocsp.hashes.SHA256())
        self.ocsp_request = builder.build()

    def verify(self, url):
        ocsp_request = self.ocsp_request.public_bytes(serialization.Encoding.DER)

        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/ocsp-request'
        }
        r = requests.post(url, headers=headers, data=ocsp_request)
        r.raise_for_status()

        # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
        ocsp_resp = ocsp.load_der_ocsp_response(r.content)
        #print(ocsp_resp.response_status)
        if ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
            raise ValueError("OCSP response status: UNAUTHORIZED")
        if not ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError("OCSP response status not successful")


        ocsp_status = True
        ocsp_data = {
            'hash_algorithm': ocsp_resp.hash_algorithm.__class__.__name__,
            'signature_hash_algorithm': ocsp_resp.signature_hash_algorithm.__class__.__name__,
            'certificates': ocsp_resp.certificates,
            'responder_name': ocsp_resp.responder_name,
            'certificate_status': ocsp_resp.certificate_status,
            'revocation_time': ocsp_resp.revocation_time,
            'revocation_reason': ocsp_resp.revocation_reason,
            'produced_at': ocsp_resp.produced_at,
            'this_update': ocsp_resp.this_update,
            'next_update': ocsp_resp.next_update,
            'serial_number': ocsp_resp.serial_number,
        }

        if ocsp_resp.certificate_status != ocsp.OCSPCertStatus.GOOD:
            ocsp_status = False

        return ocsp_status, ocsp_data

    @staticmethod
    def load_issuer_cert_from_url(url):
        r = requests.get(url)
        r.raise_for_status()

        return r.content
