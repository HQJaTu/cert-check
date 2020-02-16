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
        #print(ocsp_resp)
        print("OCSP response:")
        print("    Response hash algorithm: %s" % ocsp_resp.hash_algorithm.__class__.__name__)
        print("    Response signature hash algorithm: %s" % ocsp_resp.signature_hash_algorithm.__class__.__name__)
        #print(ocsp_resp.signature)
        #print("    Certificates: %s" % ocsp_resp.certificates)
        #print("    Responder: %s" % ocsp_resp.responder_name)
        print("    Certificate status: %s" % ocsp_resp.certificate_status)
        print("    Revocation time: %s" % ocsp_resp.revocation_time)
        print("    Revocation reason: %s" % ocsp_resp.revocation_reason)
        print("    Produced at: %s" % ocsp_resp.produced_at)
        print("    This update: %s" % ocsp_resp.this_update)
        print("    Next update: %s" % ocsp_resp.next_update)
        #print("    Serial #: %s" % ocsp_resp.serial_number)

    @staticmethod
    def load_issuer_cert_from_url(url):
        r = requests.get(url)
        r.raise_for_status()

        return r.content
