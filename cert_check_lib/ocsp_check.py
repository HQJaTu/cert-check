from cryptography.x509 import ocsp
from cryptography.hazmat.backends.openssl.backend import backend as x509_openssl_backend
from cryptography.hazmat.primitives import serialization
import requests


class OcspChecker:
    ocsp_request = None
    last_ocsp_response = None

    def __init__(self, subject_cert, issuer_cert):
        # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(subject_cert, issuer_cert, ocsp.hashes.SHA256())
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
        if False:
            # Debug failing responses
            print(r.content)
            with open('/tmp/ocsp-resp.bin', 'wb') as outfile:
                outfile.write(r.content)
        if False:
            ocsp_response_der = open('/tmp/ocsp-army.deps.mil-resp.der', 'rb').read()
            ocsp_resp = x509_openssl_backend.load_der_ocsp_response(ocsp_response_der)
        ocsp_resp = x509_openssl_backend.load_der_ocsp_response(r.content)
        #print(ocsp_resp.response_status)
        if ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
            raise ValueError("OCSP response status: UNAUTHORIZED")
        if not ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError("OCSP response status not successful")

        self.last_ocsp_response = ocsp_resp.public_bytes(serialization.Encoding.DER)
        ocsp_status = True
        ocsp_data = {
            'hash_algorithm': ocsp_resp.hash_algorithm.__class__.__name__,
            'signature_hash_algorithm': ocsp_resp.signature_hash_algorithm.__class__.__name__,
            'signature': ocsp_resp.signature,
            'responder_key_hash': ocsp_resp.responder_key_hash,
            'issuer_key_hash': ocsp_resp.issuer_key_hash,
            'issuer_name_hash': ocsp_resp.issuer_name_hash,
            'serial_number': ocsp_resp.serial_number,
            'certificates': ocsp_resp.certificates,
            'responder_name': ocsp_resp.responder_name,
            'certificate_status': ocsp_resp.certificate_status,
            'revocation_time': ocsp_resp.revocation_time,
            'revocation_reason': ocsp_resp.revocation_reason,
            'produced_at': ocsp_resp.produced_at,
            'this_update': ocsp_resp.this_update,
            'next_update': ocsp_resp.next_update
        }

        if ocsp_resp.certificate_status != ocsp.OCSPCertStatus.GOOD:
            ocsp_status = False

        return ocsp_status, ocsp_data
