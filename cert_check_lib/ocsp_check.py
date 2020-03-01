from cryptography.x509 import ocsp
from cryptography.hazmat.backends.openssl.backend import backend as x509_openssl_backend
from cryptography.hazmat.primitives import serialization
import requests


class OcspChecker:
    ocsp_request = None
    last_ocsp_response = None
    subject_cert = None
    issuer_cert = None
    request_hash = None

    def __init__(self, subject_cert, issuer_cert, hash='sha256'):
        # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
        self.subject_cert = subject_cert
        self.issuer_cert = issuer_cert
        if hash == 'sha256':
            self.request_hash = ocsp.hashes.SHA256()
        elif hash == 'sha1':
            self.request_hash = ocsp.hashes.SHA1()
        else:
            raise ValueError("Don't know hash '%s'! Cannot go OCSP." % hash)
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(self.subject_cert, self.issuer_cert, self.request_hash)
        self.ocsp_request = builder.build()

    def verify(self, url, verbose=False):
        ocsp_request = self.ocsp_request.public_bytes(serialization.Encoding.DER)

        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/ocsp-request'
        }
        r = requests.post(url, headers=headers, data=ocsp_request)
        r.raise_for_status()
        # print("HTTP/%d, %s bytes" % (r.status_code, r.headers['content-length']))

        # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
        ocsp_status = True
        ocsp_resp = x509_openssl_backend.load_der_ocsp_response(r.content)
        if ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
            if self.request_hash.name == 'sha256':
                if verbose:
                    print("Warning! OCSP-request with SHA-256 failed. Downgrading into SHA-1 and retrying.")
                self.request_hash = ocsp.hashes.SHA1()
                builder = ocsp.OCSPRequestBuilder()
                builder = builder.add_certificate(self.subject_cert, self.issuer_cert, self.request_hash)
                self.ocsp_request = builder.build()

                return self.verify(url)
            else:
                ocsp_status = False
            # raise ValueError("OCSP response status: UNAUTHORIZED")
        elif not ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError("OCSP response status not successful")

        # Save last response for possible further analysis.
        self.last_ocsp_response = ocsp_resp.public_bytes(serialization.Encoding.DER)

        if ocsp_status:
            ocsp_data = {
                'response_status_ok': True,
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
        else:
            self.last_ocsp_response = None
            ocsp_data = {
                'response_status_ok': False,
                'hash_algorithm': None,
                'signature_hash_algorithm': None,
                'signature': None,
                'responder_key_hash': None,
                'issuer_key_hash': None,
                'issuer_name_hash': None,
                'serial_number': None,
                'certificates': None,
                'responder_name': None,
                'certificate_status': ocsp.OCSPCertStatus.UNKNOWN,
                'revocation_time': None,
                'revocation_reason': None,
                'produced_at': None,
                'this_update': None,
                'next_update': None
            }

        return ocsp_status, ocsp_data
