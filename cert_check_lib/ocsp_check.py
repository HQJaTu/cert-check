from cryptography.x509 import ocsp
from cryptography.hazmat.backends.openssl.backend import backend as x509_openssl_backend
from cryptography.hazmat.primitives import serialization
from .requests import RequestsSession
from requests import exceptions as requests_exceptions



class OcspChecker:
    ocsp_request = None
    last_ocsp_response = None
    subject_cert = None
    issuer_cert = None
    request_hashes = None

    def __init__(self, subject_cert, issuer_cert, hashes=None):
        # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
        if hashes is None:
            hashes = ['sha256', 'sha1']
        self.subject_cert = subject_cert
        self.issuer_cert = issuer_cert

        self.request_hashes = []
        for hash in hashes:
            if hash == 'sha256':
                self.request_hashes.append(ocsp.hashes.SHA256)
            elif hash == 'sha1':
                self.request_hashes.append(ocsp.hashes.SHA1)
            else:
                raise ValueError("Don't know hash '%s'! Cannot go OCSP." % hash)

    def verify(self, url, verbose=False):
        ocsp_status = None
        ocsp_data = {}
        for request_hash_class in self.request_hashes:
            request_hash = request_hash_class()
            ocsp_status, ocsp_should_retry, ocsp_data = self._do_verify(url,
                                                                        self.subject_cert, self.issuer_cert,
                                                                        request_hash)
            if ocsp_status:
                # Success
                break

            # Ah. Failure.
            if not ocsp_should_retry:
                break

            if verbose:
                print("Warning! OCSP-request with %s failed. Retrying using another hash." % request_hash_class.__name__.lower())

        return ocsp_status, ocsp_data

    def _do_verify(self, url, cert, issuer_cert, hash, verbose=False):
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hash)
        self.ocsp_request = builder.build()
        ocsp_request = self.ocsp_request.public_bytes(serialization.Encoding.DER)

        headers = {
            'Accept': '*/*',
            'Content-Type': 'application/ocsp-request'
        }

        ocsp_status = True
        ocsp_should_retry = False
        self.last_ocsp_response = None

        # Go get the issuer certificate from indicated URI
        session = RequestsSession.get_requests_retry_session(retries=2)
        response = None
        try:
            response = session.post(url, headers=headers, data=ocsp_request)
            response.raise_for_status()
        except requests_exceptions.ConnectTimeout:
            ocsp_status = False

        # print("HTTP/%d, %s bytes" % (response.status_code, response.headers['content-length']))

        ocsp_resp = None
        if ocsp_status:
            # Docs, see: https://cryptography.io/en/latest/x509/ocsp/
            ocsp_resp = x509_openssl_backend.load_der_ocsp_response(response.content)
            if ocsp_resp.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED or \
                    not ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                ocsp_status = False
                ocsp_should_retry = True
                if verbose:
                    print("OCSP response status '%s' not successful" % ocsp_resp.response_status)

            # Save last response for possible further analysis.
            self.last_ocsp_response = ocsp_resp.public_bytes(serialization.Encoding.DER)

        if ocsp_status:
            ocsp_data = {
                'response_status_ok': True,
                'request_hash_algorithm': hash.name.upper(),
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
            ocsp_data = {
                'response_status_ok': False,
                'request_hash_algorithm': hash.name.upper(),
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

        return ocsp_status, ocsp_should_retry, ocsp_data
