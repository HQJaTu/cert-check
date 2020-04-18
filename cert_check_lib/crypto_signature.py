# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives import (
    serialization,
    hashes,
    asymmetric
)
from .exceptions import *


class CryptoSignature:

    @staticmethod
    def verify_signature(public_key_type, public_key, signature, payload, hash_algorithm):
        signature_verifies_ok = None

        if public_key_type == '_RSAPublicKey':
            try:
                public_key.verify(
                    signature,
                    payload,
                    asymmetric.padding.PKCS1v15(),
                    hash_algorithm,
                )
                signature_verifies_ok = True
            except crypto_exceptions.InvalidSignature:
                signature_verifies_ok = False
        elif public_key_type == '_DSAPublicKey':
            pass
        elif public_key_type == '_EllipticCurvePublicKey':
            ecdsa_algorithm = asymmetric.ec.ECDSA(hash_algorithm)
            try:
                public_key.verify(
                    signature,
                    payload,
                    ecdsa_algorithm
                )
                signature_verifies_ok = True
            except crypto_exceptions.InvalidSignature:
                signature_verifies_ok = False
        elif public_key_type == '_DHPublicKey':
            pass
        elif public_key_type == '_Ed25519PublicKey':
            pass
        elif public_key_type == '_X448PublicKey':
            pass
        elif public_key_type == '_X25519PublicKey':
            pass
        elif public_key_type == '_Ed448PublicKey':
            pass
        else:
            raise UnsupportedPublicKeyAlgorithmException("Unsupported key type: %s" % public_key_type)

        return signature_verifies_ok
