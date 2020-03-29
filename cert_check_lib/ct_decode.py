# This code from:
# https://github.com/google/certificate-transparency/blob/2588562fd306a447958471b6f06c1069619c1641/python/ct/crypto/verify.py#L24

import io
import struct
from enum import Enum

from .exceptions import SCTDecodeException


# Code from:
# https://github.com/google/certificate-transparency/blob/5fce65cb60cfe7808afc98de23c7dd5ddbfa1509/proto/ct.proto
class HashAlgorithm(Enum):
    NONE = 0
    MD5 = 1
    SHA1 = 2
    SHA224 = 3
    SHA256 = 4
    SHA384 = 5
    SHA512 = 6


class SignatureAlgorithm(Enum):
    ANONYMOUS = 0
    RSA = 1
    DSA = 2
    ECDSA = 3


SUPPORTED_SIGNATURE_ALGORITHMS = (
    SignatureAlgorithm.ECDSA,
    SignatureAlgorithm.RSA
)


def decode_signature(signature):
    """Decode the TLS-encoded serialized signature.
    Args:
        signature: TLS-encoded signature.
    Returns:
        a tuple of (hash algorithm, signature algorithm, signature data)
    Raises:
        ct.crypto.error.EncodingError: invalid TLS encoding.
    """

    sig_stream = io.BytesIO(signature)

    sig_prefix = sig_stream.read(2)
    if len(sig_prefix) != 2:
        raise SCTDecodeException("Invalid algorithm prefix %s" %
                                 sig_prefix.hex())
    hash_algo, sig_algo = struct.unpack(">BB", sig_prefix)
    print(sig_prefix.hex())
    if hash_algo != HashAlgorithm.SHA256:
        raise SCTDecodeException("Invalid hash algorithm %d" % hash_algo)
    if sig_algo not in SUPPORTED_SIGNATURE_ALGORITHMS:
        raise SCTDecodeException("Invalid signature algorithm %d" % sig_algo)

    length_prefix = sig_stream.read(2)
    if len(length_prefix) != 2:
        raise SCTDecodeException("Invalid signature length prefix %s" %
                                 length_prefix.hex())
    sig_length, = struct.unpack(">H", length_prefix)
    remaining = sig_stream.read()
    if len(remaining) != sig_length:
        raise SCTDecodeException("Invalid signature length %d for "
                                 "signature %s with length %d" %
                                 (sig_length, remaining.hex(),
                                  len(remaining)))

    return hash_algo, sig_algo, remaining
