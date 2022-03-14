# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# SPDX-License-Identifier: GPL-2.0
# Code in CTLog-class is heavily inspired by https://github.com/theno/ctutlz written by Theodor Nolte.
# This is an object-oriented adaptation of ctutlz.

import sys
import struct
from enum import Enum
import base64
import hashlib
from datetime import datetime
from functools import reduce
from cryptography.hazmat.primitives import (
    serialization,
    hashes,
    asymmetric
)
from cryptography.x509 import (
    oid as x509_oid
)
from pyasn1.codec.der import (
    decoder as asn1_decoder,
    encoder as asn1_encoder
)
from pyasn1.type import univ, tag
from pyasn1_modules import rfc5280
from .crypto_signature import CryptoSignature
from .exceptions import CTLogException


class CTLog:
    # https://groups.google.com/forum/#!topic/certificate-transparency/zZwGExvQeiE
    # PENDING:
    #       The Log has requested inclusion in the Log list distributor’s trusted Log list,
    #       but has not yet been accepted.
    #       A PENDING Log does not count as ‘currently qualified’, and does not count as ‘once qualified’.
    # QUALIFIED:
    #       The Log has been accepted by the Log list distributor, and added to the CT checking code
    #       used by the Log list distributor.
    #       A QUALIFIED Log counts as ‘currently qualified’.
    # USABLE:
    #       SCTs from the Log can be relied upon from the perspective of the Log list distributor.
    #       A USABLE Log counts as ‘currently qualified’.
    # FROZEN (READONLY in JSON-schema):
    #       The Log is trusted by the Log list distributor, but is read-only, i.e. has stopped accepting
    #       certificate submissions.
    #       A FROZEN Log counts as ‘currently qualified’.
    # RETIRED:
    #       The Log was trusted by the Log list distributor up until a specific retirement timestamp.
    #       A RETIRED Log counts as ‘once qualified’ if the SCT in question was issued before the retirement timestamp.
    #       A RETIRED Log does not count as ‘currently qualified’.
    # REJECTED:
    #       The Log is not and will never be trusted by the Log list distributor.
    #       A REJECTED Log does not count as ‘currently qualified’, and does not count as ‘once qualified’.
    class KnownCTStates(Enum):
        PENDING = 'pending'
        QUALIFIED = 'qualified'
        USABLE = 'usable'
        READONLY = 'readonly'  # frozen
        RETIRED = 'retired'
        REJECTED = 'rejected'

    key = None  # base-64 encoded, type: str
    log_id = None
    mmd = None  # v1: maximum_merge_delay
    url = None

    # optional ones:
    description = None
    dns = None
    temporal_interval_begin = None
    temporal_interval_end = None
    log_type = None
    state = None  # JSON-schema has: pending, qualified, usable, readonly, retired, rejected
    state_timestamp = None

    # Custom
    operated_by_name = None
    operated_by_emails = None

    def __init__(self, data):
        self.key = data['key']
        self.log_id = data['log_id']
        self.mmd = data['mmd']
        self.url = data['url']
        self.operated_by_name = data['operated_by']['name']
        self.operated_by_emails = data['operated_by']['email']

        # optional ones:
        self.description = data['description'] if 'description' in data else None
        self.dns = data['dns'] if 'dns' in data else None
        if 'temporal_interval' in data:
            self.temporal_interval = datetime.strptime(data['temporal_interval']['start_inclusive'],
                                                       "%Y-%m-%dT%H:%M:%SZ")
            self.temporal_interval_end = datetime.strptime(data['temporal_interval']['end_exclusive'],
                                                           "%Y-%m-%dT%H:%M:%SZ")
        else:
            self.temporal_interval_begin = None
            self.temporal_interval_end = None

        self.log_type = data['log_type'] if 'log_type' in data else None

        if 'state' in data:
            state_str = next(iter(data['state']))
            if state_str in [state.value for state in CTLog.KnownCTStates]:
                state_timestamp_str = data['state'][state_str]['timestamp']
                self.state = next(iter([state for state in CTLog.KnownCTStates if state.value == state_str]))
                self.state_timestamp = datetime.strptime(state_timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
            else:
                self.state = None
                self.state_timestamp = None
        else:
            self.state = None
            self.state_timestamp = None

    def key_der(self):
        key = base64.b64decode(self.key)

        return key

    def log_id_der(self):
        log_id = base64.b64decode(self.log_id)
        digest = hashlib.sha256(log_id).digest()

        return digest

    def pubkey(self):
        # String chunk from: https://stackoverflow.com/a/18854817/1548275
        def chunk_string(string, length):
            for i in range(0, len(string), length):
                yield string[0 + i:length + i]

        key = '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' % '\n'.join(chunk_string(self.key, 64))

        return key

    def scts_accepted_by_chrome(self):
        if self.state is None:
            return None

        if next(iter(self.state)) in [CTLog.KnownCTStates.USABLE,
                                      CTLog.KnownCTStates.QUALIFIED,
                                      CTLog.KnownCTStates.READONLY]:
            return True

        return False

    def verify_precert_signature(self, ee_cert, issuer_cert, sct, signature, digest_algo):
        '''Verify if `signature` over `signature_input` was created using
        `digest_algo` by the private key of the `pubkey_pem`.

        A signature is the private key encrypted hash over the signature input data.

        Args:
            signature_input(bytes): signed data
            signature(bytes):
            pubkey_pem(str): PEM formatted pubkey
            digest_algo(str): name of the used digest hash algorithm
                              (default: 'sha256')

        Return:
            True, if signature could be verified
            False, else
        '''

        signature_input = self._create_signature_input_precert(ee_cert, sct, issuer_cert)

        cryptography_key = serialization.load_pem_public_key(self.key, backend)
        pkey = pkey_from_cryptography_key(cryptography_key)

        auxiliary_cert = X509()
        auxiliary_cert.set_pubkey(pkey)

        certificate_verifies_ok = CryptoSignature.verify_signature(public_key_type,
                                                                   public_key,
                                                                   self.cert.signature,
                                                                   self.cert.tbs_certificate_bytes,
                                                                   self.cert.signature_hash_algorithm)

        return certificate_verifies_ok

    @staticmethod
    def _create_signature_input_precert(ee_cert, sct, issuer_cert):
        # cf. https://tools.ietf.org/html/rfc6962#section-3.2

        signature_type = 0  # 0 means certificate_timestamp
        entry_type = 1  # 0: ASN.1Cert, 1: PreCert

        tbscert = CTLog._tbscert_bytes_without_ct(ee_cert)
        tbscert_length_3_bytes = len(tbscert).to_bytes(3, byteorder='big')

        issuer_cert_public_key = issuer_cert.public_key()
        issuer_cert_key = issuer_cert_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                              )
        if sys.version_info >= (3, 8):
            issuer_cert_key_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._x509)
        else:
            issuer_cert_key_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._backend)
        issuer_cert_key_hash.update(issuer_cert_key)
        issuer_cert_key_hash_bytes = issuer_cert_key_hash.finalize()

        # Define helper:
        def reduce_func(accum_value, current):
            fmt = accum_value[0] + current[0]
            values = accum_value[1] + (current[1],)
            return fmt, values

        # Define initializer:
        initializer = ('!', ())

        # Go reduce!
        # fmt = '!BBQh...', values = [<sct.version>, <signature_type>, ...]
        fmt, values = reduce(reduce_func, [
            ('B', sct.version.value),
            ('B', signature_type),
            ('Q', 0), # XXX argh! sct._backend._lib.SCT_get_timestamp(sct._sct)),
            ('h', entry_type),

            # signed_entry

            # issuer_key_hash[32]
            ('32s', issuer_cert_key_hash_bytes),

            # tbs_certificate (rfc6962, page 12)
            #  * DER encoded TBSCertificate of the ee_cert
            #    * without SCT extension
            ('B', int(tbscert_length_3_bytes[0])),
            ('B', int(tbscert_length_3_bytes[1])),
            ('B', int(tbscert_length_3_bytes[2])),
            ('%ds' % len(tbscert), tbscert),

            ('h', 0)  # XXX argh! sct.extensions_len),
        ], initializer)

        return struct.pack(fmt, *values)

    @staticmethod
    def _tbscert_bytes_without_ct(cert_in):
        # Note: ee_cert.tbs_certificate_bytes doesn't decode! Need to do entire cert with signature.
        substrate = cert_in.public_bytes(serialization.Encoding.DER)
        cert, rest = asn1_decoder.decode(substrate, asn1Spec=rfc5280.Certificate())

        sctlist_oid = x509_oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS._dotted_string
        poison_oid = x509_oid.ExtensionOID.PRECERT_POISON._dotted_string
        exts_to_remove = [sctlist_oid, poison_oid]

        cert_out = rfc5280.Certificate()
        tbscertificate_seq = rfc5280.TBSCertificate()
        cert_out.setComponentByPosition(0, tbscertificate_seq)

        # Iterate the input X.509 and produce an almost exact replica of it
        for part_idx in range(0, len(cert['tbsCertificate'])):
            part = cert['tbsCertificate'][part_idx]

            # Check if this sequence item is extensions.
            # Need to produce a list of extensions without Certificate Transparency in it.
            if isinstance(part, rfc5280.Extensions):
                # NOTE! Need the tags to be compatible.
                # See: https://stackoverflow.com/questions/31553535/simpler-way-to-add-tagged-items-in-pyasn1
                extension_part = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext,
                                                                                  tag.tagFormatSimple, 3))
                extension_idx = 0
                for ext_idx, ext in enumerate(part):
                    if str(ext['extnID']) in exts_to_remove:
                        # print("XXX naah: '%s'=='%s'" % (ext['extnID'], sctlist_oid))
                        continue

                    extension_part.setComponentByPosition(extension_idx, ext)
                    extension_idx += 1

                # Add the newly created list of extensions
                tbscertificate_seq.setComponentByPosition(part_idx, extension_part)
            else:
                # All other parts go in as-is
                tbscertificate_seq.setComponentByPosition(part_idx, part)

        # Back to DER-bytes:
        cert_out_bytes = asn1_encoder.encode(tbscertificate_seq)

        return cert_out_bytes
