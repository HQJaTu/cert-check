# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

# X.509 certificate checker library and tool
# Copyright (C) 2020 Jari Turkia
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2, as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details (http://www.gnu.org/licenses/gpl.txt).

__author__ = 'Jari Turkia'
__email__ = 'jatu@hqcodeshop.fi'
__url__ = 'https://blog.hqcodeshop.fi/'
__git__ = 'https://github.com/HQJaTu/cert-check'
__version__ = '0.3'
__license__ = 'GPLv2'
__banner__ = 'cert_check_lib v%s (%s)' % (__version__, __git__)

from OpenSSL import crypto  # pip3 install pyOpenSSL
from OpenSSL._util import (
    ffi as _ffi,
    lib as _lib,
)
from cryptography.x509 import (
    base as x509,
    extensions as x509_extensions,
    oid as x509_oid,
    DNSName, IPAddress, UniformResourceIdentifier
)
from cryptography.hazmat._oid import ObjectIdentifier
from cryptography.hazmat.primitives import (
    serialization,
    hashes,
    asymmetric
)
from cryptography.hazmat.backends import (
    default_backend
)
from cryptography.hazmat.backends.openssl.backend import (
    backend as x509_openssl_backend
)
import cryptography.exceptions
import socket
import ssl
import asyncio
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timedelta
from pyasn1.codec.ber import decoder as asn1_decoder
from .ocsp_check import OcspChecker
from .requests import RequestsSession
from .exceptions import *


class CertChecker:
    # See:https://cabforum.org/object-registry/
    KNOWN_VERIFICATION_POLICIES = {
        'EV': ObjectIdentifier('2.23.140.1.1'),
        'DV': ObjectIdentifier('2.23.140.1.2.1'),
        'OV': ObjectIdentifier('2.23.140.1.2.2'),
        'EV code sign': ObjectIdentifier('2.23.140.1.3'),
        'Test': ObjectIdentifier('2.23.140.2.1'),
        'EV Onion': ObjectIdentifier('2.23.140.1.31')
    }

    DEFAULT_TIMEOUT: int = 5
    DEFAULT_OCSP_RESPONSE_EXPIRY_DAYS: int = 7
    connection_timeout = DEFAULT_TIMEOUT
    ocsp_response_expiry_days = DEFAULT_OCSP_RESPONSE_EXPIRY_DAYS

    loop = None

    cert = None
    cert_from_disc = False
    cert_from_host = False
    cert_from_host_conn_proto = None
    cert_from_host_conn_cipher = None
    cert_from_host_conn_cipher_bits = None
    cert_from_host_matches_cert = None
    cert_from_host_ja3s = None

    # Extensions of cert
    aia_ext = None
    alt_name_ext = None
    key_id_ext = None
    cert_policies_ext = None
    tls_feature_ext = None
    sct_ext = None
    sct_poison_ext = None

    # Request results
    last_ocsp_response = None
    last_certificate_pem = None
    last_issuer_certificate_pem = None

    # Experimental features:
    _can_do_ocsp_stapling = False
    _can_collect_tls_extensions = False
    _can_get_sct_details = False

    def __init__(self, loop=None):
        self.cert = None
        self.loop = loop

        self._can_do_ocsp_stapling = False
        self._can_collect_tls_extensions = False
        self._can_get_sct_details = False

    def has_cert(self):
        return self.cert is not None

    def load_pem_from_file(self, certfile):
        st_cert = open(certfile, 'rb').read()

        self.cert = x509_openssl_backend.load_pem_x509_certificate(st_cert)
        self._process_extensions()
        self.last_certificate_pem = None

        self.cert_from_disc = True
        self.cert_from_host = False
        self.cert_from_host_conn_proto = None
        self.cert_from_host_conn_cipher = None
        self.cert_from_host_conn_cipher_bits = None
        self.cert_from_host_matches_cert = None
        self.cert_from_host_ja3s = None

    async def load_pem_from_host_async(self, hostname, port, verbose=False):
        self.cert = None

        host_ip_addr, cipher_name, tls_version, cipher_secret_size_bits, server_cert_bytes, ja3s = \
            await self._load_pem_from_host_asynchronous(hostname, port, verbose)

        self.cert = x509.load_der_x509_certificate(server_cert_bytes, x509_openssl_backend)
        self._process_extensions(verbose=verbose)
        self.last_certificate_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        certificate_matches_hostname = self.verify_hostname(hostname)

        self.cert_from_disc = False
        self.cert_from_host = (host_ip_addr, hostname)
        self.cert_from_host_conn_proto = tls_version
        self.cert_from_host_conn_cipher = cipher_name
        self.cert_from_host_conn_cipher_bits = cipher_secret_size_bits
        self.cert_from_host_matches_cert = certificate_matches_hostname
        self.cert_from_host_ja3s = ja3s

        return certificate_matches_hostname

    async def _load_pem_from_host_asynchronous(self, hostname, port, verbose=False):
        """
        Load X.509 certificate from a host

        To-Do:
        - cipher number used to connect: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
        - JA3S: full value, comma separated list of TLS-version, ciphers and extensions
        - Request OCSP-staple response: on/off
        - Stapled OCSP: if any provided
        :param hostname: host or IP-address to load the certificate from
        :param port: TCP-port to connect
        :param verbose:
        :return:
        """
        server_cert_bytes = None
        host_ip_addr = None
        cipher_name = None
        tls_version_detected = None
        cipher_secret_size_bits = None

        def ocsp_staple_cb(socket, ocsp_response, context):
            print("ocsp_cb()!")
            # print("  - Socket: %s" % dir(socket))
            print("  - Socket %d shared ciphers" % len(socket.shared_ciphers()))
            if ocsp_response:
                print("  - OCSP: %s" % ocsp_response.hex())
            else:
                print("  - OCSP: %s" % ocsp_response)
            print("ocsp_cb() done.")
            return True

        tls_versions = {
            'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            'TLSv1.1': ssl.TLSVersion.TLSv1_1,
            'TLSv1.0': ssl.TLSVersion.TLSv1
        }
        if verbose:
            print("Info: Going for %s in %d" % (hostname, port))
        ctx = ssl._create_unverified_context()
        ctx.set_default_verify_paths()
        if self._can_do_ocsp_stapling:
            ctx.ocsp_staple_callback = ocsp_staple_cb
        if self._can_collect_tls_extensions:
            ctx.collect_tls_extensions = True

        tls_version_name: str = None
        ja3s: str = None
        for tls_version_name in tls_versions:
            tls_ctx_version = tls_versions[tls_version_name]
            ctx.minimum_version = tls_ctx_version

            retries = 3
            reader = None
            writer = None
            peername = None
            while retries > 0:
                retries -= 1
                try:
                    future = asyncio.open_connection(hostname, port, ssl=ctx, loop=self.loop)
                    try:
                        # Raise TimeoutError on error
                        reader, writer = await asyncio.wait_for(future, timeout=CertChecker.connection_timeout)
                    except asyncio.TimeoutError:
                        raise ConnectionException(
                            "Failed to load certificate from %s:%d. Connection timed out." % (hostname, port))
                except ssl.SSLError:
                    continue
                except (ConnectionResetError, socket.gaierror):
                    raise ConnectionException("Failed to load certificate from %s:%d. OS error." % (
                        hostname, port))
                except OSError:
                    raise ConnectionException(
                        "Failed to load certificate from %s:%d. OS error." % (hostname, port))

                # Note: In an ultra-rare case, peername wasn't available.
                #       Such an incident doesn't make any sense! Why wouldn't the other end of an open socket be available!
                peername = writer.get_extra_info('peername')
                if peername:
                    break

                if retries >= 0:
                    # Try again!
                    if verbose:
                        print("Getting peername failed on an open socket. Retrying. %d" % retries)
                    writer.close()
                    continue

            if not peername:
                raise ConnectionException(
                    "Failed to load certificate from %s:%d. OS error." % (hostname, port))

            host_ip_addr = peername[0]
            ssl_obj = writer.get_extra_info('ssl_object')
            server_cert_bytes = ssl_obj.getpeercert(binary_form=True)
            cipher_name, tls_version_detected, cipher_secret_size_bits = ssl_obj.cipher()
            if self._can_collect_tls_extensions:
                proto_id, cipher_id, tls_extensions = ssl_obj._sslobj.peer_info()
                extension_types = []
                if tls_extensions:
                    for extension in tls_extensions:
                        extension_types.append(str(extension['type']))
                ja3s = "%d,%d,%s" % (proto_id, cipher_id, '-'.join(extension_types))
                print("JA3S: %s" % ja3s)
            writer.close()
            break

        if not server_cert_bytes:
            raise ConnectionException("Failed to load certificate from %s:%d. No TLS-version allowed connection." %
                                      (hostname, port))

        if tls_version_name > tls_version_detected:
            tls_version_detected = tls_version_name

        return host_ip_addr, cipher_name, tls_version_detected, cipher_secret_size_bits, server_cert_bytes, ja3s

    def verify_hostname(self, hostname):
        # OpenSSL code, see: https://github.com/openssl/openssl/blob/5f5edd7d3eb20c39177b9fa6422f1db57634e9e3/crypto/x509/v3_utl.c#L818
        # This is something that needed to be done:
        # hostname_bytes = hostname.encode()
        # data_ptr = _ffi.from_buffer(hostname_bytes)
        # res = _lib.X509_check_host(self.cert._x509,
        #                           data_ptr, len(hostname_bytes),
        #                           0, _ffi.NULL
        #                           )
        # if res:
        #    return True
        # That is not available.

        # First alternate names. If any exist, subject won't be checked.
        # RFC 6125: https://tools.ietf.org/html/rfc6125#section-6.4.4
        # "As noted, a client MUST NOT seek a match for a reference identifier of CN-ID
        #  if the presented identifiers include a DNS-ID, SRV-ID, URI-ID.
        if self.alt_name_ext:
            try:
                hostname_ip = ipaddress.ip_address(hostname)
                hostname_parts = None
            except ValueError:
                hostname_ip = None
                hostname_parts = hostname.lower().split('.')

            for alt_name in self.alt_name_ext.value:
                if isinstance(alt_name, DNSName):
                    if hostname_ip is None and '*' in alt_name.value:
                        # Wildcard matching. Valid only for a DNS-name.
                        if not alt_name.value.startswith('*'):
                            # Invalid wildcard (sort of).
                            # We're not fully RFC-compliant here. We're simply doing what most browsers do.
                            # See: https://en.wikipedia.org/wiki/Wildcard_certificate#Examples
                            continue
                        host_to_validate = hostname_parts[:]  # clone
                        altname = alt_name.value.lower().split('.')
                        while host_to_validate and altname:
                            hostname_part = host_to_validate.pop()
                            altname_part = altname.pop()
                            if altname_part == '*' and not host_to_validate and not altname:
                                # Last element to match was an asterisk. Ignore hostname part.
                                # We have a confident match.
                                return True
                            if not altname_part == hostname_part:
                                # Nope. Part didn't match. Stop investigating this alternate name
                                break
                            # So far, so good.
                            # Iterate more parts and make sure they'll match.
                    else:
                        # Non-wildcard. A very trivial comparison.
                        if alt_name.value.lower() == hostname.lower():
                            return True
                elif isinstance(alt_name, IPAddress) and hostname_ip:
                    if alt_name == hostname_ip:
                        return True

            return False

        # Subject
        # Hostname is compared against subject's common name only
        # CA/Brower forum spec: https://cabforum.org/wp-content/uploads/BRv1.2.5.pdf#page=17
        # "If present, this field MUST contain a single IP address or Fully-Qualified Domain Name
        #  that is one of the values contained in the Certificate’s subjectAltName extension."
        if not self.cert.subject:
            return False

        for subject_compo in self.cert.subject:
            if not subject_compo.oid._name == 'commonName':
                continue
            if subject_compo.value == hostname:
                return True
            break

        return False

    def _process_extensions(self, verbose=False):
        self.aia_ext = None
        self.alt_name_ext = None
        self.key_id_ext = None
        self.cert_policies_ext = None
        self.tls_feature_ext = None
        self.sct_ext = None
        self.sct_poison_ext = None

        extensions = x509_extensions.Extensions(self.cert.extensions)
        try:
            self.aia_ext = extensions.get_extension_for_class(x509_extensions.AuthorityInformationAccess)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have AuthorityInformationAccess extension")

        try:
            self.alt_name_ext = extensions.get_extension_for_class(x509_extensions.SubjectAlternativeName)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have SubjectAlternativeName extension")

        try:
            self.key_id_ext = extensions.get_extension_for_class(x509_extensions.SubjectKeyIdentifier)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have SubjectKeyIdentifier extension")

        try:
            self.cert_policies_ext = extensions.get_extension_for_class(x509_extensions.CertificatePolicies)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have CertificatePolicies extension")

        try:
            self.tls_feature_ext = extensions.get_extension_for_class(x509_extensions.TLSFeature)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have TLSFeature extension")

        try:
            self.sct_ext = extensions.get_extension_for_class(x509_extensions.PrecertificateSignedCertificateTimestamps)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have PrecertificateSignedCertificateTimestamps extension")
        try:
            self.sct_poison_ext = extensions.get_extension_for_class(x509_extensions.PrecertPoison)
        except x509_extensions.ExtensionNotFound:
            if verbose:
                print("Note: This certificate doesn't have PrecertPoison extension")

    async def verify_async(self, ocsp=True, verbose=False):
        if not self.cert:
            raise ConnectionException("Need cert! Cannot do.")

        try:
            issuer = self.cert.issuer
        except ValueError:
            issuer = None
        try:
            subject = self.cert.subject
        except ValueError:
            subject = None
        serial_nro = self.cert.serial_number
        sig_algo = self.cert.signature_hash_algorithm.__class__.__name__.lower()
        valid_from = self.cert.not_valid_before
        valid_to = self.cert.not_valid_after
        now = datetime.utcnow()
        if now < valid_from or now > valid_to:
            is_expired = True
        else:
            is_expired = False

        issuer_info = {}
        subject_info = {}
        if issuer:
            for issuer_compo in issuer:
                issuer_info[issuer_compo.oid._name] = issuer_compo.value
        if subject:
            for subject_compo in subject:
                subject_info[subject_compo.oid._name] = subject_compo.value

        cert_public_key = self.cert.public_key()
        cert_key = cert_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                )
        cert_key_asn1, _remainder = asn1_decoder.decode(cert_key)
        cert_key_bytes = cert_key_asn1[1].asOctets()
        public_key_type = cert_public_key.__class__.__name__

        dns_names = []
        ip_addresses = []
        urls = []
        if self.alt_name_ext:
            for alt_name in self.alt_name_ext.value:
                if isinstance(alt_name, DNSName):
                    dns_names.append(alt_name.value)
                elif isinstance(alt_name, IPAddress):
                    ip_addresses.append(alt_name.value)
                elif isinstance(alt_name, UniformResourceIdentifier):
                    urls.append(alt_name.value)

        ocsp_uri = self.ocsp_uri()
        ca_issuer = self.issuer_cert_uri()
        if self.aia_ext:
            if ocsp:
                ocsp_stat, issuer_data, ocsp_data = await self._verify_ocsp_async(verbose=verbose)
            else:
                ocsp_stat = None
                issuer_data = {'issuer_url_ok': False}
                ocsp_data = {}
        else:
            ocsp_stat = None
            issuer_data = {'issuer_url_ok': False}
            ocsp_data = {}

        cert_verifications = []
        if self.cert_policies_ext:
            for cert_policy in self.cert_policies_ext.value:
                if not isinstance(cert_policy, x509_extensions.PolicyInformation):
                    continue
                unknown_policy = ObjectIdentifier(cert_policy.policy_identifier.dotted_string)
                usage = [usage for usage, oid in CertChecker.KNOWN_VERIFICATION_POLICIES.items() if
                         oid == unknown_policy]
                if usage:
                    cert_verifications.append(usage[0])

        ocsp_must_staple_version = None
        if self.tls_feature_ext:
            for feature in self.tls_feature_ext.value:
                if feature == x509_extensions.TLSFeatureType.status_request:
                    ocsp_must_staple_version = 1
                elif feature == x509_extensions.TLSFeatureType.status_request2:
                    ocsp_must_staple_version = 2

        sct_list = None
        sct_poison_list = None
        if self.sct_ext:
            sct_list = []
            for sct in self.sct_ext.value:
                sct_entry = {
                    'version': sct.version,
                    'log_id': sct.log_id,
                    'timestamp': sct.timestamp,
                    'entry_type': sct.entry_type,
                    'signature': sct._signature
                }
                sct_list.append(sct_entry)
                if self._can_get_sct_details:
                    print('Version: %s' % sct.version)
                    print('Log id: %s' % sct.log_id.hex())
                    print('Timestamp: %s' % sct.timestamp)
                    print('Type: %s' % sct.entry_type)
                    print(sct._signature.hex())
                    from pyasn1.compat.integer import (to_bytes, bitLength)
                    part1, _remainder = asn1_decoder.decode(sct._signature)
                    print("1: %s" % part1[0])
                    print("2: %s" % part1[1])
                    if False:
                        b = int(part1[1]).to_bytes(2, byteorder='big')
                        print(b)
                        print("Go decode:")
                        print(decode_signature(b))
        if self.sct_poison_ext:
            sct_list = []
            for sct in self.sct_poison_ext.value:
                sct_entry = {
                    'version': sct.version,
                    'log_id': sct.log_id,
                    'timestamp': sct.timestamp,
                    'entry_type': sct.entry_type
                }
                sct_poison_list.append(sct_entry)

        if self.cert_from_host:
            connection_info = {
                'host_ip': self.cert_from_host[0],
                'requested_host': self.cert_from_host[1],
                'cert_matches_requested_host': self.cert_from_host_matches_cert,
                'protocol': self.cert_from_host_conn_proto,
                'cipher_name': self.cert_from_host_conn_cipher,
                'cipher_secret_size_bits': self.cert_from_host_conn_cipher_bits
            }
        else:
            connection_info = None
        verify_data = {
            'certificate_from_disc': self.cert_from_disc,
            'certificate_from_host': connection_info,
            'certificate': {
                'expired': is_expired,
                'valid_from': valid_from,
                'valid_to': valid_to,
                'issuer': issuer_info,
                'subject': subject_info,
                'serial_nro': serial_nro,
                'signature_algorithm': sig_algo,
                'dns_names': dns_names,
                'ip_addresses': ip_addresses,
                'urls': urls,
                'issuer_cert_url': ca_issuer,
                'ocsp_url': ocsp_uri,
                'public_key': cert_key_bytes,
                'public_key_type': public_key_type[1:],
                'cert_verification': cert_verifications,
                'ocsp_must_staple_version': ocsp_must_staple_version,
                'sct': sct_list,
                'sct_poison': sct_poison_list
            },
            'issuer': issuer_data,
            'ocsp_run': not ocsp_stat == None,
            'ocsp_ok': ocsp_stat,
            'ocsp': ocsp_data
        }

        return not is_expired and ocsp_stat, verify_data

    def issuer_cert_uri(self):
        ca_issuer = None
        if self.aia_ext and self.aia_ext.value:
            for aia in self.aia_ext.value:
                if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(aia.access_location, UniformResourceIdentifier):
                        ca_issuer = aia.access_location.value

        return ca_issuer

    def ocsp_uri(self):
        ocsp_uri = None
        if self.aia_ext and self.aia_ext.value:
            for aia in self.aia_ext.value:
                if aia.access_method == x509_oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(aia.access_location, UniformResourceIdentifier):
                        ocsp_uri = aia.access_location.value

        return ocsp_uri

    async def _verify_ocsp_async(self, verbose=False):
        issuer_data = {
            'issuer_url_ok': False,
            'issuer_url_connected_ok': None,
            'issuer_public_key': None,
            'issuer_public_key_type': None,
            'cert_signed_by_aia_issuer': None
        }
        ocsp_data = {
            'ocsp_url_connected_ok': None,
            'ocsp_certificate': None,
            'ocsp_certificate_pem': None
        }

        ocsp_uri = self.ocsp_uri()
        if not ocsp_uri:
            # raise OCSPUrlException("Cannot do get OCSP URI! Cert has no URL in AIA.")
            return None, issuer_data, ocsp_data

        issuer_cert = None
        try:
            ca_issuer_url, issuer_cert = await self._load_issuer_cert_async()
        except IssuerCertificateException:
            ca_issuer_url = None
        if ca_issuer_url:
            issuer_data['issuer_url_ok'] = True
        else:
            issuer_data['issuer_url_ok'] = False
        if not issuer_cert:
            issuer_data['issuer_url_connected_ok'] = False
            return None, issuer_data, ocsp_data

        issuer_data['issuer_url_connected_ok'] = True

        # Sanity check:
        # Is the certificate being investigated issued by the alleged "issuer" certificate we just loaded?
        issuer_cert_public_key = issuer_cert.public_key()
        issuer_cert_key = issuer_cert_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo
                                                              )
        issuer_cert_key_asn1, _remainder = asn1_decoder.decode(issuer_cert_key)
        issuer_cert_key_bytes = issuer_cert_key_asn1[1].asOctets()
        issuer_public_key_type = issuer_cert_public_key.__class__.__name__

        issuer_data['issuer_public_key'] = issuer_cert_key_bytes
        issuer_data['issuer_public_key_type'] = issuer_public_key_type[1:]

        # Basics:
        # Verify our target certificate is signed by our issuer certificate.
        certificate_verifies_ok = self._verify_signature(issuer_public_key_type,
                                                         issuer_cert_public_key,
                                                         self.cert.signature, self.cert.tbs_certificate_bytes,
                                                         self.cert.signature_hash_algorithm)
        issuer_data['cert_signed_by_aia_issuer'] = certificate_verifies_ok
        if not certificate_verifies_ok:
            # raise IssuerCertificateException(
            #    'Attempt to get issuer certificate failed. Loaded certificate is not the certificate used as issuer.')
            return None, issuer_data, ocsp_data

        # Go for OCSP!
        ocsp = OcspChecker(self.cert, issuer_cert, CertChecker.connection_timeout, self.loop)
        ocsp_stat, ocsp_data = await ocsp.request_async(ocsp_uri, verbose=verbose)
        self.last_ocsp_response = ocsp.last_ocsp_response

        ocsp_data['ocsp_url_connected_ok'] = ocsp_stat is not None

        if not ocsp_data['response_status_ok']:
            return False, issuer_data, ocsp_data

        now = datetime.utcnow()

        # Response verify process:
        # RFC 2560, 3.2  Signed Response Acceptance Requirements:
        # 1) The certificate identified in a received response corresponds to
        #    that which was identified in the corresponding request;
        # 2) The signature on the response is valid;
        # 3) The identity of the signer matches the intended recipient of the request.
        # 4) The signer is currently authorized to sign the response.
        # 5) The time at which the status being indicated is known to be correct (thisUpdate) is sufficiently recent.
        # 6) When available, the time at or before which newer information will be available
        #    about the status of the certificate (nextUpdate) is greater than the current time.

        # Steps:
        # 1) Serial number check
        # 2) RSA verify with issuer key
        # 3) If issuer hash present, matched
        # 4) Either (For more information see RFC 6960 below):
        # 4.1) Issuer signs the response
        # 4.2) OCSP-certificate signs the response
        # 4.2.1) OCSP-certificate has id-kp-OCSPSigning
        # 4.2.2) OCSP-certificate and subject certificate are issued by same CA
        # 5) Added check for OCSP-response data to be (by default) 7 days old, at max.
        # 6) If next update information is available, it needs to be in the future.

        # Response verify 1:
        # To-do: Verify signature

        # RFC 6960, 4.2.2.2. Authorized Responders, https://tools.ietf.org/html/rfc6960
        # Three rules for the signature of an Authorized Responder:
        #    1. Matches a local configuration of OCSP signing authority for the
        #       certificate in question, or
        #    2. Is the certificate of the CA that issued the certificate in
        #       question, or
        #    3. Includes a value of id-kp-OCSPSigning in an extended key usage
        #       extension and is issued by the CA that issued the certificate in
        #       question as stated above.
        # JaTu's notes on RFC 6960, 4.2.2.2.:
        #    1. There is no local configuration for anybody!! Never seen one in wild world.
        #    2. This is the typical scenario covered in above code. Issuer cert handles also OCSP responses.
        #    3. X.509 certificate to verify against is returned in OCSP-response

        signature = ocsp_data['signature']

        # Assume verifying with issuer public key
        ocsp_certificate_used = False
        ocsp_certificate_valid = None
        ocsp_certificate_valid_nocheck = None
        verification_public_key_type = issuer_public_key_type
        verification_public_key = issuer_cert_public_key

        if ocsp_data['ocsp_certificates']:
            verification_certificate = None
            for verification_certificate in ocsp_data['ocsp_certificates']:
                verification_public_key = verification_certificate.public_key()
                verification_public_key_type = verification_public_key.__class__.__name__
                ocsp_certificate_used = True

                # Check for id-kp-OCSPSigning and id-pkix-ocsp-nocheck
                extensions = None
                try:
                    extensions = x509_extensions.Extensions(verification_certificate.extensions)
                except ValueError:
                    pass

                extended_key_usage_name_ext = None
                ocsp_no_check_ext = None
                if extensions:
                    try:
                        extended_key_usage_name_ext = extensions.get_extension_for_class(
                            x509_extensions.ExtendedKeyUsage)
                    except x509_extensions.ExtensionNotFound:
                        extended_key_usage_name_ext = None
                    try:
                        ocsp_no_check_ext = extensions.get_extension_for_class(x509_extensions.OCSPNoCheck)
                        ocsp_certificate_valid_nocheck = verification_certificate.not_valid_after
                    except x509_extensions.ExtensionNotFound:
                        ocsp_certificate_valid_nocheck = False

                    if extended_key_usage_name_ext and extended_key_usage_name_ext.value:
                        ocsp_certificate_valid = False
                        if extended_key_usage_name_ext.value._usages and \
                                x509_oid.ExtendedKeyUsageOID.OCSP_SIGNING in extended_key_usage_name_ext.value._usages:
                            # Both the X.509 certificate provided to us in the OCSP-response and
                            # target certificate being verified MUST be issued by the _SAME_ issuer.
                            certificate_verifies_ok = self._verify_signature(issuer_public_key_type,
                                                                             issuer_cert_public_key,
                                                                             verification_certificate.signature,
                                                                             verification_certificate.tbs_certificate_bytes,
                                                                             verification_certificate.signature_hash_algorithm)
                            if certificate_verifies_ok:
                                ocsp_certificate_valid = True
                                break

            # Tinker with return data
            del ocsp_data['ocsp_certificates']
            if certificate_verifies_ok:
                ocsp_data['ocsp_certificate'] = verification_certificate
                ocsp_data['ocsp_certificate_pem'] = verification_certificate.public_bytes(serialization.Encoding.PEM)
            else:
                ocsp_data['ocsp_certificate'] = None
                ocsp_data['ocsp_certificate_pem'] = None

        # Perform the OCSP-response signature verification.
        signature_verifies_ok = self._verify_signature(verification_public_key_type,
                                                       verification_public_key,
                                                       signature, ocsp_data['tbs_response_bytes'],
                                                       ocsp_data['signature_hash_algorithm'])
        # Apply RFC 6960, 4.2.2.2. rule 3), if applicable
        if ocsp_certificate_used and signature_verifies_ok and not ocsp_certificate_valid:
            signature_verifies_ok = False

        if False and verbose:
            if signature_verifies_ok:
                print('%s: Signature verification success: Payload and signature files verify' %
                      issuer_public_key_type)
            else:
                print('%s: Signature verification fail: Payload and/or signature files failed verification!' %
                      issuer_public_key_type)

        ocsp_data['signature_verify_status'] = signature_verifies_ok
        ocsp_data['signature_verify_ocsp_cert_used'] = ocsp_certificate_used
        ocsp_data['signature_verify_ocsp_cert_valid'] = ocsp_certificate_valid
        ocsp_data['signature_verify_ocsp_cert_valid_nocheck'] = ocsp_certificate_valid_nocheck

        # Response verify 2:
        # Make sure response certificate serial number matches our target certificate serial
        serial_nro = self.cert.serial_number
        if serial_nro == ocsp_data['serial_number']:
            ocsp_data['serial_number_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['serial_number_match'] = False

        # Response verify 3:
        # Make sure response issuer key hash matches target certificate issuer certificate key hash.
        # Debug: https://lapo.it/asn1js/ or https://holtstrom.com/michael/tools/asn1decoder.php will be handy
        if ocsp_data['hash_algorithm'].lower() == 'sha1':
            issuer_cert_key_hash = hashes.Hash(hashes.SHA1(), backend=issuer_cert._backend)
        elif ocsp_data['hash_algorithm'].lower() == 'sha256':
            issuer_cert_key_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._backend)
        else:
            raise OCSPHashException(
                "Cannot verify OCSP-response! Information hashed with a '%s' and I don't know how to handle it." %
                ocsp_data['hash_algorithm'])

        issuer_cert_key_hash.update(issuer_cert_key_bytes)
        issuer_cert_key_hash_bytes = issuer_cert_key_hash.finalize()

        if issuer_cert_key_hash_bytes == ocsp_data['issuer_key_hash']:
            ocsp_data['issuer_key_hash_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['issuer_key_hash_match'] = False

        # Response verify 4:
        # Make sure response name hash matches target certificate issuer hashed certificate name.
        certificate_asn1_bytes = issuer_cert.public_bytes(serialization.Encoding.DER)
        cert_as_openssl = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_asn1_bytes)
        cert_as_openssl_subject = cert_as_openssl.get_subject()
        subject_bytes = cert_as_openssl_subject.der()

        if ocsp_data['hash_algorithm'].lower() == 'sha1':
            subject_hash = hashes.Hash(hashes.SHA1(), backend=issuer_cert._backend)
        elif ocsp_data['hash_algorithm'].lower() == 'sha256':
            subject_hash = hashes.Hash(hashes.SHA256(), backend=issuer_cert._backend)
        else:
            raise OCSPHashException(
                "Cannot verify OCSP-response! Information hashed with a '%s' and I don't know how to handle it." %
                ocsp_data['hash_algorithm'])

        subject_hash.update(subject_bytes)
        subject_hash_bytes = subject_hash.finalize()

        ocsp_data['issuer_name_seen'] = subject_bytes
        if subject_hash_bytes == ocsp_data['issuer_name_hash']:
            ocsp_data['issuer_name_hash_match'] = True
        else:
            ocsp_stat = False
            ocsp_data['issuer_name_hash_match'] = False

        # Response verify 4:
        # OCSP-response this update time is "sufficiently recent".
        # If next update is available, use that as a criteria for "sufficiently recent".
        update_time_ok = None
        response_created = now - timedelta(days=CertChecker.ocsp_response_expiry_days)

        this_update = now - ocsp_data['this_update']
        if this_update.total_seconds() > 0:
            # Good. Update was in past.
            if ocsp_data['next_update']:
                if ocsp_data['next_update'] < now:
                    # Response information is expired.
                    update_time_ok = False
            if update_time_ok == None and ocsp_data['this_update'] > response_created:
                # Information is not expired and was created within our allowed range.
                update_time_ok = True
            else:
                # Information is not expired but is older than we allow.
                update_time_ok = False
        else:
            # What? Update is in the future.
            update_time_ok = False

        ocsp_data['update_time_ok'] = update_time_ok
        if not update_time_ok:
            ocsp_stat = False

        # Verify done!

        return ocsp_stat, issuer_data, ocsp_data

    @staticmethod
    def _verify_signature(public_key_type, public_key, signature, payload, hash_algorithm):
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
            except cryptography.exceptions.InvalidSignature:
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
            except cryptography.exceptions.InvalidSignature:
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

    async def _load_issuer_cert_async(self):
        ca_issuer_url = None
        for aia in self.aia_ext.value:
            if aia.access_method == x509_oid.AuthorityInformationAccessOID.CA_ISSUERS:
                if isinstance(aia.access_location, UniformResourceIdentifier):
                    ca_issuer_url = aia.access_location.value
        if not ca_issuer_url:
            # Cannot do get issuer certificate! Cert has no URL in AIA.
            return None, None

        url_parts = urlparse(ca_issuer_url)
        if not url_parts.scheme in ['http', 'https']:
            return None, None

        # Go get the issuer certificate from indicated URI
        response, response_content = await RequestsSession.get_issuer_cert_async(self.loop, ca_issuer_url,
                                                                                 CertChecker.connection_timeout)
        if not response:
            return ca_issuer_url, None

        issuer_cert = None
        if 'content-type' in response.headers:
            contentType = response.headers['content-type']
        else:
            contentType = ""

        if contentType in ['application/x-x509-ca-cert', 'application/pkix-cert']:
            # This is a basic certificate
            try:
                # Is DER-formatted?
                issuer_cert = x509.load_der_x509_certificate(response_content, x509_openssl_backend)
            except (TypeError, ValueError):
                issuer_cert = None
            if not issuer_cert:
                try:
                    issuer_cert = x509.load_pem_x509_certificate(response_content, x509_openssl_backend)
                except (TypeError, ValueError):
                    raise IssuerCertificateException(
                        'Cannot do get issuer certificate! No idea on how to process response from %s' % ca_issuer_url)
        elif contentType == 'application/pkcs7-mime':
            # This is a DER-formatted certificate wrapped into PKCS#7
            interim_certificates = []

            # DANGER! DANGER! DANGER!
            # Digging into guts of OpenSSL isn't smart. It's stupid. Very stupid.
            # For extracting a certificate out of a PKCS#7 there is no ready-made solution and this is the only
            # applicable way (for now). I'll be standing by for OpenSSL-team to come up with a proper interface for
            # certificate extraction.
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, response_content)

            certs = _ffi.NULL
            if pkcs7.type_is_signed():
                certs = pkcs7._pkcs7.d.sign.cert
            elif pkcs7.type_is_enveloped():
                certs = pkcs7._pkcs7.d.enveloped.cert
            elif pkcs7.type_is_signedAndEnveloped():
                certs = pkcs7._pkcs7.d.signed_and_enveloped.cert

            num_certs_in_pkcs7 = _lib.sk_X509_num(certs)
            for cert_num in range(num_certs_in_pkcs7):
                cert_data_ptr = _lib.X509_dup(_lib.sk_X509_value(certs, cert_num))
                interim_issuer_cert = crypto.X509._from_raw_x509_ptr(cert_data_ptr)
                interim_certificates.append(interim_issuer_cert.to_cryptography())
            # end DANGER! DANGER! DANGER! end

            for interim_issuer_cert in interim_certificates:
                public_key = interim_issuer_cert.public_key()
                public_key_type = public_key.__class__.__name__
                certificate_verifies_ok = self._verify_signature(public_key_type,
                                                                 public_key,
                                                                 self.cert.signature, self.cert.tbs_certificate_bytes,
                                                                 self.cert.signature_hash_algorithm)
                if certificate_verifies_ok:
                    issuer_cert = interim_issuer_cert
                    break
            if not issuer_cert:
                raise PKCS7Exception(
                    'Found PKCS#7 certificate with multiple certificates! None of them seems to be the issuer certificate.')

        else:
            # No Content-Type given or we don't know that particular Content-Type.
            # Let's guess!
            try:
                issuer_cert = x509.load_der_x509_certificate(response_content, x509_openssl_backend)
            except (TypeError, ValueError):
                issuer_cert = None
            if not issuer_cert:
                try:
                    issuer_cert = x509.load_pem_x509_certificate(response_content, x509_openssl_backend)
                except (TypeError, ValueError):
                    raise IssuerCertificateException(
                        'Cannot do get issuer certificate! No idea on how to process response from %s' % ca_issuer_url)

            if not issuer_cert:
                raise MimeTypeException(
                    "Certificate loaded from %s has content type %s. Don't know how to process it." %
                    (ca_issuer_url, contentType))

        # Store the issuer certificate also in PEM-format for possible use.
        self.last_issuer_certificate_pem = issuer_cert.public_bytes(serialization.Encoding.PEM)

        return ca_issuer_url, issuer_cert
