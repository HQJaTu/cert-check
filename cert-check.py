#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
import argparse
from cert_check_lib import *
from urllib.parse import urlparse
import shlex


def write_ocsp_response_into_file(ocsp_response_file, ocsp_response):
    with open(ocsp_response_file, 'wb') as outfile:
        outfile.write(ocsp_response)


def write_certificate_into_file(certificate_file, certificate_bytes):
    with open(certificate_file, 'wb') as outfile:
        outfile.write(certificate_bytes)


def get_ocsp_command(cert_file, issuer_uri, ocsp_uri):
    issuer_url_parts = urlparse(issuer_uri).path.split('/')
    issuer_cert_file = issuer_url_parts[-1]
    cmd = []
    cmd.append('$ wget %s' % issuer_uri)
    cmd.append('$ openssl ocsp -no_nonce -verify_other %s -issuer %s -cert %s -url %s' %
               (shlex.quote(issuer_cert_file), shlex.quote(issuer_cert_file),
                shlex.quote(cert_file), ocsp_uri)
               )

    return cmd


def print_verify_result(verify_result):
    failures = []
    certificate_info = verify_result['certificate']
    ocsp_info = verify_result['ocsp']
    issuer_info = ""
    subject_info = ""
    responder_info = None
    for component_name in certificate_info['issuer']:
        issuer_info += "\n    %s=%s" % (component_name, certificate_info['issuer'][component_name])
    for component_name in certificate_info['subject']:
        subject_info += "\n    %s=%s" % (component_name, certificate_info['subject'][component_name])
    responder_info = ''
    if ocsp_info and ocsp_info['responder_name']:
        for component_name in ocsp_info['responder_name']:
            responder_info += "\n    %s=%s" % (component_name, ocsp_info['responder_name'][component_name])

    if certificate_info['expired']:
        failures.append('Expired')

    if verify_result['certificate_from_disc']:
        print("Cert loaded from file")
    elif verify_result['certificate_from_host']:
        connection_info = verify_result['certificate_from_host']
        print("Cert loaded from: %s, Protocol: %s, Cipher: %d-bit %s" % (
            connection_info['host_ip'], connection_info['protocol'],
            connection_info['cipher_secret_size_bits'], connection_info['cipher_name'])
              )
    else:
        print("Cert loaded from ... unknown source")

    cert_key_hash = hashes.Hash(hashes.SHA1(), backend=default_backend())
    cert_key_hash.update(certificate_info['public_key'])
    cert_key_hash_bytes = cert_key_hash.finalize()
    if ocsp_info:
        issuer_cert_key_hash = hashes.Hash(hashes.SHA1(), backend=default_backend())
        issuer_cert_key_hash.update(ocsp_info['issuer_public_key'])
        issuer_cert_key_hash_bytes = issuer_cert_key_hash.finalize()
    else:
        issuer_cert_key_hash_bytes = bytes()

    print("Certificate information:")
    print("  Cert %s expired" % ('has' if certificate_info['expired'] else 'not'))
    print("    Validity: %s - %s" % (certificate_info['valid_from'], certificate_info['valid_to']))
    print("  Subject: %s" % subject_info)
    print("  Serial #: %s" % certificate_info['serial_nro'])
    print("  Signature algo: %s" % certificate_info['signature_algorithm'])
    print("  Public key (%s) SHA-1: %s" % (certificate_info['public_key_type'], cert_key_hash_bytes.hex()))

    if certificate_info['dns_names'] or certificate_info['ip_addresses'] or certificate_info['urls']:
        print("  Alternate names:")
        if certificate_info['dns_names']:
            print("    DNS-names: %s" % ', '.join(certificate_info['dns_names']))
        if certificate_info['ip_addresses']:
            ip_info = []
            for ip in certificate_info['ip_addresses']:
                ip_info.append(str(ip))
            print("    IP-addresses: %s" % ', '.join(ip_info))
        if certificate_info['urls']:
            print("    URIs: %s" % ', '.join(certificate_info['urls']))

    print("  Authority Information Access (AIA):")
    print("    Issuer certificate URL: %s" % certificate_info['issuer_cert_url'])
    print("    OCSP URL: %s" % certificate_info['ocsp_url'])

    print("Issuer:\n  Subject:%s" % issuer_info)
    if verify_result['ocsp_run']:
        print("  Public key (%s) SHA-1: %s" % (ocsp_info['issuer_public_key_type'], issuer_cert_key_hash_bytes.hex()))
    else:
        print("  Public key (-unknown-) SHA-1: -unknown-")

    print("OCSP status: %s" % (
        'pass' if verify_result['ocsp_ok'] else 'fail!' if verify_result['ocsp_run'] else '-'))
    if verify_result['ocsp_run']:
        print("  Certificate status: %s" % ocsp_info['certificate_status'])
        print("  Request hash algorithm: %s" % ocsp_info['request_hash_algorithm'])
        print("  Responder name: %s" % responder_info)
        print("  Responder key hash: %s" % (
            ocsp_info['responder_key_hash'].hex() if ocsp_info['responder_key_hash'] else ''))
        print("  Response hash algorithm: %s" % ocsp_info['hash_algorithm'])
        print("  Response signature hash algorithm: %s" % ocsp_info['signature_hash_algorithm'].__class__.__name__)
        print("  Response signature verify status: %s, used %s%s certificate" % (
            'Verifies ok' if ocsp_info['signature_verify_status'] else 'fail',
            'invalid ' if ocsp_info['signature_verify_ocsp_cert_used'] and not ocsp_info[
                'signature_verify_ocsp_cert_valid'] else 'valid ' if ocsp_info[
                'signature_verify_ocsp_cert_used'] else '',
            'OCSP' if ocsp_info['signature_verify_ocsp_cert_used'] else 'issuer'
        ))
        print("  Revocation time: %s" % ocsp_info['revocation_time'])
        print("  Revocation reason: %s" % ocsp_info['revocation_reason'])
        print("  Produced at: %s" % ocsp_info['produced_at'])
        print("  This update: %s, %s" % (
            ocsp_info['this_update'],
            'valid' if ocsp_info['update_time_ok'] else 'expired' if ocsp_info['update_time_ok'] == False else '-'))
        print("  Next update: %s" % ocsp_info['next_update'])

        if ocsp_info['serial_number_match']:
            print("  OCSP serial number: Matches certificate serial number")
        else:
            print(
                "  OCSP serial number: %s does not match certificate serial number" % ocsp_info['serial_number'])

        if ocsp_info['issuer_key_hash_match']:
            print("  OCSP issuer key hash: Matches issuer certificate key %s hash" % ocsp_info['hash_algorithm'])
        elif ocsp_info['issuer_key_hash']:
            print("  OCSP issuer key %s hash: %s does not match issuer certificate key hash" %
                  (ocsp_info['hash_algorithm'], ocsp_info['issuer_key_hash'].hex()))
        else:
            print("  OCSP issuer key hash cannot be compared, key hash not in response")

        if ocsp_info['issuer_name_hash_match']:
            print("  OCSP issuer name hash: Matches issuer certificate name %s hash" %
                  ocsp_info['hash_algorithm']
                  )
        elif ocsp_info['issuer_name_hash']:
            print("  OCSP issuer name %s hash: %s does not match issuer name hash" %
                  (ocsp_info['hash_algorithm'], ocsp_info['issuer_name_hash'].hex()))
        else:
            print("  OCSP issuer name hash cannot be compared, name not in response")

        if not verify_result['ocsp_ok']:
            failures.append('OCSP')
    else:
        print("OCSP not verified")

    if failures:
        print("Done. Failures: %s" % ', '.join(failures))
    else:
        print("Done.")


def main():
    parser = argparse.ArgumentParser(description='DNS query helper tool')
    parser.add_argument('--connect', metavar='HOSTNAME:PORT',
                        help='Host to connect to for extracting a TLS-certificate')
    parser.add_argument('--file', '--cert-file', metavar='PEM-CERT-FILE',
                        help='TLS-certificate PEM-file to read')
    parser.add_argument('--silent', action='store_true', default=False,
                        help='Normal mode is to be verbose and output human-readable information.')
    parser.add_argument('--print-ocsp-command', action='store_true',
                        help='Output openssl-command for OCSP-verification')
    parser.add_argument('--ocsp-response-file', metavar='OCSP-RESPONSE-FILE',
                        help='Write DER-formatted OCSP-response into a file, if specified')
    parser.add_argument('--output-certificate-file', '--out-cert-file', metavar='PEM-CERT-FILE',
                        help='Write PEM-formatted X.509 certificate into a file, if specified')
    parser.add_argument('--output-issuer-certificate-file', '--out-issuer-cert-file', metavar='PEM-CERT-FILE',
                        help='Write PEM-formatted issuer X.509 certificate into a file, if specified')
    args = parser.parse_args()

    cc = CertChecker()
    if args.file:
        cc.load_pem_from_file(args.file)
    elif args.connect:
        host_parts = args.connect.split(':')
        if len(host_parts) == 1:
            host_parts.append(443)
        elif len(host_parts) == 2:
            host_parts[1] = int(host_parts[1])
        else:
            raise ValueError("Don't understand --connect %s!" % args.connect)
        cc.load_pem_from_host(host_parts[0], host_parts[1], verbose=not args.silent)

    if not cc.has_cert():
        raise ValueError("Cannot proceed, no cert!")

    verify_stat, verify_result = cc.verify(verbose=not args.silent)
    if not args.silent:
        print_verify_result(verify_result)

    if args.ocsp_response_file and cc.last_ocsp_response:
        write_ocsp_response_into_file(args.ocsp_response_file, cc.last_ocsp_response)

    if args.output_certificate_file and cc.last_certificate_pem:
        write_certificate_into_file(args.output_certificate_file, cc.last_certificate_pem)

    if args.output_issuer_certificate_file and cc.last_issuer_certificate_pem:
        write_certificate_into_file(args.output_issuer_certificate_file, cc.last_issuer_certificate_pem)

    if args.print_ocsp_command:
        if args.file:
            cert_file = args.file
        else:
            cert_file = 'certificate.pem'
        ocsp_cmd = get_ocsp_command(cert_file, cc.issuer_cert_uri(), cc.ocsp_uri())
        print("Commands to execute for OCSP-verification:\n%s" % '\n'.join(ocsp_cmd))
    if not verify_stat:
        exit(1)

    exit(0)


if __name__ == "__main__":
    main()
