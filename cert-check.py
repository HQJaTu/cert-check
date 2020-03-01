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
            host_parts[1] = int(443)
        else:
            raise ValueError("Don't understand --connect %s!" % args.connect)
        cc.load_pem_from_host(host_parts[0], host_parts[1], verbose=not args.silent)

    if not cc.has_cert():
        raise ValueError("Cannot proceed, no cert!")

    verify_stat = cc.verify(verbose=not args.silent)

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
