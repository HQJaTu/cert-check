#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
import argparse
from lib.cert_check import *
from urllib.parse import urlparse
import shlex


def get_ocsp_command(cert_file, issuer_uri, ocsp_uri):
    issuer_url_parts = urlparse(issuer_uri).path.split('/')
    issuer_cert_file = issuer_url_parts[-1]
    cmd = []
    cmd.append('$ wget %s' % issuer_uri)
    cmd.append('$ openssl ocsp -no_nonce -issuer %s -cert %s -url %s' %
               (shlex.quote(issuer_cert_file), shlex.quote(cert_file), ocsp_uri)
               )

    return cmd


def main():
    parser = argparse.ArgumentParser(description='DNS query helper tool')
    parser.add_argument('--connect',
                        help='Hostname:port to connect to for a TLS-certificate')
    parser.add_argument('--file',
                        help='TLS-certificate PEM-file to read')
    parser.add_argument('--silent', action='store_true', default=False,
                        help='Normal mode is to be verbose and output human-readable information.')
    parser.add_argument('--print-ocsp-command', action='store_true',
                        help='Output openssl-command for OCSP-verification')
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
    if args.print_ocsp_command:
        if args.file:
            cert_file = args.file
        else:
            cert_file = 'certificate.pem'
        ocsp_cmd = get_ocsp_command(cert_file, cc.issuer_cert_uri(), cc.ocsp_uri())
        print("Commands to execute for OCSP-verification is\n%s" % '\n'.join(ocsp_cmd))
    if not verify_stat:
        exit(1)

    exit(0)


if __name__ == "__main__":
    main()
