#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import sys
import argparse
from lib.cert_check import *


def main():
    parser = argparse.ArgumentParser(description='DNS query helper tool')
    parser.add_argument('--connect',
                        help='Hostname:port to connect to for a TLS-certificate')
    parser.add_argument('--file',
                        help='TLS-certificate PEM-file to read')
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
        cc.load_pem_from_host(host_parts[0], host_parts[1])

    if not cc.has_cert():
        raise ValueError("Cannot proceed, no cert!")

    cc.verify()


if __name__ == "__main__":
    main()
