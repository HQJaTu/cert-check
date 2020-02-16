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

    if not cc.has_cert():
        raise ValueError("Cannot proceed, no cert!")

    cc.verify()


if __name__ == "__main__":
    main()
