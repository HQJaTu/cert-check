# Cert Check library & CLI-tool
This library and tool is intended to help verification of existing X.509 certificates.

Basic certificate verification includes expiry. The certificate needs not to be expired at the time of verifying.
Also, an OCSP-check is made if certificate includes appropriate information in Authority Information Access extension.

## Usage:
```text
usage: cert-check.py [-h] [--connect CONNECT] [--file FILE] [--silent]

DNS query helper tool

optional arguments:
  -h, --help            show this help message and exit
  --connect CONNECT     Hostname:port to connect to for a TLS-certificate
  --file FILE           TLS-certificate PEM-file to read
  --silent              Normal mode is to be verbose and output human-readable
                        information.
  --print-ocsp-command  Output openssl-command for OCSP-verification
```

### Example
```bash
./cert-check.py --connect tekes.fi:443
```
will result something like this:
```text
TLS-version used in connection: TLSv1.2
OCSP assertion length: 0
Cert not expired
    2019-01-12 00:00:00 - 2021-01-20 12:00:00
Issuer:
    C=US
    O=DigiCert Inc
    OU=www.digicert.com
    CN=DigiCert SHA2 High Assurance Server CA
Subject:
    C=FI
    L=Helsinki
    O=Business Finland Oy
    OU=Marketing and communications
    CN=www.horisontti2020.fi
Serial #: 10865345032188387016727712607843656671
Signature algo: sha256WithRSAEncryption
Alternate names:
    DNS-names: www.horisontti2020.fi, horisontti2020.fi
Authority Information Access (AIA):
    Issuer: http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
    OCSP: http://ocsp.digicert.com
OCSP status:
    Response hash algorithm: SHA1
    Response signature hash algorithm: SHA256
    Certificate status: REVOKED
    Revocation time: 2019-06-04 13:59:36
    Revocation reason: None
    Produced at: 2020-02-16 18:10:42
    This update: 2020-02-16 18:10:42
    Next update: 2020-02-23 17:25:42
```

### Verifying existing PEM-file
Example:
```bash
./cert-check.py --file tekes.pem.cer
```
will result in similar output.

### Output OpenSSL-command to run OCSP-verify
For learning, how to do OCSP-verifying without this tool, sample commands can be output
to yield similar results.

Note: `openssl` will require both target certificate to be verified and the issuer CA-certificate
PEM-certificates to be accessed as local files.
Part of `cert-check.py` is to simplify the sequence and load certificates on-the-fly.

Example:
```bash
./cert-check.py --file tekes.pem.cer --print-ocsp-command
```
output:
```bash
$ wget http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
$ openssl ocsp -no_nonce -issuer DigiCertSHA2HighAssuranceServerCA.crt -cert tekes.pem.cer -url http://ocsp.digicert.com
```