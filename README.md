# Cert Check library & CLI-tool
This library and tool is intended to help verification of existing X.509 certificates.

Basic certificate verification includes expiry. The certificate needs not to be expired at the time of verifying.
Also, an OCSP-check is made if certificate includes appropriate information in Authority Information Access extension.

## Requirements
* Python 3.7+
  * PySSL is using latest features to extract all the necessary information on `--connect`.
* OS: Tested on Linux and Windows, working on both

## Installation
1) `git clone https://github.com/HQJaTu/cert-check.git`
1) `cd cert-check`
1) `pip3 install .`
1) Done!

## Usage:
```text
usage: cert-check.py [-h] [--connect HOSTNAME:PORT] [--file PEM-CERT-FILE]
                     [--silent] [--print-ocsp-command]
                     [--ocsp-response-file OCSP-RESPONSE-FILE]
                     [--output-certificate-file PEM-CERT-FILE]
                     [--output-issuer-certificate-file PEM-CERT-FILE]

DNS query helper tool

optional arguments:
  -h, --help            show this help message and exit
  --connect HOSTNAME:PORT
                        Host to connect to for extracting a TLS-certificate
  --file PEM-CERT-FILE, --cert-file PEM-CERT-FILE
                        TLS-certificate PEM-file to read
  --silent              Normal mode is to be verbose and output human-readable
                        information.
  --print-ocsp-command  Output openssl-command for OCSP-verification
  --ocsp-response-file OCSP-RESPONSE-FILE
                        Write DER-formatted OCSP-response into a file, if
                        specified
  --output-certificate-file PEM-CERT-FILE, --out-cert-file PEM-CERT-FILE
                        Write PEM-formatted X.509 certificate into a file, if
                        specified
  --output-issuer-certificate-file PEM-CERT-FILE, --out-issuer-cert-file PEM-CERT-FILE
                        Write PEM-formatted issuer X.509 certificate into a
                        file, if specified
```

### Example
```bash
./cert-check.py --connect tekes.fi:443
```
will result something like this:
```text
Cert loaded from: 217.114.92.150, Protocol: TLSv1.2, Cipher: 128-bit ECDHE-RSA-AES128-GCM-SHA256
Certificate information:
  Cert not expired
    Validity: 2019-01-12 00:00:00 - 2021-01-20 12:00:00
  Subject:
    countryName=FI
    localityName=Helsinki
    organizationName=Business Finland Oy
    organizationalUnitName=Marketing and communications
    commonName=www.horisontti2020.fi
  Serial #: 10865345032188387016727712607843656671
  Signature algo: sha256
  Public key (RSAPublicKey) SHA-1: a3ee1646edfa1db59ceb7c2dc3b5b8c370e3d988
  Alternate names:
    DNS-names: www.horisontti2020.fi, horisontti2020.fi
  Authority Information Access (AIA):
    Issuer certificate URL: http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt
    OCSP URL: http://ocsp.digicert.com
Issuer:
  Subject:
    countryName=US
    organizationName=DigiCert Inc
    organizationalUnitName=www.digicert.com
    commonName=DigiCert SHA2 High Assurance Server CA
  Public key (RSAPublicKey) SHA-1: 5168ff90af0207753cccd9656462a212b859723b
OCSP status: fail!
  Certificate status: REVOKED
  Request hash algorithm: SHA256
  Responder name:
  Responder key hash: 5168ff90af0207753cccd9656462a212b859723b
  Response hash algorithm: SHA1
  Response signature hash algorithm: SHA256
  Response signature verify status: Verifies ok, used issuer certificate
  Revocation time: 2019-06-04 13:59:36
  Revocation reason: None
  Produced at: 2020-03-07 18:09:01
  This update: 2020-03-07 18:09:01, valid
  Next update: 2020-03-14 17:24:01
  OCSP serial number: Matches certificate serial number
  OCSP issuer key hash: Matches issuer certificate key SHA1 hash
  OCSP issuer name hash: Matches issuer certificate name SHA1 hash
Done. Failures: OCSP
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