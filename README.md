# Cert Check library & CLI-tool
This library and tool is intended to help verification of existing X.509 certificates.

## Usage:

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