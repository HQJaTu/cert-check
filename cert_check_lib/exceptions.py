# Define types for different exceptions for better error handling

class ConnectionException(Exception):
    pass


class OCSPUrlException(Exception):
    pass


class OCSPHashException(Exception):
    pass


class IssuerCertificateException(Exception):
    pass


class PKCS7Exception(Exception):
    pass


class MimeTypeException(Exception):
    pass


class UnsupportedPublicKeyAlgorithmException(Exception):
    pass
