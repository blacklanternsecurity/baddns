class BadDNSException(Exception):
    pass


class BadDNSSignatureException(BadDNSException):
    pass


class BadDNSMatcherException(BadDNSException):
    pass
