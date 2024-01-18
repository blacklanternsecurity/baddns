class BadDNSException(Exception):
    pass


class BadDNSSignatureException(BadDNSException):
    pass


class BadDNSMatcherException(BadDNSException):
    pass


class BadDNSCLIException(BadDNSException):
    pass


class BadDNSFindingException(BadDNSException):
    pass
