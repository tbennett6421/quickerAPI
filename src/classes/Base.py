from __future__ import print_function
from __future__ import absolute_import
__code_version__ = 'v3.2.2'
__env__ = "P2"

## Standard Libraries
import os
import re
import socket
from getpass import getpass

# pyOpenSSL
# from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, load_certificate, load_pkcs12

def askForCredentials(prompt):
    passwd = None
    print(prompt)
    while passwd is None:
        usernm = input("Username : ")
        prompt1 = getpass("Password : ")
        prompt2 = getpass("Confirm  : ")
        if prompt1 == prompt2:
            return (usernm, prompt1)
        else:
            print("Password mismatch. Please try again")

def configureTLSValidation(disable_verification=False):
    """
        Attempt to detect and configure TLS cert checking, allow caller to override in cases
        where the TLS for a given system/service is self-signed.
        @param: disable_verification: @boolean Whether to disable TLS verification
        @return: tuple(bool, str)
                (True, True):  Enable TLS verification; use SYSTEM CA_CERTS
                (False, None): Disable TLS verification; trust self-signed
                (True, str()): Enable TLS verification; use custom CA_CERTS
    """

    if disable_verification:
        return False, None

    env_hunt_paths = ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"]
    file_hunt_paths = [
        "/etc/pki/tls/certs/ca-bundle.crt",         # RHEL
        "/etc/ssl/certs/ca-certificates.crt",       # WSL
        "/etc/ssl/certs/Availity.pem",              # OSX
    ]

    # First attempt to probe environment
    for e in env_hunt_paths:
        try:
            return True, os.environ[e]
        except KeyError:
            pass

    # if probing env fails, probe filesystem
    for f in file_hunt_paths:
        if os.path.isfile(f):
            return True, f

    # all else fails, use system
    return True, True

def collapseTerms(t1, t2):
    """ Given two terms, (user, db_user) return t1 over t2 """
    t = t1 if t1 is not None else t2
    return t

def checkForCSV(arg):
    """ Check if argument appears to be a csv list. return list or the original item """
    if ',' in arg:
        return str(arg).split(',')
    else:
        return arg

def detectRunningSite():
    """ Probe the hostname and attempt to determine where we are running """
    global __env__
    hn = socket.gethostname()
    p1 = re.match(r'dt.prd*', hn)
    if p1 is not None:
        __env__ = 'P1'
        return __env__
    p2 = re.match(r'ag.prd*', hn)
    if p2 is not None:
        __env__ = 'P2'
        return __env__
    qap = re.match(r'ag.qap*', hn)
    if qap is not None:
        __env__ = 'QAP'
        return __env__
    qua = re.match(r'ag.qua*', hn)
    if qua is not None:
        __env__ = 'QUA'
        return __env__
    tst = re.match(r'ag.tst*', hn)
    if tst is not None:
        __env__ = 'TST'
        return __env__
    return __env__

def isEmpty(p):
    """ check if p is None or empty string """
    if not p:
        return True
    else:
        return False

def isString(arg):
    return isinstance(arg, str)

def isIterableCollection(arg):
    """
        Strings are iterable, but generally we don't want to iterate on strings, but collections
        returns true if iterable and not str
        false otherwise
    """
    b = isString(arg)
    if not b:
        try:
            x = iter(arg)
            return True
        except TypeError as te:
            return False
    else:
        return False

def getArgsLikeObject(state=None):
    """
        If a state is provided, this will pull the args out and return them,
        otherwise it constructs a lambda which can be used like an args object
    """
    if state is not None:
        args = state.args
    else:
        args = lambda: None
        args.verbose = 0
        args.debug = False
    return args

def removeCommas(arg):
    return str(arg).replace(",", "")

def stripCommas(arg):
    return removeCommas(arg)

def split(s, delimiter=","):
    return s.split(delimiter)

# def print_x509(pem):
#     """ Takes a pem file loaded using openssl.crypto """
#     print(f"                                                   ")
#     print(f"Dumping x509 details ")
#     print(f"============================")
#     print(f"PEM Issuer    : {pem.get_issuer()}")
#     print(f"PEM NotBefore : {pem.get_notBefore()}")
#     print(f"PEM NotAfter  : {pem.get_notAfter()}")
#     print(f"PEM Serial    : {pem.get_serial_number()}")
#     print(f"PEM PublicKey : {pem.get_pubkey()}")
#     print(f"PEM Subject   : {pem.get_subject()}")
#     print(f"PEM Expired   : {pem.has_expired()}")
#     print(f"                                                   ")

# def print_pk12(pk12):
#     """ Takes a pem file loaded using openssl.crypto """
#     print(f"                                                   ")
#     print(f"Dumping PKCS#12 details ")
#     print(f"============================")
#     print(f"PK12 CA Certs     : {pk12.get_ca_certificates()}")
#     print(f"PK12 Certs        : {pk12.get_certificates()}")
#     print(f"PK12 FriendlyName : {pk12.get_friendlyname()}")
#     print(f"PK12 PrivateKey   : {pk12.get_privatekey()}")
#     print(f"                                                   ")
