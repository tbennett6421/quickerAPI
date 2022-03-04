__code_version__ = 'v0.0.0'

## Standard Libraries
import os

## Third-Party
import requests
import urllib3

## Modules
try:
    from .BuildingBlocks import BaseObject
except ImportError:
    from BuildingBlocks import BaseObject

class WebClient(BaseObject):

    def __init__(self):
        ## Call parent init
        super().__init__()
        self.configureTLSValidation(allowInsecure=False)

    def configureTLSValidation(self, allowInsecure=False):
        """ Configure TLS for requests: Where possible use or require TLS validation """
        env_hunt_paths = ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"]
        file_hunt_paths = [
            "/etc/pki/tls/certs/ca-bundle.crt",         # RHEL
            "/etc/ssl/certs/ca-certificates.crt",       # WSL
            "/etc/ssl/cert.pem",                        # OSX
        ]
        self.tls_bundle = None
        self.verify = None
        # First attempt to probe environment
        for e in env_hunt_paths:
            try:
                self.tls_bundle = os.environ["REQUESTS_CA_BUNDLE"]
                self.verify = True
            except KeyError:
                pass

        # if probing env fails, probe filesystem
        if not self.verify:
            for f in file_hunt_paths:
                if os.path.isfile(f):
                    self.tls_bundle = f
                    self.verify = True

        # all else fails. allow insecure, or set to system.
        if not self.verify:
            if allowInsecure:
                self.verify = False
                self.tls_bundle = False
            else:
                self.verify = True
                self.tls_bundle = True

def demo():
    pass

def main():
    demo()

if __name__=="__main__":
    main()
