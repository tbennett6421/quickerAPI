__code_debug__ = False
__code_version__ = 'v0.0.0'

## Standard Libraries
import os
import logging
import http.client as http_client

## Third-Party
import requests
import urllib3

## Modules
try:
    from .BuildingBlocks import BaseObject
except ImportError:
    from BuildingBlocks import BaseObject

class WebClient(BaseObject):

    #region: internal methods

    def __init__(self, loglevel='INFO'):
        ## Prepare object
        self._setProps()
        ## Configure logging
        if loglevel == 'DEBUG' or __code_debug__:
            self._setHTTPLogging()
        else:
            self.log = logging.getLogger(__name__)
        ## Call parent init
        super().__init__()

    """ Ensure keys are set to avoid throwing attributeError, also perform class init """
    def _setProps(self):
        self.is_valid = False
        self.tls_verify = True
        self.requestSession = requests.Session()
        none_keys = [
            'last_raw_request', 'last_prepared_request', 'last_response',
        ]
        for k in none_keys:
            setattr(self, k, None)

    def _setHTTPLogging(self):
        # Configure logging of http requests
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        self.log = logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger('requests.packages.urllib3')
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

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

    """ pretty print the request to stdout, called when raise_for_status occurs """
    def _pretty_print_POST(self, req):
        print('{}\n{}\r\n{}\r\n\r\n{}'.format(
            '-----------START-----------',
            req.method + ' ' + req.url,
            '\r\n'.join('{}: {}'.format(k, v) for k, v in headers.items()),
            req.body,
        ))

    #endregion: internal methods

    #region: private methods

    """ Stub request handler for GET """
    def _doGet(self, url, headers=None, params=None, data=None):
        return self._doRequest(url, 'GET', headers=headers, params=params, data=data)

    """ Stub request handler for POST """
    def _doPost(self, url, headers=None, params=None, data=None, json=None):
        return self._doRequest(url, 'POST', headers=headers, params=params, data=data, json=json)

    """ Stub request handler for DELETE """
    def _doDelete(self, url, headers=None, params=None, data=None):
        return self._doRequest(url, 'DELETE', headers=headers, params=params, data=data)

    """ Stub request handler for PUT """
    def _doPut(self, url, headers=None, params=None, data=None, json=None):
        return self._doRequest(url, 'PUT', headers=headers, params=params, data=data, json=json)

    """ Stub request handler for METHOD """
    def _doRequest(self, url=None, method=None, headers=None, params=None, data=None, json=None):
        prep = self._prepareRequest(url=url, method=method, headers=headers, params=params, data=data, json=json)
        rcode, resp = self._sendPreparedRequest(prep)
        return rcode, resp

    """ Log request object under a namespace within class storage """
    def _logRequest(self, namespace, obj):
        acceptable_namespaces = ['last_raw_request', 'last_prepared_request', 'last_response']
        if namespace not in acceptable_namespaces:
            raise ValueError('Error logging requst: invalid namespace: %s' % (str(namespace)))
        setattr(self, namespace, obj)

    """ Prepare a request, while logging details """
    def _prepareRequest(self, url=None, method=None, headers=None, params=None, data=None, json=None):
        ## Do checks
        if url is None:
            raise ValueError('URL must be set')
        if str(method).upper() not in self.acceptable_methods:
            raise ValueError('Cannot use HTTP Verb: %s' % (str(method)))
        ## Prepare a request
        self.last_build_request = requests.Request(method, url=url, headers=headers, params=params, data=data, json=json)
        ## Build with session data
        self.last_prepared_request = self.requestSession.prepare_request(self.last_build_request)

        ## Log incoming request
        self._logRequest(namespace='last_raw_request', obj=self.last_build_request)
        ## Log outgoing request
        self._logRequest(namespace='last_prepared_request', obj=self.last_prepared_request)
        ## Return prepared_request
        return self.last_prepared_request

    """ Send a prepared request, while logging details """
    def _sendPreparedRequest(self, prepared_request):
        try:
            ## Send request
            response = self.requestSession.send(prepared_request, verify=self.tls_bundle)

            ## Log response
            self._logRequest(namespace='last_response', obj=response)
            response.raise_for_status()

            ## Return on success
            return response.status_code, response

        except requests.exceptions.HTTPError as e:
            print('[!!] Caught HTTPError')
            print(e)
            self._pretty_print_POST(self.last_prepared_request)
            raise e
        except requests.exceptions.RequestException as e:
            print('[!!] Caught RequestException')
            print(e)
            self._pretty_print_POST(self.last_prepared_request)
            raise e


    #endregion: private methods

    #region: public methods

    #endregion: public methods

    #region: public interfaces
    #endregion: public interfaces

    #region: public interfaces


    #endregion: public interfaces

def demo():
    pass

def main():
    demo()

if __name__ == '__main__':
    main()
