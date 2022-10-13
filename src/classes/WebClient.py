__code_desc__ = "A class wrapping requests providing sessions and logging"
__code_debug__ = False
__code_version__ = 'v2.2.1'

## Standard Libraries
import logging
import copy
from pprint import pprint
from datetime import datetime
import http.client as http_client
try:
    # JSONDecodeError derives from ValueError in 3.5+; handle legacy python
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

## Third-Party
import requests
import urllib3

## Modules
try:
    from classes.Base import configureTLSValidation
    from classes.BuildingBlocks import BaseObject
except ImportError:
    from .Base import configureTLSValidation
    from .BuildingBlocks import BaseObject

class WebClient(BaseObject):
    """
        WebClient is intended to wrap the requests library and provide sessions,
        logging, and prepared handling of requests. You should subclass this module
        and implement your own calls on top of it.

        an example of this may look like this

        def authenticate(self, usernm, passwd):
            url = 'https://www.example.com/login.php'
            headers = { 'Content-Type': "application/x-www-form-urlencoded" }
            payload = {
                'username': self.username,
                'password': self.password,
            }
            rcode, resp = self._doPost(url=url, headers=headers, data=payload)
            rjsn = resp.json()
            token = rjsn['sessionKey']
            return token

        token = client.authenticate('something', 'something')

    """

    #region: internal methods

    def __init__(self, loglevel='INFO', disable_verification=False):
        ## Prepare object
        self._setProps()
        ## Configure logging
        if loglevel == 'DEBUG' or __code_debug__:
            self._setHTTPLogging()
        else:
            self.log = logging.getLogger(__name__)

        ## Disable TLS warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        ## Configure TLS
        self._configureTLSValidation(disable_verification=disable_verification)

        ## Configure self vars
        self.acceptable_methods = ['GET', 'POST', 'DELETE', 'PUT']
        self.sensitive_headers = []
        self.common_sensitive_headers = [
            'Authorization', 'iPlanetDirectoryPro',
            'X-OpenIDM-Password', 'X-OpenAM-Password'
        ]

        ## Call parent init
        super().__init__()

    """ Ensure keys are set to avoid throwing attributeError, also perform class init """
    def _setProps(self):
        """ Ensure keys are set to avoid throwing attributeError, also perform class init """
        try:
            super()._setProps()
        except AttributeError:
            pass
        self.is_valid = False
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

    """
        Attempt to detect and configure TLS cert checking, allow caller to override in cases
        where the TLS for a given system/service is self-signed.
    """
    def _configureTLSValidation(self, disable_verification=False):
        verify, tls_bundle = configureTLSValidation(disable_verification=disable_verification)
        self.verify = verify
        self.tls_bundle = tls_bundle
        return

    def _headers_to_string(self, headers):
        return '\r\n'.join('{}: {}'.format(k, v) for k, v in headers.items())

    """ deepcopy headers, redact sensitive, and return copy """
    def _redact_sensitive_headers(self, req_headers):
        # Use common sensitive headers if none have been provided.
        if len(self.sensitive_headers) == 0:
            sensitive = self.common_sensitive_headers
        else:
            sensitive = self.sensitive_headers

        try:
            headers = copy.deepcopy(req_headers)
            for item in sensitive:
                if item in headers:
                    headers[item] = "[REDACTED]"
            return headers
        # No sensitive_headers, return
        except AttributeError:
            return req_headers

    """ pretty print the request to stdout, called when raise_for_status occurs """
    def _pretty_print_web_trace(self):
        ret = {}
        try:
            print(" --- Last Raw Request ---")
            lpq = self.last_raw_request
            headers = self._redact_sensitive_headers(lpq.headers)
            try:
                body=lpq.body
            except AttributeError:
                body = ""

            lpq_payload = (
                '{method} {url}\r\n'
                '{headers}\r\n'
                '\r\n{body}'
            ).format(
                method = lpq.method, url = lpq.url,
                headers=self._headers_to_string(headers),
                body=body
            )
            ret['last_raw_request'] = lpq_payload
            print(lpq_payload)
            print()
        except AttributeError as e:
            msg = "Caught %s" % (e.__class__.__name__)
            self.log.error(msg)
            pprint(e)
            raise e
        except Exception as e:
            msg = "Caught %s" % (e.__class__.__name__)
            self.log.error(msg)
            pprint(e)
            raise e

        try:
            print(" --- Last Prepared Request ---")
            lpq = self.last_prepared_request
            headers = self._redact_sensitive_headers(lpq.headers)
            try:
                body=lpq.body
            except AttributeError:
                body = ""
            lpq_payload = (
                '{method} {url}\r\n'
                '{headers}\r\n'
                '\r\n{body}'
            ).format(
                method = lpq.method, url = lpq.url,
                headers=self._headers_to_string(headers),
                body=body
            )
            ret['last_prepared_request'] = lpq_payload
            print(lpq_payload)
            print()
        except AttributeError as e:
            msg = "Caught %s" % (e.__class__.__name__)
            self.log.error(msg)
            pprint(e)
            raise e
        except Exception as e:
            msg = "Caught %s" % (e.__class__.__name__)
            self.log.error(msg)
            pprint(e)
            raise e

        try:
            print(" --- Last Response ---")
            lr = self.last_response
            try:
                body = lr.json()
            except JSONDecodeError:
                body = lr.text
            headers = self._redact_sensitive_headers(lr.headers)
            lr_payload = (
                '[{status_code}] ({reason}) {url}\r\n'
                '{headers}\r\n'
                '\r\n{body}'
            ).format(
                status_code = lr.status_code, reason = lr.reason, url = lr.url,
                headers=self._headers_to_string(headers),
                body=body
            )
            ret['last_response'] = lr_payload
            print(lr_payload)
            print()
        except AttributeError as e:
            msg = "Caught %s" % (e.__class__.__name__)
            self.log.error(msg)
            msg = "Appears we did not get a response back from the remote endpoint."
            self.log.error(msg)
            pass
        except Exception as e:
            msg = "Caught %s" % (e.__class__.__name__)
            self.log.error(msg)
            pprint(e)
            raise e

        return ret

    def _getTS(format=None):
        assert format in ['utc', 'local']
        if format == 'utc':
            return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if format == 'local':
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _getTimeStampUTC(self):
        return self.getTS(format='utc')

    def _getTimeStampLocal(self):
        return self.getTS(format='local')

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
            raise ValueError('Error logging request: invalid namespace: %s' % (str(namespace)))
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
            print('[!!] Caught %s' % (type(e)))
            rval = self._pretty_print_web_trace()
            raise e
        except requests.exceptions.RequestException as e:
            print('[!!] Caught %s' % (type(e)))
            rval = self._pretty_print_web_trace()
            raise e

    #endregion: private methods

    #region: public methods

    """ Mimick datetime functions """
    def now(self):
        return self._getTimeStampLocal()

    """ Mimick datetime functions """
    def utcnow(self):
        return self._getTimeStampUTC()

    """ Mimick datetime functions """
    def utc(self):
        return self._getTimeStampUTC()

    #endregion: public methods

    #region: public interfaces

    def get(self, url, headers=None, params=None, data=None):
        return self._doGet(url, headers=headers, params=params, data=data)

    def post(self, url, headers=None, params=None, data=None, json=None):
        return self._doPost(url, headers=headers, params=params, data=data, json=json)

    def delete(self, url, headers=None, params=None, data=None):
        return self._doDelete(url, headers=headers, params=params, data=data)

    def put(self, url, headers=None, params=None, data=None, json=None):
        return self._doPut(url, headers=headers, params=params, data=data, json=json)

    def updateHeader(self, header, value):
        self.requestSession.headers.update({header: value})

    def setHeader(self, header, value):
        return self.updateHeader(header, value)

    def getHeader(self, header):
        try:
            return self.requestSession.headers[header]
        except Exception as e:
            msg = "Caught %s" % (e.__class__.__name__)
            print(msg)
            raise e

    #endregion: public interfaces

def demo():
    pass

def main():
    demo()

if __name__ == '__main__':
    main()
