__code_desc__ = "An interface to the ThreatMiner API"
__code_debug__ = False
__code_version__ = 'v0.0.0'

## Standard Libraries
import ipaddress
from pprint import pprint
from urllib.parse import urljoin

## Third-Party
from ratelimit import limits#, RateLimitException

## Modules
try:
    from .WebClient import WebClient
except ImportError:
    from WebClient import WebClient

class ThreatMiner(WebClient):

    """
        Anything that raises NotImplementedError has either
        not been tested yet... or is unfinished
    """

    # rating limiting variables
    rate_limit_value = 10
    rate_limit_period = 60

    # flags for api
    DOMAIN_WHOIS = 1
    DOMAIN_PASV_DNS= 2
    DOMAIN_EXAMPLE_Q = 3
    DOMAIN_RELATED = 4
    DOMAIN_SUBDOM = 5
    DOMAIN_REPORT_TAG = 6
    IP_WHOIS = 1
    IP_PASV_DNS = 2
    IP_URIS = 3
    IP_RELATED = 4
    IP_SSLCERTS = 5
    IP_REPORT_TAG = 6
    SAMPLE_METADATA = 1
    SAMPLE_HTTP_TRAFFIC = 2
    SAMPLE_HOSTS = 3
    SAMPLE_MUTANTS = 4
    SAMPLE_REGISTRY_KEYS = 5
    SAMPLE_AV_DETECTIONS = 6
    SAMPLE_REPORT_TAG = 7
    IMPHASH_SAMPLES = 1
    IMPHASH_REPORT_TAG = 2
    SSDEEP_SAMPLES = 1
    SSDEEP_REPORT_TAG = 2
    SSL_HOSTS = 1
    SSL_REPORT_TAG = 2
    EMAIL_DOMAINS = 1
    AV_SAMPLES = 1
    AV_REPORT_TAG = 2

    #region: internal methods

    def __init__(self, loglevel='INFO'):
        self.base_url = 'https://api.threatminer.org/v2/'
        super().__init__()

    #endregion: internal methods

    #region: private methods
    @limits(calls=rate_limit_value, period=rate_limit_period)
    def _doQuery(self, url, params):
        return self._doGet(url=url, params=params)

    def _isIPAddress(self, i):
        try:
            _ = ipaddress.ip_address(i)
            return True
        except ValueError:
            return False

    #endregion: private methods

    #region: public methods

    def _queryDomain(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'domain.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        rcode, resp = self._doQuery(endpoint, payload)
        return rcode, resp

    def _queryIP(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        assert self._isIPAddress(q)
        stub = 'host.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        rcode, resp = self._doQuery(endpoint, payload)
        return rcode, resp
        raise NotImplementedError

    def _querySamples(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'sample.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        raise NotImplementedError

    def _queryIMPHash(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'imphash.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        raise NotImplementedError

    def _querySSDeep(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'ssdeep.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        raise NotImplementedError

    def _querySSL(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'ssl.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        raise NotImplementedError

    def _queryEmail(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'email.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        raise NotImplementedError

    def _queryAV(self, q=None, rt=None):
        assert q is not None
        assert rt is not None
        stub = 'av.php'
        endpoint = urljoin(self.base_url, stub)
        payload = {'q': q, 'rt': rt}
        raise NotImplementedError

    #endregion: public methods

    #region: public interfaces

    def queryDomainWhois(self, query):
        _, resp= self._queryDomain(q=query, rt=self.DOMAIN_WHOIS)
        return resp.json()

    def queryDomainPassiveDNS(self, query):
        _, resp= self._queryDomain(q=query, rt=self.DOMAIN_PASV_DNS)
        return resp.json()

    def queryDomainExampleQuery(self, query):
        _, resp= self._queryDomain(q=query, rt=self.DOMAIN_EXAMPLE_Q)
        return resp.json()

    def queryDomainRelatedSamples(self, query):
        _, resp= self._queryDomain(q=query, rt=self.DOMAIN_RELATED)
        return resp.json()

    def queryDomainSubDomains(self, query):
        _, resp= self._queryDomain(q=query, rt=self.DOMAIN_SUBDOM)
        return resp.json()

    def queryDomainReportTag(self, query):
        _, resp= self._queryDomain(q=query, rt=self.DOMAIN_REPORT_TAG)
        return resp.json()

    def queryIPWhois(self, query):
        _, resp= self._queryIP(q=query, rt=self.IP_WHOIS)
        return resp.json()

    def queryIPPassiveDNS(self, query):
        _, resp= self._queryIP(q=query, rt=self.IP_PASV_DNS)
        return resp.json()

    def queryIPURIS(self, query):
        _, resp= self._queryIP(q=query, rt=self.IP_URIS)
        return resp.json()

    def queryIPRelatedSamples(self, query):
        _, resp= self._queryIP(q=query, rt=self.IP_RELATED)
        return resp.json()

    def queryIPSSLCerts(self, query):
        _, resp= self._queryIP(q=query, rt=self.IP_SSLCERTS)
        return resp.json()

    def queryIPReportTag(self, query):
        _, resp= self._queryIP(q=query, rt=self.IP_REPORT_TAG)
        return resp.json()

    #endregion: public interfaces

def demo():
    url='vwrm.com'
    ip='8.8.8.8'
    t = ThreatMiner()

def main():
    demo()

if __name__ == '__main__':
    main()
