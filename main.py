__code_project__ = 'threat-toolbox'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries
from pprint import pprint

## Third Party libraries
import pandas as pd
from fastapi import FastAPI
from pyasn import pyasn
from whois import whois
from ipwhois import IPWhois

## Modules
from classes.ThreatMiner import ThreatMiner
from classes.Enumerations import frequency_tables,whois_method,whois_artifact
from classes.freq import FreqCounter
from classes.funcs import md5,sha1,sha256
from classes.utils import log_health,log_exception,load_alexa,load_cisco

tags_metadata = [
    {
        "name": "Health",
        "description": "health checks for this node.",
    },
    {
        "name": "Hash Generation",
        "description": "endpoints related to generating hashes against their arguments.",
    },
    {
        "name": "default",
        "description": "uncategorized endpoints.",
    },
    # {
    #     "name": "whois",
    #     "description": "Whois related endpoints.",
    # },
]

app = FastAPI(
    title=__code_project__,
    description=__code_desc__,
    version=__code_version__,
    openapi_tags=tags_metadata,
)

@app.on_event("startup")
async def main():
    """ On startup, load components """
    ## Configure pandas display
    pd.set_option('display.max_rows', 5)
    pd.set_option('display.max_columns', 5)
    pd.set_option('display.width', 1000)
    pd.set_option('display.colheader_justify', 'center')
    pd.set_option('display.precision', 3)

    # load database services
    app.freq = lambda: None
    app.freq.default = lambda: None
    app.freq.domain = lambda: None
    app.freq.default.fc = FreqCounter()
    app.freq.domain.fc = FreqCounter()
    try:
        app.freq.default.fc.load('resources/freqtable2018.freq')
    except (FileNotFoundError,OSError,NameError) as e:
        app.freq.default = None
    try:
        app.freq.domain.fc.load('resources/domain.freq')
    except (FileNotFoundError,OSError,NameError) as e:
        app.freq.domain = None
    try:
        app.asn = pyasn('resources/ipasn.dat')
    except (FileNotFoundError,OSError,NameError) as e:
        app.asn = None
    try:
        app.alexa = load_alexa('resources/top-1m-alexa.csv')
    except (FileNotFoundError,OSError,NameError) as e:
        app.alexa = None
    try:
        app.cisco = load_cisco('resources/top-1m-cisco.csv')
    except (FileNotFoundError,OSError,NameError) as e:
        app.cisco = None

    # Instantiate network services
    try:
        app.dns_whois = whois
    except (OSError,NameError) as e:
        app.dns_whois = None
        raise e
    try:
        app.ip_whois = IPWhois
    except (OSError,NameError) as e:
        app.ip_whois = None
        raise e

    # Instantiate api services
    app.threatminer = ThreatMiner()

    # finished loading; dump services to stdout
    app.health = log_health(app)

#region: routes

@app.get("/")
async def read_main():
    return {"msg": "Hello World"}

@app.get("/health/", tags=['Health'])
async def list_services():
    """
    List all services available on this node:

    At this time health is a placeholder for /services/. Health may be reused in the future for node statistics.

    Examples of future uses include
    * cpu usage
    * memory usage
    * cache usage
    * load perc
    * average response time
    * errors, success

    If you want to know about services available for the purposes of tailoring queries, you should use /services/
    """
    return app.health.items()

@app.get("/services/", tags=['Health'])
async def list_services():
    """ List all services available on this node. """
    return app.health.items()


#endregion: routes
