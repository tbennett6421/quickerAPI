__code_project__ = 'threat-toolbox'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries
from pprint import pprint

## Third Party libraries
import pandas as pd
from fastapi import FastAPI, HTTPException
from pyasn import pyasn
from whois import whois
from ipwhois import IPWhois

## Modules
from src.classes.ThreatMiner import ThreatMiner
from src.classes.Enumerations import frequency_tables,whois_method,whois_artifact
from src.classes.freq import FreqCounter
from src.classes.funcs import md5,sha1,sha256
from src.classes.utils import log_health,log_exception,load_alexa,load_cisco
#from routes.routes import list_services as ls

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


@app.get("/alexa/{param}")
async def fetch_alexa(param: str):
    """
    Return the ranking of the input according to the alexa top 1 million records:

    Return Codes
    - 200: Success
    - 404: Not found
    - 500: Alexa database is not loaded
    """

    if app.alexa is not None:
        try:
            df = app.alexa
            capture = df.loc[df['domain'] == param]
            rval = int(capture['rank'].values[0])
            return {
                'alexa_score': rval
            }
        except IndexError:
            raise HTTPException(status_code=404, detail="item not found")
    else:
        raise HTTPException(status_code=500, detail="alexa not loaded")

@app.get("/cisco/{param}")
async def fetch_cisco(param: str):
    """
    Return the ranking of the input according to the cisco umbrella top 1 million records:

    Return Codes
    - 200: Success
    - 404: Not found
    - 500: Cisco database is not loaded
    """

    if app.cisco is not None:
        try:
            df = app.cisco
            capture = df.loc[df['domain'] == param]
            rval = int(capture['rank'].values[0])
            return {
                'cisco_score': rval
            }
        except IndexError:
            raise HTTPException(status_code=404, detail="item not found")
    else:
        raise HTTPException(status_code=500, detail="cisco umbrella not loaded")


@app.get("/md5/{param}", tags=['Hash Generation'])
async def calculate_md5(param: str):
    """ Calculate MD5 for a string """
    md = md5(param)
    return { "md5": md }

@app.get("/sha1/{param}", tags=['Hash Generation'])
async def calculate_sha1(param: str):
    """ Calculate SHA1 for a string """
    md = sha1(param)
    return { "sha1": md }

@app.get("/sha256/{param}", tags=['Hash Generation'])
async def calculate_sha256(param: str):
    """ Calculate SHA256 for a string """
    md = sha256(param)
    return { "sha256": md }

@app.get("/hashes/{param}", tags=['Hash Generation'])
async def calculate_hashes(param: str):
    """ Calculate all message digests supported for a string """
    return {
        "md5": md5(param),
        "sha1": sha1(param),
        "sha256": sha256(param),
    }

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
