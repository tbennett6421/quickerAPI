__code_project__ = 'QuickerAPI'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries
from pprint import pprint

## Third Party libraries
import pandas as pd
from pyasn import pyasn
from fastapi import FastAPI, HTTPException
from whois import whois
from ipwhois import IPWhois

## Modules
from classes.ThreatMiner import ThreatMiner
from classes.Enumerations import frequency_tables,whois_method,whois_artifact
from classes.freq import FreqCounter
from classes.funcs import md5,sha1,sha256
from classes.utils import log_health,log_exception,load_alexa,load_cisco

app = FastAPI(
    title=__code_project__,
    description=__code_desc__,
    version=__code_version__,
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
    except (FileNotFoundError,OSError) as e:
        app.freq.default = None
    try:
        app.freq.domain.fc.load('resources/domain.freq')
    except (FileNotFoundError,OSError) as e:
        app.freq.domain = None
    try:
        app.asn = pyasn('resources/ipasn.dat')
    except (FileNotFoundError,OSError) as e:
        app.asn = None
    try:
        app.alexa = load_alexa('resources/top-1m-alexa.csv')
    except (FileNotFoundError,OSError) as e:
        app.alexa = None
    try:
        app.cisco = load_cisco('resources/top-1m-cisco.csv')
    except (FileNotFoundError,OSError) as e:
        app.cisco = None

    # Instantiate network services
    app.dns_whois = whois
    app.ip_whois = IPWhois

    # Instantiate api services
    app.threatminer = ThreatMiner()

    # finished loading; dump services to stdout
    log_health(app)

#region: routes

@app.get("/frequency/{param}")
async def calculate_frequency(param: str, table: frequency_tables = frequency_tables.default):
    """
    Calculate the frequency score for some input using character pair frequency analysis:

    Lower scores are more likely to be high-entropy

    Two scores are returned
    - **average probability**
    - **word probability**

    Return Codes
    - 200: Success
    - 500: Freq table not loaded
    - 500: Unknown Error

    """
    try:
        if table == frequency_tables.domain:
            if app.freq.domain is not None:
                x,y = app.freq.domain.fc.probability(param)
            else:
                raise HTTPException(status_code=500, detail="freq::domain not loaded")
        else:
            if app.freq.default is not None:
                x,y = app.freq.default.fc.probability(param)
            else:
                raise HTTPException(status_code=500, detail="freq::default not loaded")
        return {
            "freq_score_avg": x,
            "freq_score_word": y,
        }
    except Exception as e:
        # Re-raise any HTTPExceptions
        if type(e) == HTTPException:
            raise e
        # Otherwise log it for review and return generic
        else:
            log_exception(e)
            raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/whois/{param}")
async def fetch_whois(q: str, artifact_type: whois_artifact = whois_artifact.default, method: whois_method = whois_method.default):
    # @to-do: auto-detect artifact type
    # whois_method.whois is a online lookup from whois binary
    if method == whois_method.whois:
        if artifact_type == whois_artifact.ip:
            obj = app.ip_whois(q)
            rval = obj.lookup_rdap()
            return rval
        if artifact_type == whois_artifact.domain:
            rval = app.dns_whois(q)
            return rval
    if method == whois_method.threatminer:
        if artifact_type == whois_artifact.ip:
            return app.threatminer.queryIPWhois(q)
        elif artifact_type == whois_artifact.domain:
            return app.threatminer.queryDomainWhois(q)
        else:
            # attempt to guess at type
            raise HTTPException(status_code=501, detail="Not implemented yet")
    else:
        raise HTTPException(status_code=501, detail="Not implemented yet")

@app.get("/asn/{ip_address}", summary="Fetch ASN")
async def fetch_asn(ip_address: str):
    """
    Return the ASN and BGP-Prefix of an ip address:

    Return Codes
    - 200: Success
    - 404: Not found
    - 500: ASN database is not loaded
    """
    if app.asn is not None:
        try:
            x, y = app.asn.lookup(ip_address)
            return {
                "asn": x,
                "bgp_prefix": y,
            }
        except ValueError as e:
            raise HTTPException(status_code=404, detail="item not found")
    else:
        raise HTTPException(status_code=500, detail="asn database not loaded")

#@app.get("/geoip/{param}")
#async def fetch_geoip(param: str):
#     raise HTTPException(status_code=501, detail="Not implemented yet")
#     return {}

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

@app.get("/md5/{param}")
async def calculate_md5(param: str):
    """ Calculate MD5 for a string """
    md = md5(param)
    return { "md5": md }

@app.get("/sha1/{param}")
async def calculate_sha1(param: str):
    """ Calculate SHA1 for a string """
    md = sha1(param)
    return { "sha1": md }

@app.get("/sha256/{param}")
async def calculate_sha256(param: str):
    """ Calculate SHA256 for a string """
    md = sha256(param)
    return { "sha256": md }

@app.get("/hashes/{param}")
async def calculate_hashes(param: str):
    """ Calculate all message digests supported for a string """
    return {
        "md5": md5(param),
        "sha1": sha1(param),
        "sha256": sha256(param),
    }

# @app.get("/ip/{param}")
# async def query_x(param: str):
#     raise HTTPException(status_code=501, detail="Not implemented yet")
#     return {}

# @app.get("/domain/{param}")
# async def query_x(param: str):
#     raise HTTPException(status_code=501, detail="Not implemented yet")
#     return {}

#@app.get("/threat/{param}")
#async def query_threathunter(param: str):
#     raise HTTPException(status_code=501, detail="Not implemented yet")
#     return {}

#endregion: routes

#region: stubs

#@app.get("/entropy/{param}")
#async def calculate_entropy(param: str):
#    return await calculate_frequency(param)

#endregion: stubs
