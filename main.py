__code_project__ = 'QuickerAPI'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries

## Third Party libraries
import pandas as pd
from pyasn import pyasn
from fastapi import FastAPI, HTTPException

## Modules
from classes.freq import FreqCounter
from classes.funcs import md5,sha1,sha256
from classes.Enumerations import frequency_tables

## run server with
## uvicorn main:app --reload
app = FastAPI(
    title=__code_project__,
    description=__code_desc__,
    version=__code_version__,
)

def is_none(x):
    if isinstance(x, type(None)):
        return True
    else:
        return False

def is_service_alive(x):
    x = is_none(x)
    if x:
        return False
    else:
        return True

def log_health(app):
    print("===Service Health===")
    print(f"freq::default  => {is_service_alive(app.freq.default)}")
    print(f"freq::domain   => {is_service_alive(app.freq.domain)}")
    print(f"asn            => {is_service_alive(app.asn)}")
    print(f"alexa          => {is_service_alive(app.alexa)}")
    print(f"cisco          => {is_service_alive(app.cisco)}")

def log_exception(e):
    # @todo: implement logging
    print(f"Caught Exception type({type(e)}) => {e}")

def load_1m_list(filename):
    data = pd.read_csv(filename, names=['rank', 'domain'])
    return data

def load_alexa(filename):
    try:
        alexa = load_1m_list(filename)
        return alexa
    except FileNotFoundError as e:
        log_exception(e)
        return None
    except Exception as e:
        log_exception(e)

def load_cisco(filename):
    try:
        cisco = load_1m_list(filename)
        return cisco
    except FileNotFoundError as e:
        log_exception(e)
        return None
    except Exception as e:
        log_exception(e)

@app.on_event("startup")
async def main():
    """ On startup, load databases """
    ## Configure andas display
    pd.set_option('display.max_rows', 5)
    pd.set_option('display.max_columns', 5)
    pd.set_option('display.width', 1000)
    pd.set_option('display.colheader_justify', 'center')
    pd.set_option('display.precision', 3)

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

#@app.get("/whois/{param}")
#async def fetch_whois(param: str):
#    pass

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
#    pass

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
#     return {
#         "md5": md5(param),
#         "sha1": sha1(param),
#         "sha256": sha256(param),
#     }

# @app.get("/domain/{param}")
# async def query_x(param: str):
#     return {
#         "md5": md5(param),
#         "sha1": sha1(param),
#         "sha256": sha256(param),
#     }

#@app.get("/threat/{param}")
#async def query_threathunter(param: str):
#    pass

#endregion: routes

#region: stubs

@app.get("/entropy/{param}")
async def calculate_entropy(param: str):
    return await calculate_frequency(param)

#endregion: stubs
