__code_project__ = 'QuickerAPI'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries

## Third Party libraries
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

def log_exception(e):
    # @todo: implement logging
    print(f"Caught Exception type({type(e)}) => {e}")


@app.on_event("startup")
async def main():
    """ On startup, load databases """
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


#region: routes

@app.get("/frequency/{param}")
async def calculate_frequency(param: str, table: frequency_tables = frequency_tables.default):
    """
    Calculate the frequency score for some input using character pair frequency analysis:

    Lower scores are more likely to be high-entropy

    Two scores are returned
    - **average probability**
    - **word probability**
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
    try:
        x, y = app.asn.lookup(ip_address)
        return {
            "asn": x,
            "bgp_prefix": y,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail="item not found")

#@app.get("/geoip/{param}")
#async def fetch_geoip(param: str):
#    pass

#@app.get("/alexa/{param}")
#async def fetch_alexa(param: str):
#    pass

#@app.get("/cisco/{param}")
#async def fetch_cisco(param: str):
#    pass

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
