__code_project__ = 'QuickerAPI'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries

## Third Party libraries
import pyasn
from fastapi import FastAPI

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


@app.on_event("startup")
async def main():
    """ On startup, load databases """
    app.freq = lambda: None
    app.freq.default = lambda: None
    app.freq.domain = lambda: None
    app.freq.default.fc = FreqCounter()
    app.freq.domain.fc = FreqCounter()
    app.freq.default.fc.load('resources/freqtable2018.freq')
    app.freq.domain.fc.load('resources/domain.freq')
    app.asn = pyasn.pyasn('resources/ipasn.dat')

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
    if table == frequency_tables.domain:
        x,y = app.freq.domain.fc.probability(param)
    else:
        x,y = app.freq.default.fc.probability(param)
    return {
        "freq_score_avg": x,
        "freq_score_word": y,
    }

#@app.get("/whois/{param}")
#async def fetch_whois(param: str):
#    pass

#@app.get("/asn/{param}")
#async def fetch_asn(param: str):
#    pass

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
