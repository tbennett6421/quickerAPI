__code_project__ = 'QuickerAPI'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries

## Third Party libraries
from fastapi import FastAPI

## Modules
from classes.freq import FreqCounter
from classes.funcs import md5,sha1,sha256

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
    app.fc = FreqCounter()
    app.fc.load('resources/freqtable2018.freq')

#region: routes

@app.get("/frequency/{param}")
async def calculate_frequency(param: str):
    x,y = app.fc.probability(param)
    return {
        "freq_score_1": x,
        "freq_score_2": y,
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

@app.get("/md5/{param}", summary="Calculate MD5 for a string")
async def calculate_md5(param: str):
    md = md5(param)
    return { "md5": md }

@app.get("/sha1/{param}", summary="Calculate SHA1 for a string")
async def calculate_sha1(param: str):
    md = sha1(param)
    return { "sha1": md }

@app.get("/sha256/{param}", summary="Calculate SHA256 for a string")
async def calculate_sha256(param: str):
    md = sha256(param)
    return { "sha256": md }

@app.get("/hashes/{param}", summary="Calculate all message digests supported for a string")
async def calculate_hashes(param: str):
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
