__code_project__ = 'threat-toolbox'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.2'

## Standard Libraries
import os, sys
from pprint import pprint as p

## Third Party libraries
from fastapi import FastAPI, HTTPException
from fastapi.middleware.gzip import GZipMiddleware

## Configure sys.path
abs = os.path.abspath(__file__)
pwd = os.path.dirname(abs)
ppwd = os.path.dirname(pwd)
sys.path.insert(0, pwd)         # prepend classes\ to syspath
sys.path.insert(0, ppwd)        # prepend src\ to syspath

## Modules
from src.classes.Enumerations import whois_method,whois_artifact
from src.classes.utils import isIPAddress
from src.classes.ApplicationInit import init
from src.routes import alexa,asn,cisco,frequency,hashes,meta
from src.classes.PrettyJSONResponse import PrettyJSONResponse

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
        "name": "Lookup Services",
        "description": "endpoints related to querying a resource for information.",
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
app.add_middleware(GZipMiddleware, minimum_size=1000)
routes_to_include = [alexa, asn, cisco, frequency, hashes, meta]
for i in routes_to_include:
    app.include_router(i.router)

@app.on_event("startup")
async def main():
    """ On startup, load components """
    init(app)

#region: routes
@app.get("/whois/{param}", response_class=PrettyJSONResponse)
async def fetch_whois(param: str, artifact_type: whois_artifact = whois_artifact.default, method: whois_method = whois_method.default):
    # @to-do: auto-detect artifact type
    # whois_method.whois is a online lookup from whois binary
    if method == whois_method.whois:
        if artifact_type == whois_artifact.ip:
            obj = app.ip_whois(param)
            rval = obj.lookup_rdap()
            return rval
        if artifact_type == whois_artifact.domain:
            rval = app.dns_whois(param)
            return rval
    if method == whois_method.threatminer:
        if artifact_type == whois_artifact.ip:
            return app.threatminer.queryIPWhois(param)
        elif artifact_type == whois_artifact.domain:
            return app.threatminer.queryDomainWhois(param)
        else:
            # attempt to guess at type
            raise HTTPException(status_code=501, detail="Not implemented yet")
    else:
        raise HTTPException(status_code=501, detail="Not implemented yet")

@app.get("/whois/ip/{param}", response_class=PrettyJSONResponse)
async def fetch_whois_ip(param: str, method: whois_method = None):
    if not isIPAddress(param):
        raise HTTPException(status_code=400, detail="Bad Request")
    else:
        if method == whois_method.threatminer:
            return app.threatminer.queryIPWhois(param)
        elif method == whois_method.whois:
            obj = app.ip_whois(param)
            rval = obj.lookup_rdap()
            return rval
        else:
            obj = app.ip_whois(param)
            rval = obj.lookup_rdap()
            return rval

# @app.get("/ip/{param}")
# async def query_x(param: str):
#     raise HTTPException(status_code=501, detail="Not implemented yet")
#     return {}

# @app.get("/domain/{param}")
# async def query_x(param: str):
#     raise HTTPException(status_code=501, detail="Not implemented yet")
#     return {}

#@app.get("/geoip/{param}")
#async def fetch_geoip(param: str):
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
