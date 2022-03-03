__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries

## Third Party libraries
from fastapi import FastAPI

## Modules
from classes.funcs import md5,sha1,sha256

## run server with
## uvicorn main:app --reload
app = FastAPI()

@app.on_event("startup")
async def main():
    print('[*] started')

#region: routes


@app.get("/md5/{param}")
async def calculate_md5(param: str):
    md = md5(param)
    return { "md5": md }

@app.get("/sha1/{param}")
async def calculate_sha1(param: str):
    md = sha1(param)
    return { "sha1": md }

@app.get("/sha256/{param}")
async def calculate_sha256(param: str):
    md = sha256(param)
    return { "sha256": md }

@app.get("/hashes/{param}")
async def calculate_hashes(param: str):
    return {
        "md5": md5(param),
        "sha1": sha1(param),
        "sha256": sha256(param),
    }


#endregion: routes

#region: stubs


#endregion: stubs
