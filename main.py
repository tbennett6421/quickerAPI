__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries

## Third Party libraries
from fastapi import FastAPI

## Modules

## run server with
## uvicorn main:app --reload
app = FastAPI()

@app.on_event("startup")
async def main():
    print('[*] started')

#region: routes


#endregion: routes

#region: stubs


#endregion: stubs
