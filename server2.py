__code_project__ = 'threat-toolbox'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

## Standard Libraries
from pprint import pprint

## Third Party libraries
from fastapi import FastAPI

## Modules
from classes.funcs import md5,sha1,sha256

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


class Server2(FastAPI):
    def __init__(self) -> None:
        super().__init__(
            title=__code_project__,
            description=__code_desc__,
            version=__code_version__,
            openapi_tags=tags_metadata,
        )

        @self.get("/md5/{param}", tags=['Hash Generation'])
        async def calculate_md5(param: str):
            """ Calculate MD5 for a string """
            md = md5(param)
            return { "md5": md }
