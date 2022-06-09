__code_project__ = 'threat-toolbox'
__code_desc__ = "A POC/Learning exercise with FastAPI"
__code_version__ = 'v0.0.1'

from fastapi import FastAPI

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

@app.get("/")
async def read_main():
    return {"msg": "Hello World"}
