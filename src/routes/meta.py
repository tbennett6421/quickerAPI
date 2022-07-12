from fastapi import APIRouter, Depends
from src.classes.PrettyJSONResponse import PrettyJSONResponse
from src.dependencies.SharedEngine import SharedEngine

""" Contains routes relating to self """
router = APIRouter()

@router.get("/", response_class=PrettyJSONResponse)
async def read_main():
    return {"msg": "Hello World"}

@router.get("/health/", tags=['Health'], response_class=PrettyJSONResponse)
async def list_services(se: SharedEngine = Depends(SharedEngine)):

    """
    List all services available on this node:

    At this time health is a placeholder for /services/. Health may be reused in the future for node statistics.

    Examples of future uses include
    * cpu usage
    * memory usage
    * cache usage
    * load percentage
    * average response time
    * errors, success

    If you want to know about services available for the purposes of tailoring queries, you should use /services/
    """
    return se.health.items()

@router.get("/services/", tags=['Health'], response_class=PrettyJSONResponse)
async def list_services(se: SharedEngine = Depends(SharedEngine)):
    """ List all services available on this node. """
    return se.health.items()

# @app.get("/services/", tags=['health'])
# async def list_services():
#     """ List all services available on this node. """
#     return await ls(app)
