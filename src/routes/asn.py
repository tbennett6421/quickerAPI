from fastapi import APIRouter, Depends, HTTPException
from src.classes.PrettyJSONResponse import PrettyJSONResponse
from src.dependencies.SharedEngine import SharedEngine

router = APIRouter()

@router.get("/asn/{ip_address}", summary="Fetch ASN", tags=['Lookup Services'], response_class=PrettyJSONResponse)
async def fetch_asn(ip_address: str, se: SharedEngine = Depends(SharedEngine)):
    """
    Return the ASN and BGP-Prefix of an ip address:

    Return Codes
    - 200: Success
    - 404: Not found
    - 500: ASN database is not loaded
    """
    if se.asn is not None:
        try:
            x, y = se.asn.lookup(ip_address)
            return {
                "asn": x,
                "bgp_prefix": y,
            }
        except ValueError as e:
            raise HTTPException(status_code=404, detail="item not found")
    else:
        raise HTTPException(status_code=500, detail="asn database not loaded")
