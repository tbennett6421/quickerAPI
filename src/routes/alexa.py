from fastapi import APIRouter, Depends, HTTPException
from src.classes.PrettyJSONResponse import PrettyJSONResponse
from src.dependencies.SharedEngine import SharedEngine

router = APIRouter()

@router.get("/alexa/{param}", tags=['Lookup Services'], response_class=PrettyJSONResponse)
async def fetch_alexa(param: str, se: SharedEngine = Depends(SharedEngine)):
    """
    Return the ranking of the input according to the alexa top 1 million records:

    Return Codes
    - 200: Success
    - 404: Not found
    - 500: Alexa database is not loaded
    """

    if se.alexa is not None:
        try:
            df = se.alexa
            capture = df.loc[df['domain'] == param]
            rval = int(capture['rank'].values[0])
            return {
                'alexa_score': rval
            }
        except IndexError:
            raise HTTPException(status_code=404, detail="item not found")
    else:
        raise HTTPException(status_code=500, detail="alexa db not loaded")
