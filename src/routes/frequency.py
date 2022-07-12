from fastapi import APIRouter, Depends, HTTPException
from src.classes.PrettyJSONResponse import PrettyJSONResponse
from src.dependencies.SharedEngine import SharedEngine

## Modules
from src.classes.Enumerations import frequency_tables
from src.classes.freq import FreqCounter
from src.classes.utils import log_exception

router = APIRouter()

@router.get("/frequency/{param}", tags=['Lookup Services'], response_class=PrettyJSONResponse)
async def calculate_frequency(param: str, table: frequency_tables = frequency_tables.default, se: SharedEngine = Depends(SharedEngine)):

    """
    Calculate the frequency score for some input using character pair frequency analysis:

    Lower scores are more likely to be high-entropy

    Two scores are returned
    - **average probability**
    - **word probability**

    Return Codes
    - 200: Success
    - 500: Freq table not loaded
    - 500: Unknown Error

    """
    try:
        if table == frequency_tables.domain:
            if se.freq.domain is not None:
                x,y = se.freq.domain.fc.probability(param)
            else:
                raise HTTPException(status_code=500, detail="freq::domain not loaded")
        else:
            if se.freq.default is not None:
                x,y = se.freq.default.fc.probability(param)
            else:
                raise HTTPException(status_code=500, detail="freq::default not loaded")
        return {
            "freq_score_avg": x,
            "freq_score_word": y,
        }
    except Exception as e:
        # Re-raise any HTTPExceptions
        if type(e) == HTTPException:
            raise e
        # Otherwise log it for review and return generic
        else:
            log_exception(e)
            raise HTTPException(status_code=500, detail="Internal Server Error")

