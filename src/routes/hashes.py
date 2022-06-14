from fastapi import APIRouter
from src.classes.funcs import md5,sha1,sha256

router = APIRouter()

@router.get("/md5/{param}", tags=['Hash Generation'])
async def calculate_md5(param: str):
    """ Calculate MD5 for a string """
    md = md5(param)
    return { "md5": md }

@router.get("/sha1/{param}", tags=['Hash Generation'])
async def calculate_sha1(param: str):
    """ Calculate SHA1 for a string """
    md = sha1(param)
    return { "sha1": md }

@router.get("/sha256/{param}", tags=['Hash Generation'])
async def calculate_sha256(param: str):
    """ Calculate SHA256 for a string """
    md = sha256(param)
    return { "sha256": md }

@router.get("/hashes/{param}", tags=['Hash Generation'])
async def calculate_hashes(param: str):
    """ Calculate all message digests supported for a string """
    return {
        "md5": md5(param),
        "sha1": sha1(param),
        "sha256": sha256(param),
    }
