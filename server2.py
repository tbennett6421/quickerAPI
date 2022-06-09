from hashlib import md5

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

class CustomAPI(FastAPI):
    def __init__(self, title: str = "CustomAPI") -> None:
        super().__init__(title=title)

        @self.get("/md5/{param}", tags=['Hash Generation'])
        async def calculate_md5(param: str):
            """ Calculate MD5 for a string """
            md = md5(param)
            return { "md5": md }
