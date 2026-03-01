from typing import Annotated, Any

from fastapi import FastAPI
from fastapi.params import Depends

from fastapi_sample.auth import verify_token

app = FastAPI()


@app.get("/")
def read_root(claims: Annotated[dict[str, Any], Depends(verify_token)]):
    return {"Hello": "World"}
