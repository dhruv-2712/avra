import os
from fastapi import Header, HTTPException


async def require_api_key(x_api_key: str = Header(default="")):
    key = os.getenv("SCAN_API_KEY", "")
    if key and x_api_key != key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
