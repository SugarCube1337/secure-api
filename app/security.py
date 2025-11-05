import os
import time
import jwt
from functools import wraps
from flask import request
from .config import Config


def create_jwt(claims: dict) -> str:
    now = int(time.time())
    payload = {
        **claims,
        "iat": now,
        "exp": now + int(Config.JWT_EXPIRES.total_seconds()),
    }
    secret = os.getenv("SECRET_KEY", Config.SECRET_KEY)
    return jwt.encode(payload, secret, algorithm=Config.JWT_ALG)


def require_jwt(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return {"error": "missing bearer token"}, 401
        token = auth.split(" ", 1)[1].strip()
        secret = os.getenv("SECRET_KEY", Config.SECRET_KEY)
        try:
            decoded = jwt.decode(token, secret, algorithms=[Config.JWT_ALG])
            request.user = decoded
        except jwt.ExpiredSignatureError:
            return {"error": "token expired"}, 401
        except jwt.InvalidTokenError:
            return {"error": "invalid token"}, 401
        return fn(*args, **kwargs)

    return wrapper
