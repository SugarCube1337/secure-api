from flask import Blueprint, request
from .models import db, User
from .security import create_jwt
import bcrypt

auth_bp = Blueprint("auth", __name__)

@auth_bp.post("/register")
def register():
    data = request.get_json(force=True, silent=True) or {}
    login = (data.get("login") or "").strip()
    password = data.get("password") or ""
    if not login or not password:
        return {"error": "login and password required"}, 400

    if User.query.filter_by(login=login).first():
        return {"error": "login already exists"}, 409

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    user = User(login=login, password_hash=pw_hash)
    db.session.add(user)
    db.session.commit()
    return {"message": "registered"}, 201

@auth_bp.post("/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    login = (data.get("login") or "").strip()
    password = data.get("password") or ""
    user = User.query.filter_by(login=login).first()
    if not user:
        return {"error": "invalid credentials"}, 401
    if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return {"error": "invalid credentials"}, 401
    token = create_jwt({"sub": user.id, "login": user.login})
    return {"access_token": token}, 200
