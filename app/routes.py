from flask import Blueprint, request
from markupsafe import escape
from .models import db, User, Post
from .security import require_jwt

api_bp = Blueprint("api", __name__)


@api_bp.get("/data")
@require_jwt
def get_data():
    users = User.query.order_by(User.id).all()
    return {
        "items": [
            {"id": u.id, "login": escape(u.login)}
            for u in users
        ]
    }, 200


@api_bp.get("/user")
@require_jwt
def list_users():
    users = User.query.order_by(User.id).all()
    return {"users": [{"id": u.id, "login": escape(u.login)} for u in users]}, 200


@api_bp.get("/user/<int:user_id>")
@require_jwt
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return {"id": user.id, "login": escape(user.login)}, 200


@api_bp.patch("/user/<int:user_id>")
@require_jwt
def patch_user(user_id):
    if int(request.user.get("sub")) != int(user_id):
        return {"error": "forbidden"}, 403

    data = request.get_json(force=True, silent=True) or {}
    new_login = (data.get("login") or "").strip()
    new_password = data.get("password") or ""

    user = User.query.get_or_404(user_id)

    if new_login:
        if User.query.filter(User.login == new_login, User.id != user_id).first():
            return {"error": "login already taken"}, 409
        user.login = new_login

    if new_password:
        import bcrypt
        if len(new_password) < 6:
            return {"error": "password too short"}, 400
        user.password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12)).decode()

    db.session.commit()
    return {"message": "updated"}, 200


@api_bp.delete("/user/<int:user_id>")
@require_jwt
def delete_user(user_id):
    if int(request.user.get("sub")) != int(user_id):
        return {"error": "forbidden"}, 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return {"message": "deleted"}, 200

@api_bp.post("/posts")
@require_jwt
def create_post():
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get("title") or "").strip()
    body = (data.get("body") or "").strip()
    if not title or not body:
        return {"error": "title and body required"}, 400
    post = Post(title=title, body=body)
    db.session.add(post)
    db.session.commit()
    return {"message": "created", "id": post.id}, 201