import os
import pytest

from app import create_app
from app.models import db

class TestConfig:
    TESTING = True
    SECRET_KEY = "QO34NT5UU4509BG94"
    SQLALCHEMY_DATABASE_URI = "sqlite:///app.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALG = "HS256"

@pytest.fixture
def app():
    os.environ["SECRET_KEY"] = TestConfig.SECRET_KEY
    os.environ["DATABASE_URL"] = TestConfig.SQLALCHEMY_DATABASE_URI

    app = create_app()
    app.config.from_object(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_headers(client):
    """Регистрирует пользователя, логинится и возвращает заголовки с Bearer токеном."""
    r = client.post("/auth/register", json={"login": "alice", "password": "Str0ng_P@ss"})
    assert r.status_code in (200, 201, 409)  # 409 если перезапуск теста

    r = client.post("/auth/login", json={"login": "alice", "password": "Str0ng_P@ss"})
    assert r.status_code == 200
    token = r.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
