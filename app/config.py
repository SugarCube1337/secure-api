import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(basedir, '..', 'app.db')}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ALG = "HS256"
    JWT_EXPIRES = timedelta(hours=12)
