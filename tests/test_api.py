from markupsafe import escape

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}

def test_register_and_login_returns_jwt(client):
    r = client.post("/auth/register", json={"login": "bob", "password": "S3cPass!"})
    assert r.status_code in (200, 201, 409)

    r = client.post("/auth/login", json={"login": "bob", "password": "S3cPass!"})
    assert r.status_code == 200
    data = r.get_json()
    assert "access_token" in data and isinstance(data["access_token"], str) and len(data["access_token"]) > 10

def test_protected_requires_token(client):
    r = client.get("/api/data")
    assert r.status_code == 401
    assert r.get_json()["error"] in ("missing bearer token", "invalid token", "token expired")

def test_invalid_token_rejected(client):
    r = client.get("/api/data", headers={"Authorization": "Bearer not.a.real.token"})
    assert r.status_code == 401

def test_create_post_and_list_data_escaped(client, auth_headers):
    # создаём пост с потенциально опасным содержимым
    payload = {"title": "Hello <b>world</b>", "body": "Hi <script>alert(1)</script>"}
    r = client.post("/api/posts", json=payload, headers=auth_headers)
    assert r.status_code == 201
    post_id = r.get_json()["id"]
    assert isinstance(post_id, int)

    # получаем список (/api/data возвращает посты)
    r = client.get("/api/data", headers=auth_headers)
    assert r.status_code == 200
    items = r.get_json()["items"]
    assert any(i["id"] == post_id for i in items)

    # проверяем, что спецсимволы экранированы (XSS mitigation)
    found = next(i for i in items if i["id"] == post_id)
    assert found["title"] == escape(payload["title"])
    assert found["body"] == escape(payload["body"])
