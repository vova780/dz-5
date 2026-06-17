import copy
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from jose import jwt
import main
from main import ALGORITHM, SECRET_KEY, app

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    snapshot = copy.deepcopy(main.fake_users_db)
    yield
    main.fake_users_db.clear()
    main.fake_users_db.update(snapshot)
    main.token_blacklist.clear()

def register_user(username="testuser", email="test@example.com", password="securepass123"):
    return client.post(
        "/register",
        json={"username": username, "email": email, "password": password},
    )

def login_user(username="testuser", password="securepass123"):
    return client.post("/login", data={"username": username, "password": password})

def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}

def test_register_success():
    response = register_user()
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "testuser"
    assert body["email"] == "test@example.com"
    assert body["role"] == "user"
    assert "password" not in body

def test_register_duplicate_username_returns_400():
    register_user()
    response = register_user()
    assert response.status_code == 400

def test_login_success_returns_tokens():
    register_user()
    response = login_user()
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"

def test_login_wrong_password_returns_401():
    register_user()
    response = login_user(password="wrongpassword")
    assert response.status_code == 401

def test_profile_with_valid_token():
    register_user()
    token = login_user().json()["access_token"]
    response = client.get("/profile", headers=auth_header(token))
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

def test_profile_without_token_returns_401():
    response = client.get("/profile")
    assert response.status_code == 401

def test_change_password_then_relogin_with_new_password():
    register_user()
    token = login_user().json()["access_token"]

    response = client.post(
        "/change-password",
        json={"old_password": "securepass123", "new_password": "newsecurepass456"},
        headers=auth_header(token),
    )
    assert response.status_code == 200

    old_login = login_user(password="securepass123")
    assert old_login.status_code == 401

    new_login = login_user(password="newsecurepass456")
    assert new_login.status_code == 200

def test_expired_access_token_rejected():
    register_user()
    expired_payload = {
        "sub": "testuser",
        "type": "access",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }
    expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)
    response = client.get("/profile", headers=auth_header(expired_token))
    assert response.status_code == 401

def test_refresh_token_returns_new_access_token():
    register_user()
    refresh_token = login_user().json()["refresh_token"]
    response = client.post("/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_refresh_with_access_token_is_rejected():
    register_user()
    access_token = login_user().json()["access_token"]
    response = client.post("/refresh", json={"refresh_token": access_token})
    assert response.status_code == 401

def test_logout_blacklists_token():
    register_user()
    token = login_user().json()["access_token"]
    headers = auth_header(token)

    logout_response = client.post("/logout", headers=headers)
    assert logout_response.status_code == 200

    profile_response = client.get("/profile", headers=headers)
    assert profile_response.status_code == 401

def test_regular_user_cannot_access_admin_endpoint():
    register_user()
    token = login_user().json()["access_token"]
    response = client.get("/admin/users", headers=auth_header(token))
    assert response.status_code == 403


def test_admin_can_access_admin_endpoint():
    token = login_user(username="admin", password="admin123").json()["access_token"]
    response = client.get("/admin/users", headers=auth_header(token))
    assert response.status_code == 200
    usernames = [u["username"] for u in response.json()]
    assert "admin" in usernames

def test_delete_account_requires_correct_password():
    register_user()
    token = login_user().json()["access_token"]
    response = client.request(
        "DELETE",
        "/profile",
        json={"password": "wrongpassword"},
        headers=auth_header(token),
    )
    assert response.status_code == 401

def test_delete_account_success_removes_user():
    register_user()
    token = login_user().json()["access_token"]
    response = client.request(
        "DELETE",
        "/profile",
        json={"password": "securepass123"},
        headers=auth_header(token),
    )
    assert response.status_code == 200

    relogin = login_user()
    assert relogin.status_code == 401