"""
Auth endpoint tests.

The DB is fully mocked; we control what `query().filter().first()` returns
to simulate existing / non-existing users.

Password hashing (passlib/bcrypt) is mocked because the local environment has
a bcrypt version that is incompatible with passlib. The hash/verify logic is
unit-tested separately in test_auth_service.py.
"""
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from apps.api.models.user import UserStatus


_FAKE_HASH = "$2b$12$fakehashforteststhatisnotrealatall00000000000000000000"


def _mock_user(
    email: str = "test@example.com",
    password_hash: str = _FAKE_HASH,
) -> MagicMock:
    u = MagicMock()
    u.id = uuid.uuid4()
    u.email = email
    u.name = "Test User"
    u.password_hash = password_hash
    u.status = UserStatus.active
    u.avatar_url = None
    u.token_version = 1
    u.created_at = datetime.now(timezone.utc)
    u.deleted_at = None
    return u


# Patch bcrypt hashing so tests don't depend on the local bcrypt installation.
_HASH_PATCH = "apps.api.routers.auth.hash_password"
_VERIFY_PATCH = "apps.api.routers.auth.verify_password"


def test_register_success(client, mock_db):
    """POST /auth/register — happy path creates a user and returns 201."""
    mock_db.first.return_value = None  # no duplicate email

    def _refresh_side_effect(obj):
        obj.id = uuid.uuid4()
        obj.created_at = datetime.now(timezone.utc)
        obj.deleted_at = None
        obj.avatar_url = None
        obj.status = UserStatus.active
        obj.is_superadmin = False
        obj.email_verified = False
        obj.preferences = {}
        obj.invite_token = None

    mock_db.refresh.side_effect = _refresh_side_effect

    with patch(_HASH_PATCH, return_value=_FAKE_HASH):
        resp = client.post(
            "/auth/register",
            json={"email": "newuser@example.com", "name": "New User", "password": "securepassword"},
        )

    assert resp.status_code == 201
    assert resp.json()["email"] == "newuser@example.com"


def test_register_duplicate_email(client, mock_db):
    """POST /auth/register — returns 400 when email already exists."""
    existing = _mock_user("dup@example.com")
    mock_db.first.return_value = existing

    with patch(_HASH_PATCH, return_value=_FAKE_HASH):
        resp = client.post(
            "/auth/register",
            json={"email": "dup@example.com", "name": "A", "password": "pw123456"},
        )

    assert resp.status_code == 400


def test_login_success(client, mock_db):
    """POST /auth/login — happy path returns access_token."""
    user = _mock_user("login@example.com")
    mock_db.first.return_value = user

    with patch(_VERIFY_PATCH, return_value=True):
        resp = client.post(
            "/auth/login",
            json={"email": "login@example.com", "password": "pw123456"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_wrong_password(client, mock_db):
    """POST /auth/login — 401 on wrong password."""
    user = _mock_user("wp@example.com")
    mock_db.first.return_value = user

    with patch(_VERIFY_PATCH, return_value=False):
        resp = client.post(
            "/auth/login",
            json={"email": "wp@example.com", "password": "wrong"},
        )

    assert resp.status_code == 401


def test_login_nonexistent_user(client, mock_db):
    """POST /auth/login — 401 when user not found."""
    mock_db.first.return_value = None

    resp = client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "anypassword"},
    )
    assert resp.status_code == 401


def test_get_me(client, auth_headers, test_user):
    """GET /auth/me — returns current user profile."""
    resp = client.get("/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["email"] == test_user.email


def test_refresh_token(client, mock_db):
    """POST /auth/refresh — valid refresh token returns new access_token."""
    from apps.api.services.auth_service import create_refresh_token

    user = _mock_user("ref@example.com")
    refresh = create_refresh_token(str(user.id))
    mock_db.first.return_value = user

    resp = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_refresh_token_invalid(client, mock_db):
    """POST /auth/refresh — bad token returns 401."""
    resp = client.post("/auth/refresh", json={"refresh_token": "not-a-valid-token"})
    assert resp.status_code == 401


def test_get_me_no_auth(client):
    """GET /auth/me without token should return 401 or 403 (no bearer scheme)."""
    resp = client.get("/auth/me")
    assert resp.status_code in (401, 403)

def test_change_password_invalid_length(client, auth_headers):
    """Test that passwords under 8 characters are rejected by Pydantic."""
    payload = {
        "current_password": "ValidPassword123!",
        "new_password": "short" # 5 characters
    }
    
    response = client.patch("/auth/change-password", json=payload, headers=auth_headers)
    
    assert response.status_code == 422
    assert "new_password" in response.text

def test_refresh_token_rejected_after_password_change(client, mock_db):
    """Test that an old refresh token is rejected if the token_version has incremented."""
    from apps.api.services.auth_service import create_refresh_token
    
    # 1. Use the file's mock helper, but simulate a password change by bumping the version to 2
    mock_user = _mock_user("test@example.com")
    mock_user.token_version = 2 
    
    # Configure the mock_db to return this user
    mock_db.first.return_value = mock_user

    # 2. Create a "stolen" refresh token that was minted when the version was 1
    stolen_token = create_refresh_token(str(mock_user.id), token_version=1)

    # 3. Attempt to refresh the session
    response = client.post("/auth/refresh", json={"refresh_token": stolen_token})
    
    # 4. Assert the request is blocked
    assert response.status_code == 401
    assert response.json()["detail"] == "Session expired, please log in again"

def test_refresh_token_legacy_token_accepted(client, mock_db):
    """Test that a token without a 'ver' claim is treated as version 1 and accepted."""
    from apps.api.config import settings
    from jose import jwt
    
    mock_user = _mock_user("legacy@example.com")
    mock_user.token_version = 1
    mock_db.first.return_value = mock_user
    
    # Manually mint a JWT that completely lacks the "ver" claim
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    legacy_token = jwt.encode({"sub": str(mock_user.id), "type": "refresh", "exp": expire}, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    
    response = client.post("/auth/refresh", json={"refresh_token": legacy_token})
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_change_password_increments_version(client, auth_headers, test_user, mock_db):
    """Test that changing password bumps token_version and returns fresh tokens."""
    
    # Explicitly set the token_version so the endpoint doesn't crash on `None += 1`
    test_user.token_version = 1
    mock_db.commit()
    mock_db.refresh(test_user)
    
    initial_version = test_user.token_version
    
    with patch("apps.api.routers.auth.verify_password", return_value=True), \
         patch("apps.api.routers.auth.hash_password", return_value=_FAKE_HASH):
        
        payload = {
            "current_password": "AnyOldPassword123!",
            "new_password": "NewValidPassword123!"
        }
        response = client.patch("/auth/change-password", json=payload, headers=auth_headers)
        
        # If it still fails, this will print the actual error to the console
        if response.status_code == 500:
            print(f"500 ERROR: {response.text}")
            
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        
        mock_db.refresh(test_user)
        assert test_user.token_version == initial_version + 1
