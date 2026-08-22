"""
Auth tests — specifically designed to catch the two real vulnerabilities found
earlier in this project:
1. SECRET_KEY had a hardcoded default fallback (os.getenv(..., "sentinel-super-secret-key-change-me"))
2. create_default_user.py had a hardcoded password ("admin") and no env-var gate

These tests verify both fixes hold. If either regression is introduced, these fail.
"""
import pytest
import os
from unittest.mock import patch, MagicMock


class TestSecretKeyHardening:
    """Test that SECRET_KEY is truly required — no default fallback allowed."""

    def test_secret_key_required_at_import(self):
        """auth.py must raise KeyError if SECRET_KEY is not in the environment."""
        import importlib
        import sys

        # Remove the module if already cached so we get a fresh import
        if 'auth' in sys.modules:
            del sys.modules['auth']

        # Ensure SECRET_KEY is NOT in env
        env_without_key = {k: v for k, v in os.environ.items() if k != 'SECRET_KEY'}
        with patch.dict(os.environ, env_without_key, clear=True):
            with pytest.raises(KeyError):
                import auth  # noqa: F401

    def test_secret_key_used_when_present(self):
        """auth.py loads cleanly when SECRET_KEY is set."""
        import sys
        if 'auth' in sys.modules:
            del sys.modules['auth']

        with patch.dict(os.environ, {'SECRET_KEY': 'a' * 64}, clear=False):
            import auth  # noqa: F401
            assert auth.SECRET_KEY == 'a' * 64

    def test_no_hardcoded_fallback_in_source(self):
        """Grep the source file to verify there is no .getenv() fallback string."""
        auth_path = os.path.join(os.path.dirname(__file__), '..', 'auth.py')
        with open(auth_path) as f:
            content = f.read()
        # These are the strings from the original vulnerable version
        assert 'sentinel-super-secret-key' not in content, \
            "Hardcoded SECRET_KEY fallback found in auth.py!"
        assert 'os.getenv("SECRET_KEY"' not in content, \
            "os.getenv with fallback found — must use os.environ[] instead"


class TestDefaultAdminGating:
    """Test that create_default_user.py cannot run with a short/absent password."""

    def test_skips_when_flag_not_set(self):
        """Should do nothing if CREATE_DEFAULT_ADMIN is not 'true'."""
        import sys
        if 'create_default_user' in sys.modules:
            del sys.modules['create_default_user']

        with patch.dict(os.environ, {'CREATE_DEFAULT_ADMIN': 'false', 'SECRET_KEY': 'a' * 64}):
            # We need to mock the DB imports so we don't need a real DB connection
            with patch.dict('sys.modules', {
                'database': MagicMock(),
                'models': MagicMock(),
                'auth': MagicMock()
            }):
                import create_default_user
                # Should return without error and without touching the DB
                create_default_user.create_default()

    def test_raises_on_short_password(self):
        """Should raise RuntimeError if DEFAULT_ADMIN_PASSWORD is too short."""
        import sys
        if 'create_default_user' in sys.modules:
            del sys.modules['create_default_user']

        with patch.dict(os.environ, {
            'CREATE_DEFAULT_ADMIN': 'true',
            'DEFAULT_ADMIN_PASSWORD': 'tooshort',
            'SECRET_KEY': 'a' * 64
        }):
            with patch.dict('sys.modules', {
                'database': MagicMock(),
                'models': MagicMock(),
                'auth': MagicMock()
            }):
                import create_default_user
                with pytest.raises(RuntimeError, match="DEFAULT_ADMIN_PASSWORD must be at least 16 characters"):
                    create_default_user.create_default()

    def test_raises_on_absent_password(self):
        """Should raise RuntimeError if DEFAULT_ADMIN_PASSWORD is empty."""
        import sys
        if 'create_default_user' in sys.modules:
            del sys.modules['create_default_user']

        env = {k: v for k, v in os.environ.items() if k != 'DEFAULT_ADMIN_PASSWORD'}
        env['CREATE_DEFAULT_ADMIN'] = 'true'
        env['SECRET_KEY'] = 'a' * 64

        with patch.dict(os.environ, env, clear=True):
            with patch.dict('sys.modules', {
                'database': MagicMock(),
                'models': MagicMock(),
                'auth': MagicMock()
            }):
                import create_default_user
                with pytest.raises(RuntimeError):
                    create_default_user.create_default()

    def test_no_hardcoded_password_in_source(self):
        """Grep the source file to verify 'admin' password is not hardcoded."""
        cdp_path = os.path.join(os.path.dirname(__file__), '..', 'create_default_user.py')
        with open(cdp_path) as f:
            content = f.read()
        assert 'password = "admin"' not in content, \
            "Hardcoded admin password found in create_default_user.py!"


class TestTokenGeneration:
    """Basic tests for JWT token creation and validation."""

    def test_token_round_trip(self):
        """A token created by create_access_token can be decoded by get_current_user."""
        import sys
        if 'auth' in sys.modules:
            del sys.modules['auth']

        with patch.dict(os.environ, {'SECRET_KEY': 'a' * 64}):
            import auth
            token = auth.create_access_token({"user_id": 42, "role": "admin"})
            assert isinstance(token, str)
            assert len(token) > 20

            # Decode manually to verify contents
            import jwt
            payload = jwt.decode(token, 'a' * 64, algorithms=["HS256"])
            assert payload["user_id"] == 42
            assert payload["role"] == "admin"
            assert "exp" in payload
