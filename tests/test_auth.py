import base64
import os
import re
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pyotp
from sqlalchemy import delete, inspect
from sqlalchemy.exc import OperationalError
from werkzeug.test import TestResponse

os.environ.setdefault("SECRET_KEY", "test-only-secret")

from app import _ensure_demo_admin, create_app
from app.extensions import db
from app.models import (
    LoginAttempt,
    SecurityEvent,
    SimulationEvent,
    User,
    UserLoginSession,
)


class FrozenDateTime(datetime):
    frozen_at = datetime.now(timezone.utc)

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return cls.frozen_at.replace(tzinfo=None)
        return cls.frozen_at.astimezone(tz)


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(
            {
                "SECRET_KEY": "test-only-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "RATELIMIT_STORAGE_URI": "memory://",
                "SESSION_COOKIE_SECURE": False,
                "BRUTE_FORCE_SIMULATOR_ENABLED": True,
                "TESTING": True,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

    def csrf_token(self, path: str) -> str:
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def register(self) -> None:
        response = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token("/register"),
                "username": "testuser",
                "email": "test@example.com",
                "password": "Test-Secure-Password-123",
                "password_confirmation": "Test-Secure-Password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/register"))

    def sign_in(self, email: str = "test@example.com") -> TestResponse:
        return self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token("/login"),
                "email": email,
                "password": "Test-Secure-Password-123",
            },
        )

    def create_admin(
        self,
        username: str = "admin",
        email: str = "admin@example.com",
        password: str = "Test-Admin-Password-123",
        mfa_secret: str | None = None,
    ) -> int:
        with self.app.app_context():
            user = User(
                username=username,
                email=email,
                is_admin=True,
                mfa_enabled=mfa_secret is not None,
                mfa_secret=mfa_secret,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return user.id

    def sign_in_to_admin_terminal(
        self,
        username: str = "admin",
        password: str = "Test-Admin-Password-123",
    ) -> TestResponse:
        return self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token("/admin/login"),
                "login_context": "admin",
                "username": username,
                "password": password,
            },
        )

    def logout(self) -> None:
        home = self.client.get("/")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', home.data)
        self.assertIsNotNone(match)
        response = self.client.post(
            "/logout", data={"csrf_token": match.group(1).decode()}
        )
        self.assertEqual(response.status_code, 302)

    def test_database_and_registration_use_argon2id(self) -> None:
        with self.app.app_context():
            self.assertTrue(
                {"users", "login_attempts", "security_events"}.issubset(
                    set(inspect(db.engine).get_table_names())
                )
            )

        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn(b"Sign in", home.data)
        self.assertIn(b"Create account", home.data)
        self.assertEqual(self.client.get("/experience").status_code, 200)
        self.assertEqual(self.client.post("/register", data={}).status_code, 400)

        response = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token("/register"),
                "username": "TestUser",
                "email": "TEST@example.com",
                "password": "Test-Secure-Password-123",
                "password_confirmation": "Test-Secure-Password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/register"))

        with self.app.app_context():
            user = User.query.one()
            self.assertEqual(user.username, "testuser")
            self.assertEqual(user.email, "test@example.com")
            self.assertTrue(user.password_hash.startswith("$argon2id$"))
            self.assertTrue(user.check_password("Test-Secure-Password-123"))
            self.assertFalse(user.check_password("Incorrect-Password-123"))
            password_hash = user.password_hash.encode()

        registration_page = self.client.get("/register")
        self.assertIn(
            b"Your account has been created. You can now sign in.",
            registration_page.data,
        )
        self.assertNotIn(password_hash, registration_page.data)
        home = self.client.get("/")
        self.assertNotIn(password_hash, home.data)
        self.assertIn(b"Sign in", home.data)
        self.assertNotIn(b"Sign out", home.data)

    def test_demo_admin_is_argon2_hashed_and_reused(self) -> None:
        self.app.config.update(
            DEMO_ADMIN_ENABLED=True,
            DEMO_ADMIN_USERNAME="admin",
            DEMO_ADMIN_EMAIL="admin@securecore.local",
            DEMO_ADMIN_PASSWORD="admin",
        )
        with self.app.app_context():
            _ensure_demo_admin(self.app)
            admin = User.query.filter_by(username="admin").one()
            admin_id = admin.id
            password_hash = admin.password_hash
            self.assertTrue(admin.is_admin)
            self.assertTrue(password_hash.startswith("$argon2id$"))
            self.assertTrue(admin.check_password("admin"))

            _ensure_demo_admin(self.app)

            self.assertEqual(User.query.filter_by(is_admin=True).count(), 1)
            self.assertEqual(User.query.one().id, admin_id)
            self.assertEqual(User.query.one().password_hash, password_hash)

    def test_admin_terminal_records_failed_credentials_without_claiming_breach(self) -> None:
        admin_id = self.create_admin()

        invalid_password = self.sign_in_to_admin_terminal(password="wrong-password")
        unknown_username = self.sign_in_to_admin_terminal(
            username="unknown_admin", password="wrong-password"
        )
        self.assertEqual(invalid_password.status_code, 401)
        self.assertEqual(unknown_username.status_code, 401)
        self.assertEqual(invalid_password.data, unknown_username.data)
        self.assertIn(b"WARNING: SECURITY BREACH DETECTED", invalid_password.data)
        self.assertIn(
            b"not confirmation of a compromise",
            invalid_password.data,
        )
        self.assertNotIn(b"wrong-password", invalid_password.data)

        with self.app.app_context():
            admin = db.session.get(User, admin_id)
            self.assertEqual(admin.failed_login_attempts, 1)
            self.assertEqual(
                LoginAttempt.query.filter_by(
                    attempted_identifier="admin",
                    succeeded=False,
                ).count(),
                1,
            )
            self.assertEqual(
                SecurityEvent.query.filter_by(event_type="login.failed").count(),
                2,
            )
            self.assertFalse(
                any(
                    "breach" in event.description.casefold()
                    for event in SecurityEvent.query.all()
                )
            )

    def test_admin_terminal_denies_normal_users_and_admin_route(self) -> None:
        self.register()

        denied = self.sign_in_to_admin_terminal(
            username="testuser",
            password="Test-Secure-Password-123",
        )
        self.assertEqual(denied.status_code, 401)
        self.assertIn(b"ACCESS DENIED", denied.data)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        with self.app.app_context():
            user = User.query.filter_by(username="testuser").one()
            self.assertFalse(user.is_admin)
            self.assertEqual(
                SecurityEvent.query.filter_by(
                    event_type="admin.access.denied"
                ).count(),
                1,
            )

        self.assertEqual(self.sign_in().status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 404)
        room = self.client.get("/experience")
        self.assertNotIn(b"Admin Control Panel", room.data)

    def test_admin_terminal_success_uses_protected_session_and_logout(self) -> None:
        admin_id = self.create_admin()

        response = self.sign_in_to_admin_terminal()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AUTHENTICATION SUCCESSFUL", response.data)
        self.assertIn(b"ADMIN ACCESS GRANTED", response.data)
        self.assertIn(b"SECURECORE SYSTEM ONLINE", response.data)
        self.assertIn(b'data-success-url="/experience"', response.data)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.assertTrue(
            self.client.get("/admin/login")
            .headers["Location"]
            .endswith("/experience")
        )

        room = self.client.get("/experience")
        self.assertIn(b"Admin Control Panel", room.data)
        self.assertIn(b'href="/admin"', room.data)
        dashboard = self.client.get("/admin")
        self.assertIn(b"Return to 3D Security Room", dashboard.data)
        self.assertIn(b'href="/experience"', dashboard.data)

        with self.app.app_context():
            self.assertEqual(
                UserLoginSession.query.filter_by(user_id=admin_id).count(), 1
            )

        self.logout()
        self.assertEqual(self.client.get("/admin").status_code, 302)

    def test_admin_terminal_preserves_mfa_before_admin_access(self) -> None:
        secret = pyotp.random_base32()
        self.create_admin(mfa_secret=secret)

        password_response = self.sign_in_to_admin_terminal()
        self.assertEqual(password_response.status_code, 302)
        self.assertTrue(password_response.headers["Location"].endswith("/mfa/verify"))
        self.assertEqual(self.client.get("/admin").status_code, 302)

        with self.client.session_transaction() as browser_session:
            self.assertTrue(browser_session.get("mfa_pending_admin_redirect"))
            self.assertNotIn("_user_id", browser_session)

        otp_response = self.client.post(
            "/mfa/verify",
            data={
                "csrf_token": self.csrf_token("/mfa/verify"),
                "otp": pyotp.TOTP(secret).now(),
            },
        )
        self.assertEqual(otp_response.status_code, 200)
        self.assertIn(b"AUTHENTICATION SUCCESSFUL", otp_response.data)
        self.assertIn(b'data-success-url="/experience"', otp_response.data)
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.assertIn(b"Admin Control Panel", self.client.get("/experience").data)

    def test_duplicate_and_invalid_registration_are_rejected(self) -> None:
        self.register()

        duplicate_email = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token("/register"),
                "username": "anotheruser",
                "email": "test@example.com",
                "password": "Test-Secure-Password-123",
                "password_confirmation": "Test-Secure-Password-123",
            },
        )
        self.assertEqual(duplicate_email.status_code, 409)

        duplicate_username = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token("/register"),
                "username": "testuser",
                "email": "another@example.com",
                "password": "Test-Secure-Password-123",
                "password_confirmation": "Test-Secure-Password-123",
            },
        )
        self.assertEqual(duplicate_username.status_code, 409)

        mismatched_passwords = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token("/register"),
                "username": "newuser",
                "email": "new@example.com",
                "password": "Test-Secure-Password-123",
                "password_confirmation": "Different-Secure-Password-123",
            },
        )
        self.assertEqual(mismatched_passwords.status_code, 400)

        invalid = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token("/register"),
                "username": "another",
                "email": "not-an-email",
                "password": "Test-Secure-Password-123",
                "password_confirmation": "Test-Secure-Password-123",
            },
        )
        self.assertEqual(invalid.status_code, 400)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)

    def test_registration_database_error_is_generic_and_rolls_back(self) -> None:
        with self.app.app_context():
            with patch.object(
                db.session,
                "commit",
                side_effect=OperationalError(
                    "insert", {}, Exception("private database detail")
                ),
            ):
                response = self.client.post(
                    "/register",
                    data={
                        "csrf_token": self.csrf_token("/register"),
                        "username": "testuser",
                        "email": "test@example.com",
                        "password": "Test-Secure-Password-123",
                        "password_confirmation": "Test-Secure-Password-123",
                    },
                )

        self.assertEqual(response.status_code, 500)
        self.assertIn(b"Account registration could not be completed.", response.data)
        self.assertNotIn(b"private database detail", response.data)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 0)

    def test_existing_sqlite_users_table_gets_mfa_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy.db"
            connection = sqlite3.connect(database_path)
            try:
                connection.execute(
                    """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username VARCHAR(32) NOT NULL UNIQUE,
                        email VARCHAR(254) NOT NULL UNIQUE,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at DATETIME NOT NULL,
                        is_active BOOLEAN NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO users
                        (id, username, email, password_hash, created_at, is_active)
                    VALUES
                        (1, 'existing', 'existing@example.com',
                         '$argon2id$legacy-test-hash', CURRENT_TIMESTAMP, 1)
                    """
                )
                connection.commit()
            finally:
                connection.close()

            legacy_app = create_app(
                {
                    "SECRET_KEY": "test-only-secret",
                    "SQLALCHEMY_DATABASE_URI": (
                        f"sqlite:///{database_path.as_posix()}"
                    ),
                    "RATELIMIT_STORAGE_URI": "memory://",
                    "TESTING": True,
                }
            )
            with legacy_app.app_context():
                columns = {
                    column["name"]
                    for column in inspect(db.engine).get_columns("users")
                }
                self.assertTrue(
                    {
                        "is_admin",
                        "mfa_enabled",
                        "mfa_secret",
                        "mfa_last_counter",
                        "failed_login_attempts",
                        "locked_until",
                    }.issubset(columns)
                )
                user = db.session.get(User, 1)
                self.assertIsNotNone(user)
                self.assertFalse(user.is_admin)
                self.assertFalse(user.mfa_enabled)
                self.assertIsNone(user.mfa_secret)
                self.assertIsNone(user.mfa_last_counter)
                self.assertEqual(user.failed_login_attempts, 0)
                self.assertIsNone(user.locked_until)
                index_names = {
                    index["name"] for index in inspect(db.engine).get_indexes("users")
                }
                self.assertIn("uq_users_mfa_secret", index_names)
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def test_mfa_setup_requires_current_code_and_renders_local_qr(self) -> None:
        self.register()
        self.assertEqual(self.sign_in().status_code, 302)

        setup_page = self.client.get("/mfa/setup")
        self.assertEqual(setup_page.status_code, 200)
        self.assertNotIn(b"data:image/svg+xml;base64,", setup_page.data)
        generated = self.client.post(
            "/mfa/setup",
            data={
                "csrf_token": self.csrf_token("/mfa/setup"),
                "action": "generate",
            },
        )
        self.assertEqual(generated.status_code, 302)
        setup_page = self.client.get("/mfa/setup")
        self.assertEqual(setup_page.status_code, 200)
        self.assertIn(b"data:image/svg+xml;base64,", setup_page.data)
        qr_match = re.search(
            rb'data:image/svg\+xml;base64,([^"]+)', setup_page.data
        )
        self.assertIsNotNone(qr_match)
        qr_svg = base64.b64decode(qr_match.group(1))
        self.assertIn(b"<svg", qr_svg)
        self.assertIn("no-store", setup_page.headers["Cache-Control"])

        with self.app.app_context():
            secret = User.query.one().mfa_secret
        if not isinstance(secret, str):
            self.fail("MFA setup did not persist a TOTP secret.")
        self.assertNotIn(secret.encode(), setup_page.data)
        totp = pyotp.TOTP(secret)

        frozen_timestamp = int(time.time())
        FrozenDateTime.frozen_at = datetime.fromtimestamp(
            frozen_timestamp, timezone.utc
        )
        expired_code = totp.at(frozen_timestamp - 60)
        valid_code = totp.at(frozen_timestamp)
        with patch("app.routes.datetime", FrozenDateTime):
            missing_csrf = self.client.post(
                "/mfa/setup",
                data={"otp": valid_code},
            )
            self.assertEqual(missing_csrf.status_code, 400)

            expired = self.client.post(
                "/mfa/setup",
                data={
                    "csrf_token": self.csrf_token("/mfa/setup"),
                    "otp": expired_code,
                },
            )
            self.assertEqual(expired.status_code, 400)

            enabled = self.client.post(
                "/mfa/setup",
                data={
                    "csrf_token": self.csrf_token("/mfa/setup"),
                    "otp": valid_code,
                },
            )
        self.assertEqual(enabled.status_code, 302)
        self.assertTrue(enabled.headers["Location"].endswith("/dashboard"))
        with self.app.app_context():
            user = User.query.one()
            self.assertTrue(user.mfa_enabled)
            self.assertIsNotNone(user.mfa_last_counter)
            self.assertEqual(user.mfa_secret, secret)
        dashboard = self.client.get("/dashboard")
        self.assertNotIn(secret.encode(), dashboard.data)

    def test_mfa_login_requires_a_fresh_code_and_rejects_replay(self) -> None:
        self.register()
        with self.app.app_context():
            user = User.query.one()
            user.mfa_secret = pyotp.random_base32()
            user.mfa_enabled = True
            db.session.commit()
            secret = user.mfa_secret
        if not isinstance(secret, str):
            self.fail("MFA secret was not configured for the test user.")
        totp = pyotp.TOTP(secret)

        challenge = self.sign_in()
        self.assertEqual(challenge.status_code, 302)
        self.assertTrue(challenge.headers["Location"].endswith("/mfa/verify"))
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(self.client.get("/mfa/verify").status_code, 200)
        with self.app.app_context():
            self.assertEqual(UserLoginSession.query.count(), 0)

        frozen_timestamp = (int(time.time()) // 30) * 30 - 5
        FrozenDateTime.frozen_at = datetime.fromtimestamp(
            frozen_timestamp, timezone.utc
        )
        valid_code = totp.at(frozen_timestamp)
        wrong_code = f"{(int(valid_code) + 1) % 1_000_000:06d}"
        expired_code = totp.at(frozen_timestamp - 60)
        with patch("app.routes.datetime", FrozenDateTime):
            missing_csrf = self.client.post(
                "/mfa/verify",
                data={"otp": wrong_code},
            )
            self.assertEqual(missing_csrf.status_code, 400)

            incorrect = self.client.post(
                "/mfa/verify",
                data={
                    "csrf_token": self.csrf_token("/mfa/verify"),
                    "otp": wrong_code,
                },
            )
            self.assertEqual(incorrect.status_code, 401)

            expired = self.client.post(
                "/mfa/verify",
                data={
                    "csrf_token": self.csrf_token("/mfa/verify"),
                    "otp": expired_code,
                },
            )
            self.assertEqual(expired.status_code, 401)
            self.assertEqual(self.client.get("/dashboard").status_code, 302)

            verified = self.client.post(
                "/mfa/verify",
                data={
                    "csrf_token": self.csrf_token("/mfa/verify"),
                    "otp": valid_code,
                },
            )
        self.assertEqual(verified.status_code, 302)
        self.assertTrue(verified.headers["Location"].endswith("/dashboard"))
        with self.app.app_context():
            self.assertEqual(UserLoginSession.query.count(), 1)
        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn(secret.encode(), dashboard.data)
        self.logout()

        second_challenge = self.sign_in()
        self.assertTrue(second_challenge.headers["Location"].endswith("/mfa/verify"))
        with patch("app.routes.datetime", FrozenDateTime):
            replayed = self.client.post(
                "/mfa/verify",
                data={
                    "csrf_token": self.csrf_token("/mfa/verify"),
                    "otp": valid_code,
                },
            )
        self.assertEqual(replayed.status_code, 401)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        with self.app.app_context():
            attempts = LoginAttempt.query.order_by(LoginAttempt.id).all()
            self.assertEqual(len(attempts), 4)
            self.assertEqual(sum(attempt.success for attempt in attempts), 1)
            self.assertTrue(
                all(
                    attempt.attempted_identifier == "test@example.com"
                    for attempt in attempts
                )
            )
            event_details = [
                event.details for event in SecurityEvent.query.all()
            ]
            for code in (wrong_code, expired_code, valid_code):
                self.assertTrue(all(code not in details for details in event_details))

    def test_login_attempts_and_logout_are_recorded(self) -> None:
        self.register()

        protected = self.client.get("/dashboard")
        self.assertEqual(protected.status_code, 302)
        self.assertIn("/login?next=", protected.headers["Location"])

        failed = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token("/login"),
                "email": "test@example.com",
                "password": "Incorrect-Password-123",
            },
        )
        self.assertEqual(failed.status_code, 401)
        self.assertIn(b"Invalid email or password.", failed.data)

        unknown = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token("/login"),
                "email": "unknown@example.com",
                "password": "Incorrect-Password-123",
            },
        )
        self.assertEqual(unknown.status_code, 401)
        self.assertIn(b"Invalid email or password.", unknown.data)

        succeeded = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token("/login"),
                "email": "TEST@example.com",
                "password": "Test-Secure-Password-123",
            },
        )
        self.assertEqual(succeeded.status_code, 302)
        self.assertTrue(succeeded.headers["Location"].endswith("/dashboard"))
        self.assertTrue(
            self.client.get("/login").headers["Location"].endswith("/dashboard")
        )

        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("no-store", dashboard.headers["Cache-Control"])
        self.assertIn(b"Welcome, testuser.", dashboard.data)
        self.assertIn(b"test@example.com", dashboard.data)
        with self.app.app_context():
            password_hash = User.query.one().password_hash.encode()
        self.assertNotIn(password_hash, dashboard.data)
        old_session_cookie = self.client.get_cookie("session")
        self.assertIsNotNone(old_session_cookie)

        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout", data={}).status_code, 400)
        self.logout()
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        copied_session_client = self.app.test_client()
        copied_session_client.set_cookie("session", old_session_cookie.value)
        self.assertEqual(copied_session_client.get("/dashboard").status_code, 302)

        with self.app.app_context():
            self.assertEqual(LoginAttempt.query.count(), 3)
            self.assertEqual(LoginAttempt.query.filter_by(succeeded=False).count(), 2)
            self.assertEqual(LoginAttempt.query.filter_by(succeeded=True).count(), 1)
            attempts = LoginAttempt.query.order_by(LoginAttempt.id).all()
            self.assertIsNotNone(attempts[0].user_id)
            self.assertIsNone(attempts[1].user_id)
            self.assertEqual(SecurityEvent.query.count(), 5)
            self.assertEqual(UserLoginSession.query.count(), 0)

    def test_idle_session_expires_and_redirects_to_login(self) -> None:
        self.register()
        self.assertEqual(self.sign_in().status_code, 302)
        with self.app.app_context():
            active_session = UserLoginSession.query.one()
            inactive_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            active_session.last_activity_at = inactive_at
            db.session.commit()

        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        with self.app.app_context():
            active_session = UserLoginSession.query.one()
            last_activity = active_session.last_activity_at
            if last_activity.tzinfo is None:
                last_activity = last_activity.replace(tzinfo=timezone.utc)
            self.assertGreater(last_activity, inactive_at)
            active_session.last_activity_at = datetime.now(timezone.utc) - timedelta(
                minutes=16
            )
            db.session.commit()

        expired = self.client.get("/dashboard")
        self.assertEqual(expired.status_code, 302)
        self.assertTrue(expired.headers["Location"].endswith("/login"))
        login_page = self.client.get("/login")
        self.assertIn(b"Your session expired.", login_page.data)
        with self.app.app_context():
            self.assertEqual(UserLoginSession.query.count(), 0)

    def test_session_cookie_attributes_and_secure_deployment_option(self) -> None:
        self.assertFalse(self.app.config["SESSION_COOKIE_SECURE"])
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertEqual(
            self.app.config["PERMANENT_SESSION_LIFETIME"], timedelta(hours=8)
        )

        self.app.config["SESSION_COOKIE_SECURE"] = True
        self.client.environ_base["wsgi.url_scheme"] = "https"
        self.register()
        response = self.sign_in()
        self.assertEqual(response.status_code, 302)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("Expires=", cookie)

    def test_production_requires_secure_cookies_and_https(self) -> None:
        production_config = {
            "SECRET_KEY": "test-only-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "RATELIMIT_STORAGE_URI": "memory://",
            "APP_ENV": "production",
            "TESTING": True,
        }
        with self.assertRaisesRegex(
            RuntimeError, "SESSION_COOKIE_SECURE must be true"
        ):
            create_app(
                {
                    **production_config,
                    "SESSION_COOKIE_SECURE": False,
                }
            )

        direct_app = create_app(
            {
                **production_config,
                "SESSION_COOKIE_SECURE": True,
                "TRUSTED_PROXY_COUNT": 0,
            }
        )
        proxy_app = create_app(
            {
                **production_config,
                "SESSION_COOKIE_SECURE": True,
                "TRUSTED_PROXY_COUNT": 1,
            }
        )
        try:
            self.assertTrue(direct_app.config["SESSION_COOKIE_SECURE"])
            direct_client = direct_app.test_client()
            self.assertEqual(
                direct_client.get(
                    "/", base_url="http://localhost"
                ).status_code,
                400,
            )
            self.assertEqual(
                direct_client.get(
                    "/", base_url="https://localhost"
                ).status_code,
                200,
            )

            proxy_client = proxy_app.test_client()
            self.assertEqual(
                proxy_client.get(
                    "/",
                    base_url="http://localhost",
                    headers={"X-Forwarded-Proto": "https"},
                ).status_code,
                200,
            )
            self.assertEqual(
                proxy_client.get(
                    "/",
                    base_url="http://localhost",
                ).status_code,
                400,
            )
        finally:
            for test_app in (direct_app, proxy_app):
                with test_app.app_context():
                    db.session.remove()
                    db.drop_all()
                    db.engine.dispose()

    def test_password_failures_lock_account_until_expiry(self) -> None:
        self.register()

        for _ in range(5):
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": self.csrf_token("/login"),
                    "email": "test@example.com",
                    "password": "Incorrect-Password-123",
                },
            )
            self.assertEqual(response.status_code, 401)

        with self.app.app_context():
            user = User.query.one()
            self.assertEqual(user.failed_login_attempts, 5)
            self.assertIsNotNone(user.locked_until)
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            lockout_seconds_remaining = (
                locked_until - datetime.now(timezone.utc)
            ).total_seconds()
            self.assertGreater(lockout_seconds_remaining, 295)
            self.assertLessEqual(lockout_seconds_remaining, 300)
            self.assertEqual(
                SecurityEvent.query.filter_by(event_type="account.locked").count(),
                1,
            )

        with self.client.session_transaction() as client_session:
            client_session.clear()
        during_lockout = self.sign_in()
        self.assertEqual(during_lockout.status_code, 401)
        self.assertIn(b"temporarily locked", during_lockout.data)
        with self.app.app_context():
            self.assertEqual(User.query.one().failed_login_attempts, 5)

        with self.app.app_context():
            user = User.query.one()
            user.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.session.commit()

        after_expiry = self.sign_in()
        self.assertEqual(after_expiry.status_code, 302)
        self.assertTrue(after_expiry.headers["Location"].endswith("/dashboard"))
        with self.app.app_context():
            user = User.query.one()
            self.assertEqual(user.failed_login_attempts, 0)
            self.assertIsNone(user.locked_until)
            self.assertEqual(
                SecurityEvent.query.filter_by(event_type="account.unlocked").count(),
                1,
            )

    def test_successful_login_resets_failed_attempt_counter(self) -> None:
        self.register()
        for _ in range(2):
            self.client.post(
                "/login",
                data={
                    "csrf_token": self.csrf_token("/login"),
                    "email": "test@example.com",
                    "password": "Incorrect-Password-123",
                },
            )

        self.assertEqual(self.sign_in().status_code, 302)
        with self.app.app_context():
            self.assertEqual(User.query.one().failed_login_attempts, 0)

    def test_login_requests_are_rate_limited_by_ip(self) -> None:
        csrf = self.csrf_token("/login")
        responses = [
            self.client.post(
                "/login",
                data={
                    "csrf_token": csrf,
                    "email": "unknown@example.com",
                    "password": "Incorrect-Password-123",
                },
                headers={"X-Forwarded-For": f"198.51.100.{index + 1}"},
            )
            for index in range(11)
        ]
        self.assertTrue(all(response.status_code == 401 for response in responses[:10]))
        self.assertEqual(responses[10].status_code, 429)

    def test_deployment_rejects_in_memory_limiter_storage(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "persistent RATELIMIT_STORAGE_URI"):
            create_app(
                {
                    "SECRET_KEY": "test-only-secret",
                    "SQLALCHEMY_DATABASE_URI": "sqlite://",
                    "RATELIMIT_STORAGE_URI": "memory://",
                    "APP_ENV": "production",
                    "SESSION_COOKIE_SECURE": True,
                }
            )

    def test_development_default_limiter_without_redis_handles_login(self) -> None:
        if os.getenv("RATELIMIT_STORAGE_URI") or os.getenv(
            "APP_ENV", "development"
        ).strip().casefold() != "development":
            self.skipTest("An explicit non-development rate-limit configuration is active.")

        app = create_app(
            {
                "SECRET_KEY": "test-only-secret",
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "APP_ENV": "development",
                "FLASK_DEBUG": False,
                "DEMO_ADMIN_ENABLED": False,
                "TESTING": False,
            }
        )
        client = app.test_client()
        try:
            self.assertEqual(app.config["RATELIMIT_STORAGE_URI"], "memory://")
            page = client.get("/admin/login")
            token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data)
            self.assertIsNotNone(token)

            response = client.post(
                "/login",
                data={
                    "csrf_token": token.group(1).decode(),
                    "login_context": "admin",
                    "username": "unknown_admin",
                    "password": "Synthetic-Invalid-Password",
                },
            )
            self.assertEqual(response.status_code, 401)
            self.assertIn(b"INVALID CREDENTIALS", response.data)
        finally:
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()

    def test_otp_failures_are_rate_limited(self) -> None:
        self.register()
        with self.app.app_context():
            user = User.query.one()
            user.mfa_secret = pyotp.random_base32()
            user.mfa_enabled = True
            db.session.commit()
            invalid_code = (
                f"{(int(pyotp.TOTP(user.mfa_secret).now()) + 1) % 1_000_000:06d}"
            )

        challenge = self.sign_in()
        self.assertTrue(challenge.headers["Location"].endswith("/mfa/verify"))
        csrf = self.csrf_token("/mfa/verify")
        responses = [
            self.client.post(
                "/mfa/verify",
                data={"csrf_token": csrf, "otp": invalid_code},
            )
            for _ in range(6)
        ]
        self.assertTrue(all(response.status_code == 401 for response in responses[:5]))
        self.assertEqual(responses[5].status_code, 429)
        with self.app.app_context():
            self.assertEqual(
                SecurityEvent.query.filter_by(event_type="mfa.failed").count(), 5
            )

    def test_brute_force_simulator_runs_bounded_mock_scenarios_only(self) -> None:
        page = self.client.get("/brute-force-simulator")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"isolated mock account only", page.data)
        self.assertIn(b'max="20"', page.data)
        csrf = self.csrf_token("/brute-force-simulator")
        results = {}

        for scenario in ("unprotected", "rate_limited", "lockout", "mfa"):
            response = self.client.post(
                "/api/simulation/brute-force",
                json={"attempt_count": 10, "scenario": scenario},
                headers={"X-CSRFToken": csrf},
            )
            self.assertEqual(response.status_code, 200)
            results[scenario] = response.get_json()

        self.assertEqual(results["unprotected"]["summary"]["successful_guesses"], 1)
        self.assertEqual(results["unprotected"]["summary"]["completed_logins"], 1)
        self.assertEqual(results["rate_limited"]["summary"]["failed_guesses"], 5)
        self.assertEqual(results["rate_limited"]["summary"]["blocked_attempts"], 5)
        self.assertEqual(results["lockout"]["summary"]["failed_guesses"], 5)
        self.assertEqual(results["lockout"]["summary"]["blocked_attempts"], 5)
        self.assertEqual(results["mfa"]["summary"]["successful_guesses"], 1)
        self.assertEqual(results["mfa"]["summary"]["completed_logins"], 0)
        self.assertEqual(results["mfa"]["events"][7]["outcome"], "mfa_required")

        over_limit = self.client.post(
            "/api/simulation/brute-force",
            json={"attempt_count": 21, "scenario": "unprotected"},
            headers={"X-CSRFToken": csrf},
        )
        self.assertEqual(over_limit.status_code, 400)
        throttled = self.client.post(
            "/api/simulation/brute-force",
            json={"attempt_count": 1, "scenario": "unprotected"},
            headers={"X-CSRFToken": csrf},
        )
        self.assertEqual(throttled.status_code, 429)

        with self.app.app_context():
            self.assertEqual(SimulationEvent.query.count(), 40)
            self.assertEqual(LoginAttempt.query.count(), 0)
            self.assertEqual(SecurityEvent.query.count(), 0)
            self.assertEqual(User.query.count(), 0)

    def test_simulator_rejects_non_local_requests(self) -> None:
        response = self.client.get(
            "/brute-force-simulator",
            environ_overrides={"REMOTE_ADDR": "203.0.113.15"},
        )
        self.assertEqual(response.status_code, 404)
        dashboard = self.client.get(
            "/attack-vs-defence",
            environ_overrides={"REMOTE_ADDR": "203.0.113.15"},
        )
        self.assertEqual(dashboard.status_code, 404)
        dashboard_data = self.client.get(
            "/api/attack-vs-defence",
            environ_overrides={"REMOTE_ADDR": "203.0.113.15"},
        )
        self.assertEqual(dashboard_data.status_code, 404)

    def test_attack_dashboard_handles_empty_simulation_data(self) -> None:
        page = self.client.get("/attack-vs-defence")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Scenario comparison", page.data)

        response = self.client.get("/api/attack-vs-defence")
        self.assertEqual(response.status_code, 200)
        dashboard = response.get_json()
        self.assertFalse(dashboard["has_data"])
        self.assertEqual(dashboard["stats"]["total_attacks"], 0)
        self.assertIsNone(dashboard["stats"]["defence_success_percent"])
        self.assertEqual(len(dashboard["timeline"]), 24)
        self.assertTrue(all(hour["attempts"] == 0 for hour in dashboard["timeline"]))

    def test_attack_dashboard_aggregates_simulation_data_and_filters_scenarios(
        self,
    ) -> None:
        csrf = self.csrf_token("/brute-force-simulator")
        for scenario in ("unprotected", "rate_limited", "lockout", "mfa"):
            response = self.client.post(
                "/api/simulation/brute-force",
                json={"attempt_count": 10, "scenario": scenario},
                headers={"X-CSRFToken": csrf},
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.get("/api/attack-vs-defence")
        self.assertEqual(response.status_code, 200)
        dashboard = response.get_json()
        stats = dashboard["stats"]
        self.assertTrue(dashboard["has_data"])
        self.assertEqual(stats["total_attacks"], 40)
        self.assertEqual(stats["failed_password_guesses"], 28)
        self.assertEqual(stats["blocked_attempts"], 10)
        self.assertEqual(stats["successful_simulated_guesses"], 2)
        self.assertEqual(stats["completed_mock_logins"], 1)
        self.assertEqual(stats["defence_success_percent"], 27.5)
        self.assertEqual(stats["rate_limiting_effectiveness_percent"], 50.0)
        self.assertEqual(stats["account_lockout_effectiveness_percent"], 50.0)
        self.assertEqual(stats["mfa_password_matches"], 1)
        self.assertEqual(stats["mfa_protection_percent"], 100.0)
        self.assertEqual(len(dashboard["comparison"]), 4)
        self.assertEqual(sum(hour["attempts"] for hour in dashboard["timeline"]), 40)

        filtered = self.client.get("/api/attack-vs-defence?scenario=mfa")
        self.assertEqual(filtered.status_code, 200)
        mfa_dashboard = filtered.get_json()
        self.assertEqual(mfa_dashboard["stats"]["total_attacks"], 10)
        self.assertEqual(len(mfa_dashboard["comparison"]), 1)
        self.assertEqual(mfa_dashboard["comparison"][0]["scenario"], "mfa")
        self.assertEqual(
            sum(hour["attempts"] for hour in mfa_dashboard["timeline"]), 10
        )

        invalid_filter = self.client.get(
            "/api/attack-vs-defence?scenario=other"
        )
        self.assertEqual(invalid_filter.status_code, 400)

    def _sign_in_as_security_monitor_admin(self) -> int:
        self.register()
        with self.app.app_context():
            user = User.query.filter_by(email="test@example.com").one()
            admin_id = user.id
        self.app.config["SECURITY_DASHBOARD_ADMIN_IDS"] = frozenset({admin_id})
        response = self.sign_in()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))
        return admin_id

    def test_security_monitoring_requires_configured_admin_access(self) -> None:
        self.assertEqual(
            self.client.get("/security-monitoring").status_code, 302
        )
        self.assertEqual(
            self.client.get("/api/security-monitoring").status_code, 401
        )

        self.register()
        self.assertEqual(self.sign_in().status_code, 302)
        self.assertEqual(self.client.get("/security-monitoring").status_code, 404)
        self.assertEqual(
            self.client.get("/api/security-monitoring").status_code, 404
        )

    def test_security_monitoring_empty_state_and_date_validation(self) -> None:
        admin_id = self._sign_in_as_security_monitor_admin()
        with self.app.app_context():
            db.session.execute(delete(LoginAttempt))
            db.session.execute(delete(SecurityEvent))
            db.session.commit()

        page = self.client.get("/security-monitoring")
        self.assertEqual(page.status_code, 200)
        response = self.client.get("/api/security-monitoring")
        self.assertEqual(response.status_code, 200)
        dashboard = response.get_json()
        self.assertEqual(dashboard["stats"]["registered_users"], 1)
        self.assertEqual(dashboard["stats"]["successful_logins"], 0)
        self.assertEqual(dashboard["stats"]["failed_login_attempts"], 0)
        self.assertEqual(dashboard["stats"]["account_lockout_events"], 0)
        self.assertEqual(dashboard["events"], [])
        self.assertEqual(dashboard["alerts"], [])
        self.assertEqual(len(dashboard["timeline"]), 7)
        self.assertTrue(
            all(day["successful_logins"] == 0 for day in dashboard["timeline"])
        )

        invalid_range = self.client.get(
            "/api/security-monitoring?start_date=2026-02-02&end_date=2026-01-01"
        )
        self.assertEqual(invalid_range.status_code, 400)
        too_wide = self.client.get(
            "/api/security-monitoring?start_date=2025-01-01&end_date=2026-01-01"
        )
        self.assertEqual(too_wide.status_code, 400)

    def test_security_monitoring_uses_real_auth_records_and_risk_filters(self) -> None:
        admin_id = self._sign_in_as_security_monitor_admin()
        now = datetime.now(timezone.utc)
        with self.app.app_context():
            user = db.session.get(User, admin_id)
            user.mfa_enabled = True
            db.session.add_all(
                [
                    LoginAttempt(
                        user=user,
                        attempted_identifier=user.email,
                        succeeded=False,
                        attempted_at=now,
                    )
                    for _ in range(3)
                ]
                + [
                    LoginAttempt(
                        user=user,
                        attempted_identifier=user.email,
                        succeeded=True,
                        attempted_at=now,
                    )
                    for _ in range(2)
                ]
                + [
                    LoginAttempt(
                        attempted_identifier="private-address@example.com",
                        succeeded=False,
                        attempted_at=now,
                    )
                    for _ in range(3)
                ]
                + [
                    LoginAttempt(
                        user=user,
                        attempted_identifier=user.email,
                        succeeded=False,
                        attempted_at=now,
                    )
                    for _ in range(3)
                ]
            )
            db.session.add_all(
                [
                    SecurityEvent(
                        user=user,
                        event_type="account.locked",
                        details="Temporary lockout recorded.",
                        created_at=now,
                    ),
                    SecurityEvent(
                        user=user,
                        event_type="mfa.challenge",
                        details="MFA challenge issued.",
                        created_at=now,
                    ),
                    SecurityEvent(
                        user=user,
                        event_type="mfa.enabled",
                        details="MFA enabled.",
                        created_at=now,
                    ),
                ]
                + [
                    SecurityEvent(
                        user=user,
                        event_type="mfa.failed",
                        details="Invalid MFA code.",
                        created_at=now,
                    )
                    for _ in range(3)
                ]
            )
            db.session.add(
                SimulationEvent(
                    run_id="separate-simulation",
                    scenario="lockout",
                    attempt_number=1,
                    outcome="blocked_lockout",
                    details="Simulation-only record.",
                    created_at=now,
                )
            )
            db.session.commit()

        response = self.client.get("/api/security-monitoring")
        self.assertEqual(response.status_code, 200)
        dashboard = response.get_json()
        stats = dashboard["stats"]
        self.assertEqual(stats["registered_users"], 1)
        self.assertEqual(stats["successful_logins"], 3)
        self.assertEqual(stats["failed_login_attempts"], 9)
        self.assertEqual(stats["account_lockout_events"], 1)
        self.assertEqual(stats["mfa_challenges"], 1)
        self.assertEqual(stats["mfa_failed_verifications"], 3)
        self.assertEqual(stats["mfa_enabled_events"], 1)
        self.assertEqual(stats["mfa_enabled_account_logins"], 3)
        self.assertEqual(
            sum(day["successful_logins"] for day in dashboard["timeline"]),
            stats["successful_logins"],
        )
        self.assertEqual(
            sum(day["failed_logins"] for day in dashboard["timeline"]),
            stats["failed_login_attempts"],
        )
        self.assertEqual(
            sum(day["lockouts"] for day in dashboard["timeline"]),
            stats["account_lockout_events"],
        )
        self.assertEqual(
            sum(day["mfa_activity"] for day in dashboard["timeline"]),
            stats["mfa_challenges"] + stats["mfa_failed_verifications"]
            + stats["mfa_enabled_events"],
        )
        self.assertNotIn("private-address@example.com", response.get_data(as_text=True))
        alert_types = {alert["event_type"] for alert in dashboard["alerts"]}
        self.assertIn("account.locked", alert_types)
        self.assertIn("detection.success_after_failures", alert_types)
        self.assertIn("detection.mfa_failures", alert_types)
        success_alert = next(
            alert
            for alert in dashboard["alerts"]
            if alert["event_type"] == "detection.success_after_failures"
        )
        self.assertEqual(success_alert["risk_score"], 85)
        self.assertEqual(success_alert["severity"], "high")
        self.assertTrue(
            all(event["event_type"] != "simulation" for event in dashboard["events"])
        )

        today = now.date().isoformat()
        filtered = self.client.get(
            "/api/security-monitoring"
            f"?start_date={today}&end_date={today}"
            "&event_type=account.locked&severity=high"
        )
        self.assertEqual(filtered.status_code, 200)
        filtered_data = filtered.get_json()
        self.assertEqual(
            [event["event_type"] for event in filtered_data["events"]],
            ["account.locked"],
        )
        self.assertEqual(
            [alert["event_type"] for alert in filtered_data["alerts"]],
            ["account.locked"],
        )

        invalid_severity = self.client.get(
            "/api/security-monitoring?severity=unknown"
        )
        self.assertEqual(invalid_severity.status_code, 400)


if __name__ == "__main__":
    unittest.main()
