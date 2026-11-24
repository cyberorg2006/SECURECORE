
import os
from datetime import timedelta

from dotenv import load_dotenv

# Load environment variables from the project root .env file
load_dotenv()


def _configured_security_dashboard_admin_ids() -> frozenset[int]:
    configured_ids = os.getenv("SECURITY_DASHBOARD_ADMIN_IDS", "")
    admin_ids: set[int] = set()
    for value in configured_ids.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            user_id = int(value)
        except ValueError as error:
            raise RuntimeError(
                "SECURITY_DASHBOARD_ADMIN_IDS must contain comma-separated positive user IDs."
            ) from error
        if user_id <= 0:
            raise RuntimeError(
                "SECURITY_DASHBOARD_ADMIN_IDS must contain comma-separated positive user IDs."
            )
        admin_ids.add(user_id)
    return frozenset(admin_ids)


def _configured_trusted_proxy_count() -> int:
    value = os.getenv("TRUSTED_PROXY_COUNT", "0").strip()
    try:
        proxy_count = int(value)
    except ValueError as error:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be a non-negative integer.") from error
    if proxy_count < 0:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be a non-negative integer.")
    return proxy_count


class Config:
    # Application security
    APP_ENV = os.getenv("APP_ENV", "development").strip().casefold()
    if APP_ENV not in {"development", "production"}:
        raise RuntimeError("APP_ENV must be either development or production.")

    SECRET_KEY = os.getenv("SECRET_KEY")

    if not SECRET_KEY:
        raise RuntimeError(
            "Set a non-empty SECRET_KEY environment variable before starting the app."
        )

    # Database configuration
    SQLALCHEMY_DATABASE_URI = "sqlite:///secure_login.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Rate limiting uses a persistent shared backend in deployment.
    RATELIMIT_STORAGE_URI = os.getenv(
        "RATELIMIT_STORAGE_URI",
        "redis://localhost:6379/0" if APP_ENV == "production" else "memory://",
    )
    RATELIMIT_IN_MEMORY_FALLBACK_ENABLED = False
    RATELIMIT_SWALLOW_ERRORS = False
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").strip().casefold() == "true"

    # Account lockout
    LOGIN_MAX_FAILED_ATTEMPTS = 5
    LOGIN_LOCKOUT_DURATION_SECONDS = 300

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (
        os.getenv(
            "SESSION_COOKIE_SECURE",
            "true" if APP_ENV == "production" else "false",
        )
        .strip()
        .casefold()
        == "true"
    )
    if APP_ENV == "production" and not SESSION_COOKIE_SECURE:
        raise RuntimeError(
            "SESSION_COOKIE_SECURE must be true when APP_ENV is production."
        )
    TRUSTED_PROXY_COUNT = _configured_trusted_proxy_count()
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_REFRESH_EACH_REQUEST = False
    SESSION_IDLE_TIMEOUT_SECONDS = 15 * 60
    SESSION_MAX_AGE_SECONDS = 8 * 60 * 60

    # The mock-only simulator is opt-in and additionally restricted to loopback.
    BRUTE_FORCE_SIMULATOR_ENABLED = (
        os.getenv("BRUTE_FORCE_SIMULATOR_ENABLED", "false").strip().casefold()
        == "true"
    )
    SECURITY_DASHBOARD_ADMIN_IDS = _configured_security_dashboard_admin_ids()

    # The predictable demo administrator is available only in local development.
    DEMO_ADMIN_ENABLED = (
        os.getenv(
            "DEMO_ADMIN_ENABLED",
            "true" if APP_ENV == "development" else "false",
        )
        .strip()
        .casefold()
        == "true"
    )
    DEMO_ADMIN_USERNAME = os.getenv("DEMO_ADMIN_USERNAME", "admin").strip().casefold()
    DEMO_ADMIN_EMAIL = os.getenv(
        "DEMO_ADMIN_EMAIL", "admin@securecore.local"
    ).strip().casefold()
    DEMO_ADMIN_PASSWORD = os.getenv(
        "DEMO_ADMIN_PASSWORD", "admin" if APP_ENV == "development" else ""
    )
    if APP_ENV == "production" and DEMO_ADMIN_ENABLED:
        raise RuntimeError("DEMO_ADMIN_ENABLED must be false in production.")

    # CSRF protection
    WTF_CSRF_ENABLED = True
