import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, logout_user
from sqlalchemy import case, delete, inspect, or_, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import AUTH_SESSION_TOKEN_KEY, csrf, db, limiter, login_manager
from app.models import SecurityEvent, User, UserLoginSession

def _ensure_user_security_schema() -> None:
    with db.engine.begin() as connection:
        columns = {
            column["name"] for column in inspect(connection).get_columns("users")
        }
        additions = {
            "mfa_enabled": (
                "ALTER TABLE users ADD COLUMN "
                "mfa_enabled BOOLEAN NOT NULL DEFAULT 0"
            ),
            "mfa_secret": "ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(32)",
            "mfa_last_counter": (
                "ALTER TABLE users ADD COLUMN mfa_last_counter BIGINT"
            ),
            "failed_login_attempts": (
                "ALTER TABLE users ADD COLUMN "
                "failed_login_attempts INTEGER NOT NULL DEFAULT 0"
            ),
            "locked_until": "ALTER TABLE users ADD COLUMN locked_until DATETIME",
            "is_admin": (
                "ALTER TABLE users ADD COLUMN "
                "is_admin BOOLEAN NOT NULL DEFAULT 0"
            ),
        }
        for column_name, statement in additions.items():
            if column_name not in columns:
                connection.execute(text(statement))

        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_login_attempts_created_at "
                "ON login_attempts (created_at)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_security_events_created_at "
                "ON security_events (created_at)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_security_events_type_created_at "
                "ON security_events (event_type, created_at)"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_users_mfa_secret "
                "ON users (mfa_secret)"
            )
        )


def _ensure_demo_admin(app: Flask) -> None:
    if not app.config.get("DEMO_ADMIN_ENABLED"):
        return
    if app.config.get("APP_ENV") != "development":
        raise RuntimeError("Demo administrator provisioning is development-only.")

    username = app.config.get("DEMO_ADMIN_USERNAME", "")
    email = app.config.get("DEMO_ADMIN_EMAIL", "")
    password = app.config.get("DEMO_ADMIN_PASSWORD", "")
    if not username or not email or not password:
        raise RuntimeError("Demo administrator configuration is incomplete.")

    admin_ids = app.config.get("SECURITY_DASHBOARD_ADMIN_IDS", frozenset())
    query = User.query.filter(
        or_(
            User.is_admin.is_(True),
            User.id.in_(admin_ids) if admin_ids else User.id < 0,
        )
    )
    if query.first() is not None:
        return

    existing_username = User.query.filter_by(username=username).first()
    existing_email = User.query.filter_by(email=email).first()
    if existing_username is not None or existing_email is not None:
        app.logger.warning(
            "Demo administrator was not provisioned because its configured "
            "account name or email is already in use."
        )
        return

    administrator = User(
        username=username,
        email=email,
        is_admin=True,
    )
    administrator.set_password(password)
    try:
        db.session.add(administrator)
        db.session.flush()
        db.session.add(
            SecurityEvent(
                user=administrator,
                event_type="account.registered",
                details="Local demo administrator provisioned.",
            )
        )
        db.session.commit()
    except IntegrityError as error:
        db.session.rollback()
        existing_admin = User.query.filter(
            or_(
                User.is_admin.is_(True),
                User.id.in_(admin_ids) if admin_ids else User.id < 0,
            )
        ).first()
        if existing_admin is not None:
            return
        raise RuntimeError(
            "Demo administrator provisioning encountered an account conflict."
        ) from error
    except SQLAlchemyError as error:
        db.session.rollback()
        app.logger.exception("Demo administrator provisioning failed.")
        raise RuntimeError("Demo administrator provisioning failed.") from error


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def create_app(config_overrides: dict[str, object] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object("config.Config")
    if config_overrides:
        app.config.update(config_overrides)

    secret_key = app.config.get("SECRET_KEY")
    if not isinstance(secret_key, str) or not secret_key.strip():
        raise RuntimeError(
            "Set a non-empty SECRET_KEY environment variable before starting the app."
        )

    app_environment = app.config.get("APP_ENV", "development")
    if app_environment not in {"development", "production"}:
        raise RuntimeError("APP_ENV must be either development or production.")
    if (
        app_environment == "production"
        and (
            config_overrides is None
            or "DEMO_ADMIN_ENABLED" not in config_overrides
        )
    ):
        app.config["DEMO_ADMIN_ENABLED"] = False
    if app_environment == "production" and app.config.get("DEMO_ADMIN_ENABLED"):
        raise RuntimeError("DEMO_ADMIN_ENABLED must be false in production.")
    if app_environment == "production" and not app.config.get(
        "SESSION_COOKIE_SECURE"
    ):
        raise RuntimeError(
            "SESSION_COOKIE_SECURE must be true when APP_ENV is production."
        )
    if app_environment == "production" and app.config.get("FLASK_DEBUG"):
        raise RuntimeError("FLASK_DEBUG must be false when APP_ENV is production.")

    trusted_proxy_count = app.config.get("TRUSTED_PROXY_COUNT", 0)
    if type(trusted_proxy_count) is not int or trusted_proxy_count < 0:
        raise RuntimeError("TRUSTED_PROXY_COUNT must be a non-negative integer.")
    if trusted_proxy_count:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_proto=trusted_proxy_count,
        )

    limiter_storage = app.config.get("RATELIMIT_STORAGE_URI")
    if not app.testing and app_environment == "production" and (
        not isinstance(limiter_storage, str)
        or not limiter_storage.strip()
        or limiter_storage.strip().startswith("memory://")
    ):
        raise RuntimeError(
            "Configure a persistent RATELIMIT_STORAGE_URI for deployment."
        )

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = "main.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "error"
    login_manager.session_protection = "strong"
    csrf.init_app(app)

    from app.routes import main

    app.register_blueprint(main)

    @app.before_request
    def require_https_in_production():
        if app.config["APP_ENV"] == "production" and not request.is_secure:
            return "HTTPS is required.", 400
        return None

    @app.before_request
    def enforce_session_idle_timeout():
        if not current_user.is_authenticated:
            return None

        token = session.get(AUTH_SESSION_TOKEN_KEY)
        if not isinstance(token, str) or not token:
            logout_user()
            session.clear()
            flash("Your session expired. Please sign in again.", "error")
            return redirect(url_for("main.login"))

        now = datetime.now(timezone.utc)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        idle_cutoff = now - timedelta(
            seconds=app.config["SESSION_IDLE_TIMEOUT_SECONDS"]
        )
        max_age_cutoff = now - timedelta(seconds=app.config["SESSION_MAX_AGE_SECONDS"])

        try:
            result = db.session.execute(
                update(UserLoginSession)
                .where(
                    UserLoginSession.token_hash == token_hash,
                    UserLoginSession.user_id == current_user.id,
                    UserLoginSession.created_at > max_age_cutoff,
                    UserLoginSession.created_at <= now,
                    UserLoginSession.last_activity_at > idle_cutoff,
                    UserLoginSession.last_activity_at <= now,
                )
                .execution_options(synchronize_session=False)
                .values(
                    last_activity_at=case(
                        (UserLoginSession.last_activity_at < now, now),
                        else_=UserLoginSession.last_activity_at,
                    )
                )
            )
            if result.rowcount != 1:
                db.session.execute(
                    delete(UserLoginSession).where(
                        UserLoginSession.token_hash == token_hash,
                        UserLoginSession.user_id == current_user.id,
                    )
                )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Authenticated session validation failed.")
            logout_user()
            session.clear()
            flash(
                "Your session could not be verified. Please sign in again.",
                "error",
            )
            return render_template("login.html", email=""), 503

        if result.rowcount != 1:
            logout_user()
            session.clear()
            flash("Your session expired. Please sign in again.", "error")
            return redirect(url_for("main.login"))
        return None

    @app.after_request
    def prevent_authenticated_page_caching(response):
        is_admin_terminal_submission = (
            request.endpoint == "main.login"
            and request.form.get("login_context") == "admin"
        )
        if (
            current_user.is_authenticated
            or is_admin_terminal_submission
            or request.endpoint
            in {
                "main.admin_dashboard",
                "main.admin_login",
                "main.dashboard",
                "main.security_monitoring_dashboard",
                "main.security_monitoring_data",
                "main.mfa_setup",
                "main.mfa_verify",
                "main.logout",
            }
        ):
            response.headers["Cache-Control"] = "no-store, private, max-age=0"
            response.headers["Pragma"] = "no-cache"
        return response

    with app.app_context():
        db.create_all()
        _ensure_user_security_schema()
        if not app.testing:
            _ensure_demo_admin(app)

    return app