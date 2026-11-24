from datetime import datetime, timezone

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from flask_login import UserMixin
from sqlalchemy.orm import synonym

from app.extensions import db

_password_hasher = PasswordHasher(
    type=Type.ID,
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_admin = db.Column(
        db.Boolean, nullable=False, default=False, server_default=db.false()
    )
    mfa_enabled = db.Column(
        db.Boolean, nullable=False, default=False, server_default=db.false()
    )
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_last_counter = db.Column(db.BigInteger, nullable=True)
    failed_login_attempts = db.Column(
        db.Integer, nullable=False, default=0, server_default="0"
    )
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("uq_users_mfa_secret", "mfa_secret", unique=True),
    )

    login_attempts = db.relationship("LoginAttempt", back_populates="user")
    security_events = db.relationship("SecurityEvent", back_populates="user")

    def set_password(self, password: str) -> None:
        self.password_hash = _password_hasher.hash(password)

    def check_password(self, password: str) -> bool:
        try:
            return _password_hasher.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False


# Preserve existing SQLite column names while exposing clearer model attributes.
class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    attempted_identifier = db.Column(db.String(254), nullable=False)
    success = db.Column("succeeded", db.Boolean, nullable=False)
    succeeded = synonym("success")
    attempted_at = db.Column(
        "created_at",
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    created_at = synonym("attempted_at")

    user = db.relationship("User", back_populates="login_attempts")


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    description = db.Column("details", db.String(255), nullable=False)
    details = synonym("description")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship("User", back_populates="security_events")


class UserLoginSession(db.Model):
    __tablename__ = "user_login_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_activity_at = db.Column(db.DateTime(timezone=True), nullable=False)


class SimulationEvent(db.Model):
    __tablename__ = "simulation_events"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.String(32), nullable=False, index=True)
    scenario = db.Column(db.String(32), nullable=False)
    attempt_number = db.Column(db.Integer, nullable=False)
    outcome = db.Column(db.String(32), nullable=False)
    details = db.Column(db.String(200), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )