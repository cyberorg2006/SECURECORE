import ipaddress
import base64
import hashlib
import re
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit

from email_validator import EmailNotValidError, validate_email
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    AnonymousUserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage
from sqlalchemy import Integer, case, cast, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.extensions import AUTH_SESSION_TOKEN_KEY, db, limiter
from app.models import (
    LoginAttempt,
    SecurityEvent,
    SimulationEvent,
    User,
    UserLoginSession,
)

main = Blueprint("main", __name__)

_MFA_PENDING_USER_ID = "mfa_pending_user_id"
_MFA_PENDING_AT = "mfa_pending_at"
_MFA_PENDING_ADMIN_REDIRECT = "mfa_pending_admin_redirect"
_MFA_CHALLENGE_TTL_SECONDS = 300
_SIMULATOR_MAX_ATTEMPTS = 20
_SIMULATOR_RATE_LIMIT_ATTEMPTS = 5
_SIMULATOR_LOCKOUT_ATTEMPTS = 5
_SIMULATOR_PASSWORD_MATCH_ATTEMPT = 8
_SIMULATOR_SCENARIOS = ("unprotected", "rate_limited", "lockout", "mfa")
_SIMULATOR_SCENARIO_LABELS = {
    "unprotected": "Unprotected mock",
    "rate_limited": "Rate-limited mock",
    "lockout": "Account lockout",
    "mfa": "MFA enabled",
}
_SECURITY_EVENT_TYPES = (
    "admin.access.denied",
    "account.registered",
    "account.locked",
    "account.unlocked",
    "login.failed",
    "login.succeeded",
    "logout",
    "mfa.challenge",
    "mfa.enabled",
    "mfa.failed",
)
_SECURITY_DETECTION_TYPES = (
    "detection.failed_burst",
    "detection.repeated_attempts",
    "detection.success_after_failures",
    "detection.mfa_failures",
)
_SECURITY_EVENT_LABELS = {
    "admin.access.denied": "Admin access denied",
    "account.registered": "Account registered",
    "account.locked": "Account locked",
    "account.unlocked": "Account unlocked",
    "login.failed": "Login failed",
    "login.succeeded": "Login succeeded",
    "logout": "Signed out",
    "mfa.challenge": "MFA challenge",
    "mfa.enabled": "MFA enabled",
    "mfa.failed": "MFA failed",
    "detection.failed_burst": "Failed-login burst",
    "detection.repeated_attempts": "Repeated login activity",
    "detection.success_after_failures": "Success after failures",
    "detection.mfa_failures": "Repeated MFA failures",
}
_SECURITY_SEVERITIES = ("info", "low", "medium", "high", "critical")
_SECURITY_SEVERITY_RANGES = {
    "info": (0, 19),
    "low": (20, 39),
    "medium": (40, 69),
    "high": (70, 89),
    "critical": (90, 100),
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _lockout_is_active(user: User, now: datetime | None = None) -> bool:
    locked_until = _as_utc(user.locked_until)
    return locked_until is not None and locked_until > (now or _utc_now())


def _is_admin_user(user: User | AnonymousUserMixin) -> bool:
    if not user.is_authenticated:
        return False
    if getattr(user, "is_admin", False):
        return True

    admin_ids = current_app.config.get("SECURITY_DASHBOARD_ADMIN_IDS", ())
    user_id = user.get_id()
    return type(user_id) is str and user_id.isdigit() and int(user_id) in admin_ids


def _is_security_monitoring_admin() -> bool:
    return _is_admin_user(current_user)


def _security_event_score_expression():
    return case(
        (SecurityEvent.event_type == "admin.access.denied", 45),
        (SecurityEvent.event_type == "account.locked", 85),
        (SecurityEvent.event_type == "mfa.failed", 55),
        (SecurityEvent.event_type == "login.failed", 25),
        (SecurityEvent.event_type == "account.unlocked", 20),
        else_=5,
    )


def _severity_for_score(score: int) -> str:
    for severity in reversed(_SECURITY_SEVERITIES):
        lower, upper = _SECURITY_SEVERITY_RANGES[severity]
        if lower <= score <= upper:
            return severity
    return "info"


def _monitoring_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _security_monitoring_date_range() -> tuple[date, date, datetime, datetime]:
    start_text = request.args.get("start_date", "")
    end_text = request.args.get("end_date", "")
    today = datetime.now(timezone.utc).date()
    if not start_text and not end_text:
        start_date = today - timedelta(days=6)
        end_date = today
    elif not start_text or not end_text:
        raise ValueError("Provide both a start date and an end date.")
    else:
        try:
            start_date = date.fromisoformat(start_text)
            end_date = date.fromisoformat(end_text)
        except ValueError as error:
            raise ValueError("Dates must use the YYYY-MM-DD format.") from error

    if start_date > end_date:
        raise ValueError("The start date must not be after the end date.")
    if (end_date - start_date).days > 89:
        raise ValueError("Choose a date range of 90 days or less.")

    start_at = datetime.combine(
        start_date, datetime.min.time(), tzinfo=timezone.utc
    )
    end_at = datetime.combine(
        end_date + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )
    return start_date, end_date, start_at, end_at


def _security_monitoring_payload(
    start_date: date,
    end_date: date,
    start_at: datetime,
    end_at: datetime,
    event_type_filter: str,
    severity_filter: str,
) -> dict[str, object]:
    attempt_range = (
        LoginAttempt.attempted_at >= start_at,
        LoginAttempt.attempted_at < end_at,
    )
    successful_count, failed_count = db.session.execute(
        select(
            func.coalesce(
                func.sum(case((LoginAttempt.success.is_(True), 1), else_=0)),
                0,
            ),
            func.coalesce(
                func.sum(case((LoginAttempt.success.is_(False), 1), else_=0)),
                0,
            ),
        ).where(*attempt_range)
    ).one()

    event_range = (
        SecurityEvent.created_at >= start_at,
        SecurityEvent.created_at < end_at,
    )
    event_counts = dict(
        db.session.execute(
            select(SecurityEvent.event_type, func.count())
            .where(*event_range)
            .group_by(SecurityEvent.event_type)
        ).all()
    )
    mfa_enabled_account_logins = db.session.scalar(
        select(func.count(LoginAttempt.id))
        .join(User, User.id == LoginAttempt.user_id)
        .where(
            *attempt_range,
            LoginAttempt.success.is_(True),
            User.mfa_enabled.is_(True),
        )
    )
    stats = {
        "registered_users": db.session.scalar(select(func.count(User.id))) or 0,
        "successful_logins": successful_count,
        "failed_login_attempts": failed_count,
        "account_lockout_events": event_counts.get("account.locked", 0),
        "account_unlock_events": event_counts.get("account.unlocked", 0),
        "mfa_challenges": event_counts.get("mfa.challenge", 0),
        "mfa_failed_verifications": event_counts.get("mfa.failed", 0),
        "mfa_enabled_events": event_counts.get("mfa.enabled", 0),
        "mfa_enabled_account_logins": mfa_enabled_account_logins or 0,
    }

    timeline_counts: dict[str, dict[str, int]] = {}
    current_day = start_date
    while current_day <= end_date:
        timeline_counts[current_day.isoformat()] = {
            "successful_logins": 0,
            "failed_logins": 0,
            "lockouts": 0,
            "mfa_activity": 0,
        }
        current_day += timedelta(days=1)

    attempt_day = func.date(LoginAttempt.attempted_at)
    for day, succeeded, count in db.session.execute(
        select(attempt_day, LoginAttempt.success, func.count())
        .where(*attempt_range)
        .group_by(attempt_day, LoginAttempt.success)
    ):
        day_counts = timeline_counts.get(day)
        if day_counts is not None:
            key = "successful_logins" if succeeded else "failed_logins"
            day_counts[key] += count

    event_day = func.date(SecurityEvent.created_at)
    for day, event_name, count in db.session.execute(
        select(event_day, SecurityEvent.event_type, func.count())
        .where(
            *event_range,
            SecurityEvent.event_type.in_(
                ("account.locked", "mfa.challenge", "mfa.failed", "mfa.enabled")
            ),
        )
        .group_by(event_day, SecurityEvent.event_type)
    ):
        day_counts = timeline_counts.get(day)
        if day_counts is not None:
            if event_name == "account.locked":
                day_counts["lockouts"] += count
            else:
                day_counts["mfa_activity"] += count
    timeline = [
        {"date": day, **counts} for day, counts in timeline_counts.items()
    ]

    event_score = _security_event_score_expression()
    security_event_query = (
        select(
            SecurityEvent.id,
            SecurityEvent.event_type,
            SecurityEvent.description,
            SecurityEvent.created_at,
            User.username,
            event_score.label("risk_score"),
        )
        .outerjoin(User, User.id == SecurityEvent.user_id)
        .where(*event_range)
    )
    if event_type_filter != "all":
        if event_type_filter in _SECURITY_EVENT_TYPES:
            security_event_query = security_event_query.where(
                SecurityEvent.event_type == event_type_filter
            )
        else:
            security_event_query = security_event_query.where(
                SecurityEvent.id < 0
            )
    if severity_filter != "all":
        lower, upper = _SECURITY_SEVERITY_RANGES[severity_filter]
        security_event_query = security_event_query.where(
            event_score.between(lower, upper)
        )
    security_event_rows = db.session.execute(
        security_event_query.order_by(SecurityEvent.created_at.desc()).limit(100)
    ).all()
    events = [
        {
            "id": row.id,
            "event_type": row.event_type,
            "label": _SECURITY_EVENT_LABELS.get(row.event_type, row.event_type),
            "actor": row.username or "Unknown account",
            "details": row.description,
            "timestamp": _monitoring_timestamp(row.created_at),
            "risk_score": row.risk_score,
            "severity": _severity_for_score(row.risk_score),
        }
        for row in security_event_rows
    ]

    alerts: list[dict[str, object]] = []

    def add_alert(
        alert_type: str,
        title: str,
        actor: str,
        details: str,
        timestamp: datetime,
        risk_score: int,
        occurrences: int,
    ) -> None:
        alerts.append(
            {
                "event_type": alert_type,
                "label": _SECURITY_EVENT_LABELS[alert_type],
                "title": title,
                "actor": actor,
                "details": details,
                "timestamp": _monitoring_timestamp(timestamp),
                "risk_score": risk_score,
                "severity": _severity_for_score(risk_score),
                "occurrences": occurrences,
            }
        )

    five_minute_bucket = (
        cast(func.strftime("%s", LoginAttempt.attempted_at), Integer) / 300
    )
    failure_sum = func.sum(
        case((LoginAttempt.success.is_(False), 1), else_=0)
    )
    success_sum = func.sum(
        case((LoginAttempt.success.is_(True), 1), else_=0)
    )
    attempt_bursts = db.session.execute(
        select(
            User.username,
            five_minute_bucket,
            func.max(LoginAttempt.attempted_at),
            func.count(LoginAttempt.id),
            failure_sum,
            success_sum,
        )
        .outerjoin(User, User.id == LoginAttempt.user_id)
        .where(*attempt_range)
        .group_by(
            func.lower(LoginAttempt.attempted_identifier),
            User.id,
            User.username,
            five_minute_bucket,
        )
        .having(func.count(LoginAttempt.id) >= 3)
        .order_by(func.max(LoginAttempt.attempted_at).desc())
        .limit(250)
    ).all()
    for username, _, last_attempt, total, failures, successes in attempt_bursts:
        failures = failures or 0
        successes = successes or 0
        if failures >= 3 and successes:
            alert_type = "detection.success_after_failures"
            score = 85
            title = "Successful login in a failure burst"
        elif failures >= 5:
            alert_type = "detection.failed_burst"
            score = 80
            title = "Repeated failed login attempts"
        elif total >= 10:
            alert_type = "detection.repeated_attempts"
            score = 95
            title = "Very frequent login activity"
        elif total >= 5:
            alert_type = "detection.repeated_attempts"
            score = 70
            title = "Repeated login activity"
        elif failures >= 3:
            alert_type = "detection.failed_burst"
            score = 60
            title = "Multiple failed login attempts"
        else:
            continue

        actor = username or "Unrecognized account (identifier withheld)"
        add_alert(
            alert_type,
            title,
            actor,
            (
                f"{failures} failed and {successes} successful login attempt(s) "
                "were recorded for this account in one five-minute window."
            ),
            last_attempt,
            score,
            total,
        )

    mfa_bucket = cast(func.strftime("%s", SecurityEvent.created_at), Integer) / 300
    mfa_failure_bursts = db.session.execute(
        select(
            User.username,
            func.max(SecurityEvent.created_at),
            func.count(SecurityEvent.id),
        )
        .outerjoin(User, User.id == SecurityEvent.user_id)
        .where(
            *event_range,
            SecurityEvent.event_type == "mfa.failed",
        )
        .group_by(SecurityEvent.user_id, User.username, mfa_bucket)
        .having(func.count(SecurityEvent.id) >= 3)
        .order_by(func.max(SecurityEvent.created_at).desc())
        .limit(100)
    ).all()
    for username, last_event, failures in mfa_failure_bursts:
        add_alert(
            "detection.mfa_failures",
            "Repeated MFA verification failures",
            username or "Unknown account",
            f"{failures} failed MFA verifications were recorded in one five-minute window.",
            last_event,
            75,
            failures,
        )

    if event_type_filter in ("all", "account.locked"):
        locked_events = db.session.execute(
            select(
                SecurityEvent.created_at,
                SecurityEvent.description,
                User.username,
            )
            .outerjoin(User, User.id == SecurityEvent.user_id)
            .where(
                *event_range,
                SecurityEvent.event_type == "account.locked",
            )
            .order_by(SecurityEvent.created_at.desc())
            .limit(100)
        ).all()
        for timestamp, details, username in locked_events:
            add_alert(
                "account.locked",
                "Account lockout recorded",
                username or "Unknown account",
                details,
                timestamp,
                85,
                1,
            )

    if event_type_filter != "all":
        alerts = [
            alert
            for alert in alerts
            if alert["event_type"] == event_type_filter
        ]
    if severity_filter != "all":
        alerts = [
            alert
            for alert in alerts
            if alert["severity"] == severity_filter
        ]
    alerts.sort(key=lambda alert: alert["timestamp"], reverse=True)

    return {
        "filters": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "event_type": event_type_filter,
            "severity": severity_filter,
        },
        "stats": stats,
        "timeline": timeline,
        "events": events,
        "alerts": alerts[:100],
        "event_types": [
            {"value": value, "label": _SECURITY_EVENT_LABELS[value]}
            for value in (*_SECURITY_EVENT_TYPES, *_SECURITY_DETECTION_TYPES)
        ],
    }


def _is_local_simulator_request() -> bool:
    if not current_app.config.get("BRUTE_FORCE_SIMULATOR_ENABLED"):
        return False

    remote_addr = request.remote_addr
    if not isinstance(remote_addr, str):
        return False
    try:
        remote_is_loopback = ipaddress.ip_address(remote_addr).is_loopback
        hostname = urlsplit(f"//{request.host}").hostname
        if hostname is None:
            return False
        hostname = hostname.casefold().rstrip(".")
        host_is_loopback = hostname == "localhost" or ipaddress.ip_address(
            hostname
        ).is_loopback
    except ValueError:
        return False
    return remote_is_loopback and host_is_loopback


def _simulate_mock_authentication(
    scenario: str, attempt_count: int
) -> tuple[str, dict[str, int], list[dict[str, str | int]]]:
    run_id = secrets.token_hex(16)
    mock_password = secrets.token_urlsafe(12)
    guesses = [secrets.token_urlsafe(6) for _ in range(attempt_count)]
    if attempt_count >= _SIMULATOR_PASSWORD_MATCH_ATTEMPT:
        guesses[_SIMULATOR_PASSWORD_MATCH_ATTEMPT - 1] = mock_password

    events: list[dict[str, str | int]] = []
    consecutive_failures = 0
    account_locked = False

    for attempt_number, guess in enumerate(guesses, start=1):
        password_matches = guess == mock_password
        details = ""
        if (
            scenario == "rate_limited"
            and attempt_number > _SIMULATOR_RATE_LIMIT_ATTEMPTS
        ):
            outcome = "blocked_rate_limit"
            details = "The mock rate limiter blocked this attempt."
        elif scenario == "lockout" and account_locked:
            outcome = "blocked_lockout"
            details = "The mock account is locked after repeated failures."
        elif scenario == "unprotected":
            outcome = "success" if password_matches else "failed"
            details = (
                "Synthetic password matched; mock authentication succeeded."
                if password_matches
                else "Synthetic guess rejected by mock authentication."
            )
        elif scenario == "rate_limited":
            outcome = "success" if password_matches else "failed"
            details = (
                "Synthetic password matched; mock authentication succeeded."
                if password_matches
                else "Synthetic guess rejected by the mock authentication."
            )
        elif scenario == "lockout":
            if password_matches:
                outcome = "success"
                details = "Synthetic password matched; mock authentication succeeded."
            else:
                outcome = "failed"
                consecutive_failures += 1
                details = "Synthetic guess rejected by mock authentication."
                if consecutive_failures >= _SIMULATOR_LOCKOUT_ATTEMPTS:
                    account_locked = True
                    details = (
                        "Synthetic guess rejected; the mock account is now locked."
                    )
        elif scenario == "mfa":
            if password_matches:
                outcome = "mfa_required"
                details = (
                    "Password matched; mock MFA is still required. "
                    "No OTP was submitted."
                )
            else:
                outcome = "failed"
                details = "Synthetic guess rejected by mock authentication."
        else:
            raise ValueError("Unsupported simulator scenario.")

        event = {
            "attempt_number": attempt_number,
            "guess_label": f"Synthetic guess {attempt_number}",
            "outcome": outcome,
            "details": details,
        }
        events.append(event)
        db.session.add(
            SimulationEvent(
                run_id=run_id,
                scenario=scenario,
                attempt_number=attempt_number,
                outcome=outcome,
                details=details,
            )
        )

    summary = {
        "successful_guesses": sum(
            event["outcome"] in {"success", "mfa_required"} for event in events
        ),
        "failed_guesses": sum(event["outcome"] == "failed" for event in events),
        "blocked_attempts": sum(
            str(event["outcome"]).startswith("blocked_") for event in events
        ),
        "completed_logins": sum(event["outcome"] == "success" for event in events),
    }
    return run_id, summary, events


def _create_login_session(user: User, now: datetime) -> str:
    token = secrets.token_urlsafe(32)
    db.session.add(
        UserLoginSession(
            user_id=user.id,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            created_at=now,
            last_activity_at=now,
        )
    )
    return token


def _establish_authenticated_session(user: User, token: str) -> None:
    session.clear()
    login_user(user, remember=False, fresh=True)
    session[AUTH_SESSION_TOKEN_KEY] = token
    session.permanent = True


def _expire_lockout(user: User, now: datetime) -> None:
    result = db.session.execute(
        update(User)
        .where(
            User.id == user.id,
            User.locked_until.is_not(None),
            User.locked_until <= now,
        )
        .execution_options(synchronize_session=False)
        .values(failed_login_attempts=0, locked_until=None)
    )
    if result.rowcount == 1:
        db.session.add(
            SecurityEvent(
                user_id=user.id,
                event_type="account.unlocked",
                details="Temporary account lockout expired.",
            )
        )
        db.session.commit()
        db.session.refresh(user)


def _reset_failed_logins(user: User, now: datetime) -> bool:
    result = db.session.execute(
        update(User)
        .where(
            User.id == user.id,
            or_(User.locked_until.is_(None), User.locked_until <= now),
        )
        .execution_options(synchronize_session=False)
        .values(failed_login_attempts=0, locked_until=None)
    )
    return result.rowcount == 1


def _record_failed_password(user: User, identifier: str, now: datetime) -> bool:
    threshold = current_app.config["LOGIN_MAX_FAILED_ATTEMPTS"]
    lockout_seconds = current_app.config["LOGIN_LOCKOUT_DURATION_SECONDS"]
    lockout_until = now + timedelta(seconds=lockout_seconds)
    expired_lockout = (
        User.locked_until.is_not(None) & (User.locked_until <= now)
    )
    next_attempts = case(
        (expired_lockout, 1),
        else_=User.failed_login_attempts + 1,
    )
    result = db.session.execute(
        update(User)
        .where(
            User.id == user.id,
            or_(User.locked_until.is_(None), User.locked_until <= now),
        )
        .execution_options(synchronize_session=False)
        .values(
            failed_login_attempts=next_attempts,
            locked_until=case(
                (next_attempts >= threshold, lockout_until),
                else_=None,
            ),
        )
    )
    db.session.add(
        LoginAttempt(
            user=user,
            attempted_identifier=identifier[:254],
            succeeded=False,
        )
    )
    db.session.add(
        SecurityEvent(
            user=user,
            event_type="login.failed",
            details="Invalid credentials.",
        )
    )

    locked = result.rowcount != 1
    if result.rowcount == 1:
        db.session.refresh(user)
        locked = _lockout_is_active(user, now)
        if locked and user.failed_login_attempts >= threshold:
            db.session.add(
                SecurityEvent(
                    user=user,
                    event_type="account.locked",
                    details=(
                        "Account temporarily locked after repeated failed "
                        "password attempts."
                    ),
                )
            )
    db.session.commit()
    return locked


def _clear_mfa_challenge() -> None:
    session.pop(_MFA_PENDING_USER_ID, None)
    session.pop(_MFA_PENDING_AT, None)
    session.pop(_MFA_PENDING_ADMIN_REDIRECT, None)


def _pending_mfa_user() -> User | None:
    user_id = session.get(_MFA_PENDING_USER_ID)
    issued_at = session.get(_MFA_PENDING_AT)
    now = int(time.time())
    if (
        type(user_id) is not int
        or type(issued_at) is not int
        or issued_at > now
        or now - issued_at > _MFA_CHALLENGE_TTL_SECONDS
    ):
        _clear_mfa_challenge()
        return None

    user = db.session.get(User, user_id)
    if (
        user is None
        or not user.is_active
        or not user.mfa_enabled
        or not user.mfa_secret
    ):
        _clear_mfa_challenge()
        return None
    return user


def _verified_totp_counter(
    secret: str, token: str, last_counter: int | None
) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", token):
        return None

    totp = pyotp.TOTP(secret)
    now = datetime.now(timezone.utc)
    counter = totp.timecode(now)
    if last_counter is not None and counter <= last_counter:
        return None
    if not totp.verify(token, for_time=now, valid_window=0):
        return None
    return counter


def _mfa_setup_response(user: User, status: int = 200):
    qr_data_uri = None
    if user.mfa_secret:
        provisioning_uri = pyotp.TOTP(user.mfa_secret).provisioning_uri(
            name=user.email,
            issuer_name="SECURECORE",
        )
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        svg = qr.make_image(image_factory=SvgPathImage).to_string()
        if isinstance(svg, str):
            svg = svg.encode("utf-8")
        image = base64.b64encode(svg).decode("ascii")
        qr_data_uri = f"data:image/svg+xml;base64,{image}"
    response = make_response(
        render_template(
            "mfa_setup.html",
            qr_data_uri=qr_data_uri,
        ),
        status,
    )
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def _mfa_verify_response(status: int = 200):
    response = make_response(render_template("mfa_verify.html"), status)
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


def _record_mfa_attempt(user: User, succeeded: bool, event_type: str) -> None:
    db.session.add(
        LoginAttempt(
            user=user,
            attempted_identifier=user.email,
            succeeded=succeeded,
        )
    )
    db.session.add(
        SecurityEvent(
            user=user,
            event_type=event_type,
            details=(
                "MFA authentication succeeded."
                if succeeded
                else "Invalid or expired MFA code."
            ),
        )
    )


@main.route("/")
def home():
    return render_template("index.html")


@main.route("/experience")
def experience():
    return render_template(
        "experience.html",
        is_admin=_is_admin_user(current_user),
    )


@main.route("/brute-force-simulator")
def brute_force_simulator():
    if not _is_local_simulator_request():
        abort(404)
    return render_template(
        "brute_force_simulator.html",
        max_attempts=_SIMULATOR_MAX_ATTEMPTS,
    )


@main.route("/api/simulation/brute-force", methods=["POST"])
@limiter.limit("5 per minute", methods=["POST"])
def run_brute_force_simulation():
    if not _is_local_simulator_request():
        abort(404)
    if not request.is_json:
        return jsonify(error="A JSON simulation request is required."), 400

    payload = request.get_json()
    if not isinstance(payload, dict):
        return jsonify(error="Invalid simulation request."), 400

    attempt_count = payload.get("attempt_count")
    scenario = payload.get("scenario")
    if (
        type(attempt_count) is not int
        or not 1 <= attempt_count <= _SIMULATOR_MAX_ATTEMPTS
        or not isinstance(scenario, str)
        or scenario not in _SIMULATOR_SCENARIOS
    ):
        return jsonify(
            error=f"Choose 1-{_SIMULATOR_MAX_ATTEMPTS} attempts and a supported scenario."
        ), 400

    try:
        run_id, summary, events = _simulate_mock_authentication(
            scenario, attempt_count
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Mock brute-force simulation could not be recorded.")
        return jsonify(error="The simulation could not be recorded. Please retry."), 503

    return jsonify(
        run_id=run_id,
        scenario=scenario,
        attempt_count=attempt_count,
        summary=summary,
        events=events,
    )


def _attack_dashboard_data(scenario_filter: str) -> dict[str, object]:
    outcome_query = select(
        SimulationEvent.scenario,
        SimulationEvent.outcome,
        func.count(),
    ).group_by(SimulationEvent.scenario, SimulationEvent.outcome)
    if scenario_filter != "all":
        outcome_query = outcome_query.where(
            SimulationEvent.scenario == scenario_filter
        )

    outcome_counts: dict[str, dict[str, int]] = {
        scenario: {} for scenario in _SIMULATOR_SCENARIOS
    }
    for scenario, outcome, count in db.session.execute(outcome_query):
        outcome_counts[scenario][outcome] = count

    def count(scenario: str, outcome: str) -> int:
        return outcome_counts[scenario].get(outcome, 0)

    def scenario_totals(scenario: str) -> dict[str, int | str]:
        failed = count(scenario, "failed")
        rate_blocked = count(scenario, "blocked_rate_limit")
        lockout_blocked = count(scenario, "blocked_lockout")
        completed = count(scenario, "success")
        mfa_challenges = count(scenario, "mfa_required")
        return {
            "scenario": scenario,
            "label": _SIMULATOR_SCENARIO_LABELS[scenario],
            "total": sum(outcome_counts[scenario].values()),
            "failed": failed,
            "blocked": rate_blocked + lockout_blocked,
            "completed": completed,
            "mfa_challenges": mfa_challenges,
        }

    visible_scenarios = (
        list(_SIMULATOR_SCENARIOS)
        if scenario_filter == "all"
        else [scenario_filter]
    )
    comparison = [scenario_totals(scenario) for scenario in visible_scenarios]
    total_attacks = sum(int(item["total"]) for item in comparison)
    failed_guesses = sum(int(item["failed"]) for item in comparison)
    blocked_attempts = sum(int(item["blocked"]) for item in comparison)
    completed_logins = sum(int(item["completed"]) for item in comparison)
    mfa_challenges = sum(int(item["mfa_challenges"]) for item in comparison)
    successful_guesses = completed_logins + mfa_challenges
    defence_stops = blocked_attempts + mfa_challenges

    rate_totals = scenario_totals("rate_limited")
    lockout_totals = scenario_totals("lockout")
    mfa_totals = scenario_totals("mfa")
    mfa_password_matches = (
        int(mfa_totals["completed"]) + int(mfa_totals["mfa_challenges"])
    )

    def percentage(numerator: int, denominator: int) -> float | None:
        if denominator == 0:
            return None
        return round(numerator * 100 / denominator, 1)

    stats = {
        "total_attacks": total_attacks,
        "failed_password_guesses": failed_guesses,
        "blocked_attempts": blocked_attempts,
        "successful_simulated_guesses": successful_guesses,
        "completed_mock_logins": completed_logins,
        "defence_stops": defence_stops,
        "defence_success_percent": percentage(defence_stops, total_attacks),
        "rate_limited_attempts": int(rate_totals["total"]),
        "rate_limit_blocks": count("rate_limited", "blocked_rate_limit"),
        "rate_limiting_effectiveness_percent": percentage(
            count("rate_limited", "blocked_rate_limit"),
            int(rate_totals["total"]),
        ),
        "lockout_attempts": int(lockout_totals["total"]),
        "lockout_blocks": count("lockout", "blocked_lockout"),
        "account_lockout_effectiveness_percent": percentage(
            count("lockout", "blocked_lockout"),
            int(lockout_totals["total"]),
        ),
        "mfa_password_matches": mfa_password_matches,
        "mfa_challenges": int(mfa_totals["mfa_challenges"]),
        "mfa_completed_logins": int(mfa_totals["completed"]),
        "mfa_protection_percent": percentage(
            int(mfa_totals["mfa_challenges"]), mfa_password_matches
        ),
    }

    now = datetime.now(timezone.utc)
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    first_hour = current_hour - timedelta(hours=23)
    hours = [first_hour + timedelta(hours=index) for index in range(24)]
    timeline_counts = {
        hour.strftime("%Y-%m-%d %H"): {
            "attempts": 0,
            "failed": 0,
            "blocked": 0,
            "completed": 0,
            "mfa_challenges": 0,
        }
        for hour in hours
    }
    bucket = func.strftime("%Y-%m-%d %H", SimulationEvent.created_at)
    timeline_query = (
        select(bucket, SimulationEvent.outcome, func.count())
        .where(
            SimulationEvent.created_at >= first_hour,
            SimulationEvent.created_at <= now,
        )
        .group_by(bucket, SimulationEvent.outcome)
        .order_by(bucket)
    )
    if scenario_filter != "all":
        timeline_query = timeline_query.where(
            SimulationEvent.scenario == scenario_filter
        )

    for bucket_key, outcome, count_in_bucket in db.session.execute(timeline_query):
        bucket_counts = timeline_counts.get(bucket_key)
        if bucket_counts is None:
            continue
        bucket_counts["attempts"] += count_in_bucket
        if outcome == "failed":
            bucket_counts["failed"] += count_in_bucket
        elif outcome in {"blocked_rate_limit", "blocked_lockout"}:
            bucket_counts["blocked"] += count_in_bucket
        elif outcome == "success":
            bucket_counts["completed"] += count_in_bucket
        elif outcome == "mfa_required":
            bucket_counts["mfa_challenges"] += count_in_bucket

    timeline = [
        {
            "timestamp": hour.isoformat(timespec="hours"),
            "label": hour.strftime("%d %b %H:00"),
            **timeline_counts[hour.strftime("%Y-%m-%d %H")],
        }
        for hour in hours
    ]

    return {
        "scenario": scenario_filter,
        "stats": stats,
        "comparison": comparison,
        "timeline": timeline,
        "has_data": total_attacks > 0,
        "updated_at": now.isoformat(timespec="seconds"),
    }


@main.route("/attack-vs-defence")
def attack_vs_defence_dashboard():
    if not _is_local_simulator_request():
        abort(404)
    return render_template(
        "attack_vs_defence.html",
        scenarios=_SIMULATOR_SCENARIO_LABELS,
        dashboard_url=url_for("main.attack_vs_defence_data"),
    )


@main.route("/api/attack-vs-defence")
@limiter.limit("30 per minute", methods=["GET"])
def attack_vs_defence_data():
    if not _is_local_simulator_request():
        abort(404)
    scenario_filter = request.args.get("scenario", "all")
    if scenario_filter != "all" and scenario_filter not in _SIMULATOR_SCENARIOS:
        return jsonify(error="Choose a supported simulation scenario."), 400

    try:
        return jsonify(_attack_dashboard_data(scenario_filter))
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Attack-versus-defence statistics failed.")
        return jsonify(error="Statistics are temporarily unavailable."), 503


@main.route("/admin/login")
def admin_login():
    if current_user.is_authenticated:
        if _is_admin_user(current_user):
            return redirect(url_for("main.experience"))
        return redirect(url_for("main.dashboard"))
    return render_template("admin_terminal.html", terminal_state="login")


@main.route("/admin")
@login_required
def admin_dashboard():
    if not _is_admin_user(current_user):
        abort(404)
    return render_template("admin_dashboard.html")


@main.route("/security-monitoring")
@login_required
def security_monitoring_dashboard():
    if not _is_security_monitoring_admin():
        abort(404)
    today = datetime.now(timezone.utc).date()
    return render_template(
        "security_monitoring.html",
        default_start_date=(today - timedelta(days=6)).isoformat(),
        default_end_date=today.isoformat(),
        dashboard_url=url_for("main.security_monitoring_data"),
        event_types=[
            {"value": value, "label": _SECURITY_EVENT_LABELS[value]}
            for value in (*_SECURITY_EVENT_TYPES, *_SECURITY_DETECTION_TYPES)
        ],
        severities=_SECURITY_SEVERITIES,
    )


@main.route("/api/security-monitoring")
@limiter.limit("30 per minute", methods=["GET"])
def security_monitoring_data():
    if not current_user.is_authenticated:
        return jsonify(error="Sign in to view security monitoring data."), 401
    if not _is_security_monitoring_admin():
        abort(404)

    event_type_filter = request.args.get("event_type", "all")
    severity_filter = request.args.get("severity", "all")
    if event_type_filter not in (
        "all",
        *_SECURITY_EVENT_TYPES,
        *_SECURITY_DETECTION_TYPES,
    ):
        return jsonify(error="Choose a supported event type."), 400
    if severity_filter not in ("all", *_SECURITY_SEVERITIES):
        return jsonify(error="Choose a supported severity."), 400
    try:
        start_date, end_date, start_at, end_at = (
            _security_monitoring_date_range()
        )
    except ValueError as error:
        return jsonify(error=str(error)), 400

    try:
        return jsonify(
            _security_monitoring_payload(
                start_date,
                end_date,
                start_at,
                end_at,
                event_type_filter,
                severity_filter,
            )
        )
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Security monitoring query failed.")
        return jsonify(error="Security monitoring data is temporarily unavailable."), 503


@main.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    username = ""
    email_input = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip().casefold()
        email_input = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password_confirmation = request.form.get("password_confirmation", "")

        if not re.fullmatch(r"[a-z0-9_]{3,32}", username):
            flash(
                "Username must be 3-32 characters using letters, numbers, or underscores.",
                "error",
            )
            return render_template(
                "register.html", username=username, email=email_input
            ), 400

        if not email_input or len(email_input) > 254:
            flash("Enter a valid email address.", "error")
            return render_template(
                "register.html", username=username, email=email_input
            ), 400

        try:
            email = validate_email(
                email_input, check_deliverability=False
            ).normalized.casefold()
        except EmailNotValidError:
            flash("Enter a valid email address.", "error")
            return render_template(
                "register.html", username=username, email=email_input
            ), 400

        if len(password) < 12 or len(password) > 128:
            flash("Password must be between 12 and 128 characters.", "error")
            return render_template(
                "register.html", username=username, email=email_input
            ), 400

        if password != password_confirmation:
            flash("The password confirmation does not match.", "error")
            return render_template(
                "register.html", username=username, email=email_input
            ), 400

        try:
            existing_user = db.session.execute(
                select(User).where(
                    or_(User.username == username, User.email == email)
                )
            ).scalar_one_or_none()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Registration uniqueness check failed.")
            flash(
                "Registration is temporarily unavailable. Please try again.",
                "error",
            )
            return render_template(
                "register.html", username=username, email=email_input
            ), 503

        if existing_user is not None:
            flash("That username or email address is already registered.", "error")
            return render_template(
                "register.html", username=username, email=email_input
            ), 409

        user = User(username=username, email=email)
        user.set_password(password)
        try:
            db.session.add(user)
            db.session.flush()
            db.session.add(
                SecurityEvent(
                    user=user,
                    event_type="account.registered",
                    details="Account created.",
                )
            )
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            error_message = str(error.orig)
            if (
                "UNIQUE constraint failed: users.username" in error_message
                or "UNIQUE constraint failed: users.email" in error_message
            ):
                flash(
                    "That username or email address is already registered.",
                    "error",
                )
                return render_template(
                    "register.html", username=username, email=email_input
                ), 409

            current_app.logger.exception(
                "Registration integrity constraint failed."
            )
            flash(
                "Account registration could not be completed. Please try again.",
                "error",
            )
            return render_template(
                "register.html", username=username, email=email_input
            ), 500
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Registration database write failed.")
            flash(
                "Account registration could not be completed. Please try again.",
                "error",
            )
            return render_template(
                "register.html", username=username, email=email_input
            ), 500

        flash("Your account has been created. You can now sign in.", "success")
        return redirect(url_for("main.register"))

    return render_template("register.html", username=username, email=email_input)


def _login_failure_response(
    email: str, admin_terminal: bool, status: int = 401
) -> tuple[str, int]:
    if admin_terminal:
        return render_template(
            "admin_terminal.html", terminal_state="failure"
        ), status
    flash(
        "Invalid email or password. If this account is temporarily locked, "
        "wait five minutes before trying again.",
        "error",
    )
    return render_template("login.html", email=email), status


@main.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    email = ""

    if request.method == "POST":
        admin_terminal = request.form.get("login_context") == "admin"
        _clear_mfa_challenge()
        email = request.form.get("email", "").strip().casefold()
        identifier = (
            request.form.get("username", "").strip().casefold()
            if admin_terminal
            else email
        )
        password = request.form.get("password", "")
        user = None
        session_token = None

        try:
            if admin_terminal:
                if re.fullmatch(r"[a-z0-9_]{3,32}", identifier):
                    user = db.session.execute(
                        select(User).where(User.username == identifier)
                    ).scalar_one_or_none()
            elif email and len(email) <= 254:
                user = db.session.execute(
                    select(User).where(User.email == email)
                ).scalar_one_or_none()

            now = _utc_now()
            if user is not None:
                _expire_lockout(user, now)

            if user is not None and _lockout_is_active(user, now):
                db.session.add(
                    LoginAttempt(
                        user=user,
                        attempted_identifier=identifier[:254],
                        succeeded=False,
                    )
                )
                if admin_terminal:
                    db.session.add(
                        SecurityEvent(
                            user=user,
                            event_type="login.failed",
                            details="Invalid credentials.",
                        )
                    )
                db.session.commit()
                return _login_failure_response(email, admin_terminal)

            password_verified = bool(
                user is not None
                and user.is_active
                and password
                and len(password) <= 128
                and user.check_password(password)
            )
            if (
                admin_terminal
                and password_verified
                and user is not None
                and not _is_admin_user(user)
            ):
                db.session.add(
                    LoginAttempt(
                        user=user,
                        attempted_identifier=identifier[:254],
                        succeeded=False,
                    )
                )
                db.session.add(
                    SecurityEvent(
                        user=user,
                        event_type="admin.access.denied",
                        details="Non-administrator account denied admin terminal access.",
                    )
                )
                db.session.commit()
                return _login_failure_response(email, admin_terminal)

            if (
                password_verified
                and user is not None
                and user.mfa_enabled
                and user.mfa_secret
            ):
                db.session.add(
                    SecurityEvent(
                        user=user,
                        event_type="mfa.challenge",
                        details="Password verified; MFA challenge issued.",
                    )
                )
                db.session.commit()
                session.clear()
                session.permanent = True
                session[_MFA_PENDING_USER_ID] = user.id
                session[_MFA_PENDING_AT] = int(time.time())
                if admin_terminal:
                    session[_MFA_PENDING_ADMIN_REDIRECT] = True
                return redirect(url_for("main.mfa_verify"))

            authenticated = bool(password_verified and not user.mfa_enabled)
            if password_verified and user.mfa_enabled and not user.mfa_secret:
                authenticated = False

            if authenticated and user is not None:
                if not _reset_failed_logins(user, now):
                    authenticated = False
                    db.session.add(
                        LoginAttempt(
                            user=user,
                            attempted_identifier=identifier[:254],
                            succeeded=False,
                        )
                    )
                    db.session.add(
                        SecurityEvent(
                            user=user,
                            event_type="login.failed",
                            details="Login blocked by an active account lockout.",
                        )
                    )
                else:
                    db.session.add(
                        LoginAttempt(
                            user=user,
                            attempted_identifier=identifier[:254],
                            succeeded=True,
                        )
                    )
                    db.session.add(
                        SecurityEvent(
                            user=user,
                            event_type="login.succeeded",
                            details="User authenticated.",
                        )
                    )
            elif not password_verified:
                if user is not None:
                    _record_failed_password(user, identifier, now)
                else:
                    db.session.add(
                        LoginAttempt(
                            attempted_identifier=identifier[:254],
                            succeeded=False,
                        )
                    )
                    db.session.add(
                        SecurityEvent(
                            event_type="login.failed",
                            details="Invalid credentials.",
                        )
                    )
            else:
                db.session.add(
                    LoginAttempt(
                        user=user,
                        attempted_identifier=identifier[:254],
                        succeeded=False,
                    )
                )
                db.session.add(
                    SecurityEvent(
                        user=user,
                        event_type="login.failed",
                        details="Invalid credentials.",
                    )
                )
            if authenticated and user is not None:
                session_token = _create_login_session(user, now)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Login attempt could not be recorded.")
            if admin_terminal:
                return render_template(
                    "admin_terminal.html", terminal_state="unavailable"
                ), 503
            flash("Sign-in is temporarily unavailable. Please try again.", "error")
            return render_template("login.html", email=email), 503

        if authenticated and user is not None and session_token is not None:
            _establish_authenticated_session(user, session_token)
            flash("You are signed in.", "success")
            if admin_terminal:
                return render_template(
                    "admin_terminal.html", terminal_state="success"
                )
            return redirect(url_for("main.dashboard"))

        return _login_failure_response(email, admin_terminal)

    return render_template("login.html", email=email)


@main.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    user = current_user
    if user.mfa_enabled:
        flash("Multi-factor authentication is already enabled.", "success")
        return redirect(url_for("main.dashboard"))

    if request.method == "POST" and not user.mfa_secret:
        if request.form.get("action") != "generate":
            flash("Start MFA setup before entering a verification code.", "error")
            return _mfa_setup_response(user, 400)

        user.mfa_secret = pyotp.random_base32()
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.error("MFA setup secret could not be saved.")
            flash("MFA setup is temporarily unavailable. Please try again.", "error")
            return render_template("dashboard.html"), 503
        return redirect(url_for("main.mfa_setup"))

    secret = user.mfa_secret
    if secret is None:
        return _mfa_setup_response(user)

    if request.method == "POST":
        token = request.form.get("otp", "").strip()
        counter = _verified_totp_counter(secret, token, user.mfa_last_counter)
        if counter is None:
            flash("That code is invalid or expired. Enter the current code.", "error")
            return _mfa_setup_response(user, 400)

        try:
            result = db.session.execute(
                update(User)
                .where(
                    User.id == user.id,
                    User.mfa_enabled.is_(False),
                    User.mfa_secret == secret,
                    or_(
                        User.mfa_last_counter.is_(None),
                        User.mfa_last_counter < counter,
                    ),
                )
                .values(mfa_enabled=True, mfa_last_counter=counter)
            )
            if result.rowcount != 1:
                db.session.rollback()
                flash("That code is invalid or expired. Enter the current code.", "error")
                return _mfa_setup_response(user, 400)

            db.session.add(
                SecurityEvent(
                    user=user,
                    event_type="mfa.enabled",
                    details="Multi-factor authentication enabled.",
                )
            )
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.error("MFA setup verification failed.")
            flash("MFA setup is temporarily unavailable. Please try again.", "error")
            return render_template("dashboard.html"), 503

        flash("Multi-factor authentication is enabled.", "success")
        return redirect(url_for("main.dashboard"))

    return _mfa_setup_response(user)


@main.route("/mfa/verify", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def mfa_verify():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    user = _pending_mfa_user()
    if user is None:
        flash("Your verification session expired. Sign in again.", "error")
        return redirect(url_for("main.login"))

    secret = user.mfa_secret
    if secret is None:
        _clear_mfa_challenge()
        flash("Your verification session expired. Sign in again.", "error")
        return redirect(url_for("main.login"))

    if request.method == "POST":
        now = _utc_now()
        try:
            _expire_lockout(user, now)
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.exception("Expired account lockout could not be cleared.")
            flash("Verification is temporarily unavailable. Please try again.", "error")
            return _mfa_verify_response(503)
        if _lockout_is_active(user, now):
            _clear_mfa_challenge()
            flash(
                "This account is temporarily locked. Please wait five minutes "
                "before signing in again.",
                "error",
            )
            return redirect(url_for("main.login"))

        token = request.form.get("otp", "").strip()
        counter = _verified_totp_counter(secret, token, user.mfa_last_counter)
        if counter is None:
            try:
                _record_mfa_attempt(user, False, "mfa.failed")
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
                current_app.logger.error("MFA attempt could not be recorded.")
                flash("Verification is temporarily unavailable. Please try again.", "error")
                return _mfa_verify_response(503)
            flash("That code is invalid or expired. Enter the current code.", "error")
            return _mfa_verify_response(401)

        try:
            result = db.session.execute(
                update(User)
                .where(
                    User.id == user.id,
                    User.mfa_enabled.is_(True),
                    User.mfa_secret == secret,
                    or_(User.locked_until.is_(None), User.locked_until <= now),
                    or_(
                        User.mfa_last_counter.is_(None),
                        User.mfa_last_counter < counter,
                    ),
                )
                .execution_options(synchronize_session=False)
                .values(
                    mfa_last_counter=counter,
                    failed_login_attempts=0,
                    locked_until=None,
                )
            )
            if result.rowcount != 1:
                db.session.rollback()
                _record_mfa_attempt(user, False, "mfa.failed")
                db.session.commit()
                flash("That code is invalid or expired. Enter the current code.", "error")
                return _mfa_verify_response(401)

            _record_mfa_attempt(user, True, "login.succeeded")
            session_token = _create_login_session(user, now)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            current_app.logger.error("MFA attempt could not be recorded.")
            flash("Verification is temporarily unavailable. Please try again.", "error")
            return _mfa_verify_response(503)

        admin_terminal = session.pop(_MFA_PENDING_ADMIN_REDIRECT, False) is True
        _establish_authenticated_session(user, session_token)
        flash("You are signed in.", "success")
        if admin_terminal and _is_admin_user(user):
            return render_template(
                "admin_terminal.html", terminal_state="success"
            )
        return redirect(url_for("main.dashboard"))

    return _mfa_verify_response()


@main.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@main.route("/logout", methods=["POST"])
@login_required
def logout():
    token = session.get(AUTH_SESSION_TOKEN_KEY)
    try:
        if isinstance(token, str):
            db.session.execute(
                delete(UserLoginSession).where(
                    UserLoginSession.user_id == current_user.id,
                    UserLoginSession.token_hash
                    == hashlib.sha256(token.encode("utf-8")).hexdigest(),
                )
            )
        db.session.add(
            SecurityEvent(
                user_id=current_user.id,
                event_type="logout",
                details="User signed out.",
            )
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Logout session revocation failed.")
        logout_user()
        session.clear()
        flash("Your local session was cleared, but sign-out could not be verified.", "error")
        return render_template("login.html", email=""), 503

    logout_user()
    session.clear()
    flash("You are signed out.", "success")
    return redirect(url_for("main.login"))