"""Auth helpers: bcrypt password verify, web session dep, agent bearer dep."""
from __future__ import annotations

import logging
import secrets
from datetime import datetime
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, status

from server import db
from server.config import Config
from server.services import api_keys as api_key_svc
from server.services.activity import record_activity

log = logging.getLogger("auth")

# populated at app build time
_CONFIG: Optional[Config] = None


def configure(cfg: Config) -> None:
    global _CONFIG
    _CONFIG = cfg


def _cfg() -> Config:
    if _CONFIG is None:
        raise RuntimeError("auth.configure() must be called first")
    return _CONFIG


# ---------- web session ----------

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def login_session(request: Request, username: str) -> None:
    request.session["user"] = username
    request.session["login_at"] = datetime.utcnow().isoformat()


def logout_session(request: Request) -> None:
    request.session.clear()


def current_user(request: Request) -> Optional[str]:
    return request.session.get("user")


def require_user_api(request: Request) -> str:
    """Dep for /api/web/* — raises 401 JSON if no session."""
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


def require_web_api(request: Request) -> str:
    """Аутентификация для /api/web/*: Bearer API-ключ или cookie-сессия администратора.

    При наличии заголовка Authorization проверяется исключительно Bearer API-ключ
    без перехода к cookie. Неверный заголовок вызывает 401. При отсутствии Authorization
    требуется сессия администратора.
    """
    if "authorization" in request.headers:
        token = _extract_bearer(request.headers.get("authorization"))
        if not token or not api_key_svc.verify_api_key(token):
            raise HTTPException(status_code=401, detail="invalid api key")
        return _cfg().auth.username
    return require_user_api(request)


# ---------- agent bearer token ----------

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        # leftmost = original client
        first = fwd.split(",")[0].strip()
        if first:
            return first
    if request.client:
        return request.client.host
    return ""


def _extract_bearer(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, value = parts
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    return value or None


def get_current_device(request: Request) -> dict:
    """Проверить активное устройство по Bearer-токену и обновить last_seen/last_ip.

    Выбрасывает 401 при отсутствии или недействительности токена / неактивности устройства.
    При первом валидном запросе гасит связанную заявку approved -> revoked.
    """
    token = _extract_bearer(request.headers.get("authorization"))
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")

    ip = _client_ip(request)

    with db.transaction("IMMEDIATE") as c:
        row = c.execute(
            "SELECT * FROM devices WHERE token = ? AND is_active = 1",
            (token,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="invalid token")

        if not secrets.compare_digest(row["token"], token):
            raise HTTPException(status_code=401, detail="invalid token")

        # Погасить одобренную заявку после первого валидного запроса с токеном
        c.execute(
            "UPDATE enrollments SET status = 'revoked', token = NULL WHERE device_id = ? AND status = 'approved'",
            (row["id"],),
        )

        c.execute(
            "UPDATE devices SET last_seen = CURRENT_TIMESTAMP, last_ip = ? WHERE id = ?",
            (ip, row["id"]),
        )
        record_activity(c, row["id"])
        return dict(row)
