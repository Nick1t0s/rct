"""Сервис выпуска, проверки и отзыва API-ключей администратора."""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import TypedDict

from fastapi import HTTPException

from server import db

_TOKEN_PREFIX = "rac_"
_TOKEN_RANDOM_BYTES = 32
_TOKEN_RE = re.compile(r"rac_[A-Za-z0-9_-]{43}")


class ApiKeyInfo(TypedDict):
    """Данные действующего API-ключа для отображения в списке."""

    id: int
    name: str
    created_at: str


class CreatedApiKey(TypedDict):
    """Данные созданного API-ключа с сырым токеном."""

    id: int
    name: str
    created_at: str
    token: str


def hash_token(token: str) -> str:
    """Вычислить SHA-256 хеш полного токена."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_valid_token_format(token: str) -> bool:
    """Строго проверить формат токена rac_ + 43 символа urlsafe."""
    return _TOKEN_RE.fullmatch(token) is not None


def generate_raw_token() -> str:
    """Сгенерировать сырой токен rac_ + secrets.token_urlsafe(32)."""
    return f"{_TOKEN_PREFIX}{secrets.token_urlsafe(_TOKEN_RANDOM_BYTES)}"


def list_api_keys() -> list[ApiKeyInfo]:
    """Получить список действующих API-ключей без секретов."""
    with db.get_conn() as c:
        rows = c.execute(
            "SELECT id, name, created_at FROM api_keys ORDER BY id ASC"
        ).fetchall()
    return [
        {
            "id": int(r["id"]),
            "name": str(r["name"]),
            "created_at": str(r["created_at"]),
        }
        for r in rows
    ]


def create_api_key(name: str) -> CreatedApiKey:
    """Выпустить новый API-ключ с уникальным токеном."""
    clean_name = name.strip()
    if not 1 <= len(clean_name) <= 80:
        raise HTTPException(status_code=400, detail="name must be between 1 and 80 characters")

    token = generate_raw_token()
    digest = hash_token(token)

    with db.transaction("IMMEDIATE") as c:
        cur = c.execute(
            "INSERT INTO api_keys (name, key_hash) VALUES (?, ?)",
            (clean_name, digest),
        )
        key_id = cur.lastrowid
        row = c.execute(
            "SELECT id, name, created_at FROM api_keys WHERE id = ?",
            (key_id,),
        ).fetchone()

    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "created_at": str(row["created_at"]),
        "token": token,
    }


def revoke_api_key(key_id: int) -> bool:
    """Отозвать API-ключ по ID с удалением записи. Возвращает True, если ключ найден."""
    with db.transaction("IMMEDIATE") as c:
        cur = c.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        return bool(cur.rowcount and cur.rowcount > 0)


def verify_api_key(token: str) -> bool:
    """Проверить подлинность Bearer API-ключа в базе данных."""
    if not is_valid_token_format(token):
        return False

    digest = hash_token(token)
    with db.get_conn() as c:
        row = c.execute(
            "SELECT key_hash FROM api_keys WHERE key_hash = ?",
            (digest,),
        ).fetchone()

    if row is None:
        return False

    return secrets.compare_digest(str(row["key_hash"]), digest)
