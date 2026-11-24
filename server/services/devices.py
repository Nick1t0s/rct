"""Управление устройствами и списком активных хостов."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException

from server import db

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def normalize_mac(mac: str) -> Optional[str]:
    """Нормализовать MAC-адрес к верхнему регистру с двоеточиями."""
    if not mac or not _MAC_RE.match(mac):
        return None
    return mac.replace("-", ":").upper()


def _parse_ts(ts: str) -> Optional[datetime]:
    """Преобразовать строку времени SQLite UTC в datetime."""
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return None


def list_devices(online_threshold_sec: int) -> list[dict]:
    """Получить список только привязанных (активных) устройств с признаком online."""
    now = datetime.now(timezone.utc)
    with db.get_conn() as c:
        rows = c.execute(
            "SELECT id, mac, hostname, last_ip, first_seen, last_seen "
            "FROM devices WHERE is_active = 1 ORDER BY id"
        ).fetchall()

    out: list[dict] = []
    for r in rows:
        ls = _parse_ts(r["last_seen"]) if isinstance(r["last_seen"], str) else r["last_seen"]
        if isinstance(ls, datetime) and ls.tzinfo is None:
            ls = ls.replace(tzinfo=timezone.utc)
        online = False
        if ls is not None:
            online = (now - ls).total_seconds() < online_threshold_sec
        out.append({
            "id": r["id"],
            "mac": r["mac"],
            "hostname": r["hostname"],
            "last_ip": r["last_ip"],
            "last_seen": r["last_seen"] if isinstance(r["last_seen"], str) else (ls.isoformat() if ls else None),
            "online": online,
        })
    return out


def get_device(device_id: int) -> Optional[dict]:
    """Получить устройство по идентификатору."""
    with db.get_conn() as c:
        r = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return dict(r) if r else None


def unlink_device(device_id: int) -> None:
    """Отвязать устройство: исключить из активных, закрыть заявки и отменить команды."""
    with db.transaction("IMMEDIATE") as c:
        row = c.execute(
            "SELECT id, is_active FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None or not row["is_active"]:
            raise HTTPException(status_code=404, detail="device not found")

        # Исключаем токен из авторизации и помечаем устройство неактивным
        c.execute(
            "UPDATE devices SET is_active = 0, token = 'revoked:' || id || ':' || hex(randomblob(16)) WHERE id = ?",
            (device_id,),
        )

        # Закрываем соответствующие заявки
        c.execute(
            "UPDATE enrollments SET status = 'revoked', token = NULL WHERE device_id = ?",
            (device_id,),
        )

        # Помечаем незавершённые команды как error с причиной отвязки
        c.execute(
            "UPDATE commands SET status = 'error', output = 'Device revoked', completed_at = CURRENT_TIMESTAMP "
            "WHERE device_id = ? AND status IN ('pending', 'in_progress')",
            (device_id,),
        )
