"""Сервис временно́й шкалы активности устройств.

``device_activity`` хранит по одной строке на (device_id, minute_ts), где
``minute_ts`` — Unix-секунды, выровненные по минуте UTC (``ts - ts % 60``).
Строки старше 30 дней удаляются лениво при записи новой активности.

Временны́е окна
---------------
``end_ts``   — начало следующей минуты UTC относительно ``now_ts``, то есть
               текущая минута включена: ``(now_ts // 60 + 1) * 60``.
``start_ts`` — ``end_ts`` минус длительность периода:

* ``24h``  → 86 400 с
* ``7d``   → 604 800 с
* ``30d``  → 2 592 000 с

Строки с ``minute_ts < start_ts`` или ``minute_ts >= end_ts`` игнорируются.

Бакеты
------
Бакет — непрерывный диапазон минут длиной ``bucket_seconds``, нумерация от 0:

* ``24h``  → 300 с  (5 мин), 288 бакетов
* ``7d``   → 1800 с (30 мин), 336 бакетов
* ``30d``  → 7200 с (2 ч),   360 бакетов

``active_minutes[i]`` — количество различных активных минут в бакете ``i``.
Нулевые бакеты включены явно; список всегда содержит ровно
``period_seconds // bucket_seconds`` элементов в хронологическом порядке.

``tracking_since_ts`` — Unix-секунды момента первого запуска сервера с этой
схемой. Позволяет UI отличить «нет активности» от «сбор ещё не запускался».
"""
from __future__ import annotations

import sqlite3
import time
from typing import Literal, TypedDict

from fastapi import HTTPException

from server import db

Period = Literal["24h", "7d", "30d"]

_PERIOD_SECONDS: dict[str, int] = {
    "24h": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
}

_BUCKET_SECONDS: dict[str, int] = {
    "24h": 300,
    "7d": 1800,
    "30d": 7200,
}

class ActivitySeries(TypedDict):
    """Временна́я шкала активности устройства."""

    start_ts: int
    end_ts: int
    bucket_seconds: int
    tracking_since_ts: int
    active_minutes: list[int]


def record_activity(conn: sqlite3.Connection, device_id: int) -> None:
    """Записать текущую минуту активности устройства в открытую транзакцию.

    Дедупликация через ON CONFLICT DO NOTHING по PRIMARY KEY (device_id, minute_ts).
    Ленивая очистка старых строк выполняется только при появлении новой минуты.
    Граница удаления: ``minute_ts < current_minute - 30*86400 + 60``.
    """
    minute_ts: int = int(time.time()) // 60 * 60
    cur = conn.execute(
        "INSERT INTO device_activity (device_id, minute_ts) VALUES (?, ?)"
        " ON CONFLICT(device_id, minute_ts) DO NOTHING",
        (device_id, minute_ts),
    )
    if cur.rowcount:
        expire_before = minute_ts + 60 - _PERIOD_SECONDS["30d"]
        conn.execute(
            "DELETE FROM device_activity WHERE minute_ts < ?",
            (expire_before,),
        )


def get_device_activity(device_id: int, period: Period, now_ts: int) -> ActivitySeries:
    """Вернуть временну́ю шкалу активности устройства за указанный период.

    ``now_ts`` — текущий Unix-timestamp (секунды).
    Выбрасывает 404, если устройство не найдено или неактивно.
    """
    period_sec = _PERIOD_SECONDS[period]
    bucket_sec = _BUCKET_SECONDS[period]
    num_buckets = period_sec // bucket_sec

    end_ts: int = (now_ts // 60 + 1) * 60
    start_ts: int = end_ts - period_sec

    with db.get_conn() as c:
        dev = c.execute(
            "SELECT id FROM devices WHERE id = ? AND is_active = 1",
            (device_id,),
        ).fetchone()
        if dev is None:
            raise HTTPException(status_code=404, detail="device not found")

        meta = c.execute(
            "SELECT tracking_since_ts FROM server_meta WHERE id = 1"
        ).fetchone()
        tracking_since_ts: int = meta["tracking_since_ts"] if meta else end_ts

        rows = c.execute(
            "SELECT (minute_ts - ?) / ? AS bucket_idx, COUNT(*) AS cnt"
            " FROM device_activity"
            " WHERE device_id = ? AND minute_ts >= ? AND minute_ts < ?"
            " GROUP BY bucket_idx",
            (start_ts, bucket_sec, device_id, start_ts, end_ts),
        ).fetchall()

    buckets: list[int] = [0] * num_buckets
    for row in rows:
        idx: int = row["bucket_idx"]
        if 0 <= idx < num_buckets:
            buckets[idx] = row["cnt"]

    return ActivitySeries(
        start_ts=start_ts,
        end_ts=end_ts,
        bucket_seconds=bucket_sec,
        tracking_since_ts=tracking_since_ts,
        active_minutes=buckets,
    )
