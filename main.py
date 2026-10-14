"""
Infinity OTP Notification Bot

This bot sends a safe alert with a masked number, country, service, and the
full SMS text with detected OTP codes replaced by same-length asterisks.

Install:
    pip install -r requirements.txt

Run:
    python otp.py
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import os
import re
import sqlite3
import sys
import time
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Lock
from typing import Any, Optional
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNetworkError,
    TelegramRetryAfter,
    TelegramServerError,
)
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    CopyTextButton,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)


# =============================================================================
# CONFIG — change these values
# =============================================================================

# Keep credentials outside the source code. Set these on the VPS:
# TELEGRAM_BOT_TOKEN and API_TOKEN.
CONFIG_BOT_TOKEN = "8947321218:AAGfUqvqZBeKyp-G60nPByndFyLWhUHTqr0"
CONFIG_API_KEY = "QlJQQUFBUzRgjVeGY2p1amWWlIRfUZddSW1Sintyj2p8UVFleI53ag=="
CONFIG_GROUP_CHAT_ID = -1003954183073
CONFIG_GET_NUMBER_URL = "https://t.me/Tahachen_otpbot"
CONFIG_MAIN_CHANNEL_URL = "https://t.me/Tshunterzone"
# Put Telegram numeric user IDs here, or set ADMIN_IDS="123,456" in the
# environment.  Environment values take precedence when present.
CONFIG_ADMIN_IDS: tuple[int, ...] = (5450557557,)

# SMS Hadi panel API
CONFIG_API_URL = "http://147.135.212.197/crapi/had/viewstats"

# Voltx SMS panel API
CONFIG_VOLTX_API_URL = (
    "https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api/success-otp"
)
CONFIG_VOLTX_AUTH_KEY = "MF5260ZN039"

# Red X SMS panel API
CONFIG_REDX_API_URL = "https://redxsms.com/api/v1/iprn/messages"
CONFIG_REDX_API_KEY = "sk_live_6w9tAa2cFQhBN0QwMc93Tq7tZFZGuzxoUIFcKjFR"

CONFIG_HADI_POLL_SECONDS = 4
CONFIG_POLL_SECONDS = 7
CONFIG_API_RECORDS = 1000
CONFIG_API_TIMEOUT_SECONDS = 15
CONFIG_API_RETRIES = 3
CONFIG_DB_PATH = str(Path(__file__).with_name("otp_notifications.sqlite3"))
CONFIG_SEND_WORKERS = 8
CONFIG_SEND_RETRY_BASE_SECONDS = 1
CONFIG_SEND_RETRY_MAX_SECONDS = 30
CONFIG_SEND_LEASE_SECONDS = 300
CONFIG_TELEGRAM_MIN_INTERVAL_SECONDS = 0.12


# Environment variables override the values above when present.
BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or CONFIG_BOT_TOKEN).strip()
API_KEY = (os.getenv("API_TOKEN") or CONFIG_API_KEY).strip()
GROUP_CHAT_ID = int(os.getenv("OTP_GROUP_CHAT_ID") or CONFIG_GROUP_CHAT_ID)
GET_NUMBER_URL = (os.getenv("GET_NUMBER_URL") or CONFIG_GET_NUMBER_URL).strip()
MAIN_CHANNEL_URL = (os.getenv("MAIN_CHANNEL_URL") or CONFIG_MAIN_CHANNEL_URL).strip()
API_URL = (os.getenv("OTP_API_URL") or CONFIG_API_URL).strip()
try:
    ADMIN_IDS = {
        int(value.strip())
        for value in os.getenv("ADMIN_IDS", "").split(",")
        if value.strip()
    } or set(CONFIG_ADMIN_IDS)
except ValueError:
    sys.exit("ADMIN_IDS-এ শুধু numeric Telegram user ID ব্যবহার করুন।")
VOLTX_API_URL = (
    os.getenv("VOLTX_API_URL") or CONFIG_VOLTX_API_URL
).strip()
VOLTX_AUTH_KEY = (os.getenv("VOLTX_AUTH_KEY") or CONFIG_VOLTX_AUTH_KEY).strip()
VOLTX_ENABLED = bool(VOLTX_AUTH_KEY)
REDX_API_URL = (os.getenv("REDX_API_URL") or CONFIG_REDX_API_URL).strip()
REDX_API_KEY = (os.getenv("REDX_API_KEY") or CONFIG_REDX_API_KEY).strip()
# Temporarily blocked until the Red X admin confirms the API rate limit.
# Red X code and configuration remain in place so it can be enabled later.
REDX_ENABLED = False
REDX_TYPE = (os.getenv("REDX_TYPE") or "a2p").strip()
REDX_PER_PAGE = max(1, int(os.getenv("REDX_PER_PAGE") or "50"))
REDX_LOOKBACK_DAYS = max(
    0, int(os.getenv("REDX_LOOKBACK_DAYS") or "1")
)
REDX_START_DATE_OVERRIDE = (
    os.getenv("REDX_START_DATE") or ""
).strip()
HADI_POLL_SECONDS = max(
    2,
    int(os.getenv("HADI_POLL_SECONDS") or CONFIG_HADI_POLL_SECONDS),
)
POLL_SECONDS = max(5, int(os.getenv("OTP_POLL_SECONDS") or CONFIG_POLL_SECONDS))
# CR API HADI documentation specifies a maximum of 2000 records per request.
API_RECORDS = min(
    2000,
    max(10, int(os.getenv("OTP_API_RECORDS") or CONFIG_API_RECORDS)),
)
API_TIMEOUT_SECONDS = max(
    5, int(os.getenv("OTP_API_TIMEOUT_SECONDS") or CONFIG_API_TIMEOUT_SECONDS)
)
API_RETRIES = max(1, int(os.getenv("OTP_API_RETRIES") or CONFIG_API_RETRIES))
DB_PATH = os.getenv("OTP_NOTIFICATION_DB_PATH") or CONFIG_DB_PATH
SEND_WORKERS = max(1, int(os.getenv("OTP_SEND_WORKERS") or CONFIG_SEND_WORKERS))
SEND_RETRY_BASE_SECONDS = max(
    0.25,
    float(
        os.getenv("OTP_SEND_RETRY_BASE_SECONDS")
        or CONFIG_SEND_RETRY_BASE_SECONDS
    ),
)
SEND_RETRY_MAX_SECONDS = max(
    SEND_RETRY_BASE_SECONDS,
    float(
        os.getenv("OTP_SEND_RETRY_MAX_SECONDS")
        or CONFIG_SEND_RETRY_MAX_SECONDS
    ),
)
SEND_LEASE_SECONDS = max(
    60,
    int(os.getenv("OTP_SEND_LEASE_SECONDS") or CONFIG_SEND_LEASE_SECONDS),
)
TELEGRAM_MIN_INTERVAL_SECONDS = max(
    0.05,
    float(
        os.getenv("OTP_TELEGRAM_MIN_INTERVAL_SECONDS")
        or CONFIG_TELEGRAM_MIN_INTERVAL_SECONDS
    ),
)
TELEGRAM_MAX_TEXT_LENGTH = 4096

PLACEHOLDERS = {
    "",
    "https://t.me/your_number_bot",
    "https://t.me/your_main_channel",
}

if BOT_TOKEN in PLACEHOLDERS:
    sys.exit("TELEGRAM_BOT_TOKEN environment variable সেট করুন।")
if API_KEY in PLACEHOLDERS:
    sys.exit("API_TOKEN environment variable সেট করুন।")
if GROUP_CHAT_ID == 0:
    sys.exit("CONFIG_GROUP_CHAT_ID-এ আপনার OTP group-এর numeric chat ID বসান।")
if GET_NUMBER_URL in PLACEHOLDERS:
    sys.exit("CONFIG_GET_NUMBER_URL-এ আপনার Get Number bot-এর link বসান।")
if MAIN_CHANNEL_URL in PLACEHOLDERS:
    sys.exit("CONFIG_MAIN_CHANNEL_URL-এ আপনার Main Channel-এর link বসান।")


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)-8s | %(message)s",
)
logger = logging.getLogger("infinity.otp.notifications")
dispatcher = Dispatcher()
last_panel_api_ok = False
last_voltx_api_ok = not VOLTX_ENABLED
last_redx_api_ok = not REDX_ENABLED
telegram_send_lock = asyncio.Lock()
telegram_next_allowed_at = 0.0
telegram_cooldown_until = 0.0
redx_request_lock = Lock()
redx_rate_limit_until = 0.0


class AdminStates(StatesGroup):
    waiting_for_panel_url = State()
    waiting_for_panel_key = State()
    waiting_for_group_chat_id = State()
    waiting_for_main_channel_url = State()
    waiting_for_number_bot_url = State()


if not VOLTX_ENABLED:
    logger.warning(
        "VOLTX_AUTH_KEY is not set; Voltx forwarding is disabled. "
        "SMS Hadi forwarding remains active."
    )
if not REDX_ENABLED:
    logger.warning(
        "Red X forwarding is temporarily disabled. "
        "SMS Hadi and Voltx forwarding remain active."
    )


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def db_connection() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db() -> None:
    with closing(db_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS seen_notifications (
                dedupe_key TEXT PRIMARY KEY,
                phone_number TEXT NOT NULL,
                country TEXT NOT NULL,
                service TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_outbox (
                dedupe_key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                lease_until REAL NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_notification_outbox_ready
            ON notification_outbox(status, next_attempt_at, created_at)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS bot_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dynamic_panels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                api_url TEXT NOT NULL,
                api_key TEXT,
                poll_seconds INTEGER NOT NULL DEFAULT 7,
                is_active INTEGER NOT NULL DEFAULT 1,
                last_error TEXT NOT NULL DEFAULT '',
                disabled_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )
        # Keep databases created by the first admin-panel revision compatible.
        dynamic_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(dynamic_panels)").fetchall()
        }
        if "last_error" not in dynamic_columns:
            conn.execute(
                "ALTER TABLE dynamic_panels ADD COLUMN last_error TEXT NOT NULL DEFAULT ''"
            )
        if "disabled_at" not in dynamic_columns:
            conn.execute(
                "ALTER TABLE dynamic_panels ADD COLUMN disabled_at TEXT NOT NULL DEFAULT ''"
            )
        # A single production process owns this database. Any "sending" item
        # left by a crashed process must become immediately retryable.
        conn.execute(
            """
            UPDATE notification_outbox
            SET status = 'pending', lease_until = 0, updated_at = ?
            WHERE status = 'sending'
            """,
            (now_utc(),),
        )
        conn.commit()


def get_setting(key: str, default: Any) -> Any:
    with closing(db_connection()) as conn:
        row = conn.execute(
            "SELECT value FROM bot_settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with closing(db_connection()) as conn:
        conn.execute(
            """
            INSERT INTO bot_settings(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, str(value)),
        )
        conn.commit()


def get_active_dynamic_panels() -> list[dict[str, Any]]:
    with closing(db_connection()) as conn:
        rows = conn.execute(
            "SELECT * FROM dynamic_panels WHERE is_active = 1 ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def get_all_dynamic_panels() -> list[dict[str, Any]]:
    with closing(db_connection()) as conn:
        rows = conn.execute(
            "SELECT * FROM dynamic_panels ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def get_dynamic_panel(panel_id: int) -> Optional[dict[str, Any]]:
    with closing(db_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM dynamic_panels WHERE id = ?", (panel_id,)
        ).fetchone()
        return dict(row) if row else None


def disable_dynamic_panel(panel_id: int, error: str) -> None:
    """Disable only the failing dynamic panel; never touch core panels."""
    with closing(db_connection()) as conn:
        conn.execute(
            """
            UPDATE dynamic_panels
            SET is_active = 0, last_error = ?, disabled_at = ?
            WHERE id = ?
            """,
            (error[:1000], now_utc(), panel_id),
        )
        conn.commit()


def clear_dynamic_panel_error(panel_id: int) -> None:
    with closing(db_connection()) as conn:
        conn.execute(
            """
            UPDATE dynamic_panels
            SET last_error = '', disabled_at = ''
            WHERE id = ?
            """,
            (panel_id,),
        )
        conn.commit()


def normalize_number(value: str) -> str:
    value = str(value or "").strip()
    if value.startswith("+"):
        return "+" + re.sub(r"\D", "", value[1:])
    return re.sub(r"\D", "", value)


def mask_number(value: str) -> str:
    """Hide the middle four digits and preserve the remaining digits."""
    normalized = normalize_number(value)
    prefix = "+" if normalized.startswith("+") else ""
    digits = normalized[1:] if prefix else normalized
    if len(digits) <= 8:
        return prefix + "****"
    start = (len(digits) - 4) // 2
    return prefix + digits[:start] + "****" + digits[start + 4 :]


def has_otp_code(message: str) -> bool:
    cleaned = " ".join(str(message or "").split())
    if not cleaned:
        return False
    if re.search(
        r"\b(?:no\s+(?:records?|messages?|sms)|not\s+found|empty)\b",
        cleaned,
        re.IGNORECASE,
    ):
        return False
    return bool(_otp_match(cleaned))


def extract_otp_code(message: str) -> str:
    match = _otp_match(str(message or ""))
    return re.sub(r"\D", "", match.group("digits")) if match else ""


_otp_candidate_pattern = re.compile(
    r"(?<![\d+])(?P<prefix>[A-Za-z][A-Za-z0-9_]{0,24}[\s:=#-]*)?"
    r"(?P<digits>\d(?:[\s-]*\d){3,7})(?!\d)",
    re.IGNORECASE,
)
_otp_context_pattern = re.compile(
    r"\b(?:otp|one[\s-]*time|verification|verify|security|login|"
    r"pass(?:code|word)?|auth(?:entication)?|code|pin|token)\b",
    re.IGNORECASE,
)
_non_otp_context_pattern = re.compile(
    r"\b(?:phone|number|mobile|tel|call|amount|balance|order|ref(?:erence)?|"
    r"account|expires?\s+in)\b",
    re.IGNORECASE,
)


def _otp_match(message: str) -> Optional[re.Match[str]]:
    """Return the best 4–8 digit OTP candidate, not merely the first number."""
    text = str(message or "")
    candidates = list(_otp_candidate_pattern.finditer(text))
    if not candidates:
        return None

    scored: list[tuple[int, int, re.Match[str]]] = []
    for match in candidates:
        digits = re.sub(r"\D", "", match.group("digits"))
        if not 4 <= len(digits) <= 8:
            continue
        start = max(0, match.start() - 80)
        end = min(len(text), match.end() + 80)
        context = text[start:end]
        score = 0
        if match.group("prefix"):
            score += 5
        score += 8 * len(_otp_context_pattern.findall(context))
        score -= 7 * len(_non_otp_context_pattern.findall(context))
        # A long numeric run is normally a phone/order/reference number.
        before = text[max(0, match.start() - 2):match.start()]
        after = text[match.end():match.end() + 2]
        if before.endswith("+") or re.search(r"\d", before + after):
            score -= 20
        scored.append((score, -match.start(), match))
    if not scored:
        return None
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return scored[0][2]


def hide_otp_codes(message: str) -> str:
    """Show the SMS text while masking each OTP with same-length asterisks."""
    def mask_match(match: re.Match[str]) -> str:
        return "*" * len(match.group(0))

    return _otp_pattern.sub(mask_match, str(message or "").strip())


_otp_pattern = re.compile(
    r"(?<![\d+])(?:[A-Za-z][A-Za-z0-9_]{0,24}[\s:=#-]*)?"
    r"\d(?:[\s-]*\d){3,7}(?!\d)",
    re.IGNORECASE,
)


def alpha2_flag(code: str) -> str:
    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        return ""
    return "".join(chr(ord(char) + 127397) for char in code)


COUNTRY_PREFIXES: tuple[tuple[str, str, str], ...] = (
    # Longest prefixes must be checked first because some calling codes share
    # the same leading digits.
    ("35818", "AX", "Åland Islands"),
    ("358", "FI", "Finland"),
    ("1242", "BS", "Bahamas"),
    ("1246", "BB", "Barbados"),
    ("1264", "AI", "Anguilla"),
    ("1268", "AG", "Antigua and Barbuda"),
    ("1284", "VG", "British Virgin Islands"),
    ("1340", "VI", "U.S. Virgin Islands"),
    ("1345", "KY", "Cayman Islands"),
    ("1441", "BM", "Bermuda"),
    ("1473", "GD", "Grenada"),
    ("1649", "TC", "Turks and Caicos Islands"),
    ("1658", "US", "United States"),
    ("1670", "MP", "Northern Mariana Islands"),
    ("1671", "GU", "Guam"),
    ("1684", "AS", "American Samoa"),
    ("1721", "SX", "Sint Maarten"),
    ("1758", "LC", "Saint Lucia"),
    ("1767", "DM", "Dominica"),
    ("1784", "VC", "Saint Vincent and the Grenadines"),
    ("1787", "PR", "Puerto Rico"),
    ("1809", "DO", "Dominican Republic"),
    ("1829", "DO", "Dominican Republic"),
    ("1849", "DO", "Dominican Republic"),
    ("1868", "TT", "Trinidad and Tobago"),
    ("1869", "KN", "Saint Kitts and Nevis"),
    ("1876", "JM", "Jamaica"),
    ("1939", "PR", "Puerto Rico"),
    ("20", "EG", "Egypt"),
    ("211", "SS", "South Sudan"),
    ("212", "MA", "Morocco"),
    ("213", "DZ", "Algeria"),
    ("216", "TN", "Tunisia"),
    ("218", "LY", "Libya"),
    ("220", "GM", "Gambia"),
    ("221", "SN", "Senegal"),
    ("222", "MR", "Mauritania"),
    ("223", "ML", "Mali"),
    ("224", "GN", "Guinea"),
    ("225", "CI", "Côte d'Ivoire"),
    ("226", "BF", "Burkina Faso"),
    ("227", "NE", "Niger"),
    ("228", "TG", "Togo"),
    ("229", "BJ", "Benin"),
    ("230", "MU", "Mauritius"),
    ("231", "LR", "Liberia"),
    ("232", "SL", "Sierra Leone"),
    ("233", "GH", "Ghana"),
    ("234", "NG", "Nigeria"),
    ("235", "TD", "Chad"),
    ("236", "CF", "Central African Republic"),
    ("237", "CM", "Cameroon"),
    ("238", "CV", "Cabo Verde"),
    ("239", "ST", "São Tomé and Príncipe"),
    ("240", "GQ", "Equatorial Guinea"),
    ("241", "GA", "Gabon"),
    ("242", "CG", "Republic of the Congo"),
    ("243", "CD", "Democratic Republic of the Congo"),
    ("244", "AO", "Angola"),
    ("245", "GW", "Guinea-Bissau"),
    ("246", "IO", "British Indian Ocean Territory"),
    ("247", "SH", "Saint Helena"),
    ("248", "SC", "Seychelles"),
    ("249", "SD", "Sudan"),
    ("250", "RW", "Rwanda"),
    ("251", "ET", "Ethiopia"),
    ("252", "SO", "Somalia"),
    ("253", "DJ", "Djibouti"),
    ("254", "KE", "Kenya"),
    ("255", "TZ", "Tanzania"),
    ("256", "UG", "Uganda"),
    ("257", "BI", "Burundi"),
    ("258", "MZ", "Mozambique"),
    ("260", "ZM", "Zambia"),
    ("261", "MG", "Madagascar"),
    ("262", "RE", "Réunion"),
    ("263", "ZW", "Zimbabwe"),
    ("264", "NA", "Namibia"),
    ("265", "MW", "Malawi"),
    ("266", "LS", "Lesotho"),
    ("267", "BW", "Botswana"),
    ("268", "SZ", "Eswatini"),
    ("269", "KM", "Comoros"),
    ("27", "ZA", "South Africa"),
    ("290", "SH", "Saint Helena"),
    ("291", "ER", "Eritrea"),
    ("297", "AW", "Aruba"),
    ("298", "FO", "Faroe Islands"),
    ("299", "GL", "Greenland"),
    ("30", "GR", "Greece"),
    ("31", "NL", "Netherlands"),
    ("32", "BE", "Belgium"),
    ("350", "GI", "Gibraltar"),
    ("351", "PT", "Portugal"),
    ("352", "LU", "Luxembourg"),
    ("353", "IE", "Ireland"),
    ("354", "IS", "Iceland"),
    ("355", "AL", "Albania"),
    ("356", "MT", "Malta"),
    ("357", "CY", "Cyprus"),
    ("359", "BG", "Bulgaria"),
    ("36", "HU", "Hungary"),
    ("370", "LT", "Lithuania"),
    ("371", "LV", "Latvia"),
    ("372", "EE", "Estonia"),
    ("373", "MD", "Moldova"),
    ("374", "AM", "Armenia"),
    ("375", "BY", "Belarus"),
    ("376", "AD", "Andorra"),
    ("377", "MC", "Monaco"),
    ("378", "SM", "San Marino"),
    ("379", "VA", "Vatican City"),
    ("380", "UA", "Ukraine"),
    ("381", "RS", "Serbia"),
    ("382", "ME", "Montenegro"),
    ("383", "XK", "Kosovo"),
    ("385", "HR", "Croatia"),
    ("386", "SI", "Slovenia"),
    ("387", "BA", "Bosnia and Herzegovina"),
    ("389", "MK", "North Macedonia"),
    ("39", "IT", "Italy"),
    ("40", "RO", "Romania"),
    ("41", "CH", "Switzerland"),
    ("420", "CZ", "Czechia"),
    ("421", "SK", "Slovakia"),
    ("423", "LI", "Liechtenstein"),
    ("43", "AT", "Austria"),
    ("44", "GB", "United Kingdom"),
    ("45", "DK", "Denmark"),
    ("46", "SE", "Sweden"),
    ("47", "NO", "Norway"),
    ("48", "PL", "Poland"),
    ("49", "DE", "Germany"),
    ("500", "FK", "Falkland Islands"),
    ("501", "BZ", "Belize"),
    ("502", "GT", "Guatemala"),
    ("503", "SV", "El Salvador"),
    ("504", "HN", "Honduras"),
    ("505", "NI", "Nicaragua"),
    ("506", "CR", "Costa Rica"),
    ("507", "PA", "Panama"),
    ("508", "PM", "Saint Pierre and Miquelon"),
    ("509", "HT", "Haiti"),
    ("51", "PE", "Peru"),
    ("52", "MX", "Mexico"),
    ("53", "CU", "Cuba"),
    ("54", "AR", "Argentina"),
    ("55", "BR", "Brazil"),
    ("56", "CL", "Chile"),
    ("57", "CO", "Colombia"),
    ("58", "VE", "Venezuela"),
    ("590", "GP", "Guadeloupe"),
    ("591", "BO", "Bolivia"),
    ("592", "GY", "Guyana"),
    ("593", "EC", "Ecuador"),
    ("594", "GF", "French Guiana"),
    ("595", "PY", "Paraguay"),
    ("596", "MQ", "Martinique"),
    ("597", "SR", "Suriname"),
    ("598", "UY", "Uruguay"),
    ("599", "CW", "Curaçao"),
    ("60", "MY", "Malaysia"),
    ("61", "AU", "Australia"),
    ("62", "ID", "Indonesia"),
    ("63", "PH", "Philippines"),
    ("64", "NZ", "New Zealand"),
    ("65", "SG", "Singapore"),
    ("66", "TH", "Thailand"),
    ("670", "TL", "Timor-Leste"),
    ("672", "AQ", "Australian External Territories"),
    ("673", "BN", "Brunei"),
    ("674", "NR", "Nauru"),
    ("675", "PG", "Papua New Guinea"),
    ("676", "TO", "Tonga"),
    ("677", "SB", "Solomon Islands"),
    ("678", "VU", "Vanuatu"),
    ("679", "FJ", "Fiji"),
    ("680", "PW", "Palau"),
    ("681", "WF", "Wallis and Futuna"),
    ("682", "CK", "Cook Islands"),
    ("683", "NU", "Niue"),
    ("685", "WS", "Samoa"),
    ("686", "KI", "Kiribati"),
    ("687", "NC", "New Caledonia"),
    ("688", "TV", "Tuvalu"),
    ("689", "PF", "French Polynesia"),
    ("690", "TK", "Tokelau"),
    ("691", "FM", "Micronesia"),
    ("692", "MH", "Marshall Islands"),
    ("7", "RU", "Russia"),
    ("800", "001", "International Freephone Service"),
    ("808", "001", "International Shared Cost Service"),
    ("81", "JP", "Japan"),
    ("82", "KR", "South Korea"),
    ("84", "VN", "Vietnam"),
    ("850", "KP", "North Korea"),
    ("852", "HK", "Hong Kong"),
    ("853", "MO", "Macao"),
    ("855", "KH", "Cambodia"),
    ("856", "LA", "Laos"),
    ("86", "CN", "China"),
    ("880", "BD", "Bangladesh"),
    ("886", "TW", "Taiwan"),
    ("90", "TR", "Turkey"),
    ("91", "IN", "India"),
    ("92", "PK", "Pakistan"),
    ("93", "AF", "Afghanistan"),
    ("94", "LK", "Sri Lanka"),
    ("95", "MM", "Myanmar"),
    ("960", "MV", "Maldives"),
    ("961", "LB", "Lebanon"),
    ("962", "JO", "Jordan"),
    ("963", "SY", "Syria"),
    ("964", "IQ", "Iraq"),
    ("965", "KW", "Kuwait"),
    ("966", "SA", "Saudi Arabia"),
    ("967", "YE", "Yemen"),
    ("968", "OM", "Oman"),
    ("970", "PS", "Palestine"),
    ("971", "AE", "United Arab Emirates"),
    ("972", "IL", "Israel"),
    ("973", "BH", "Bahrain"),
    ("974", "QA", "Qatar"),
    ("975", "BT", "Bhutan"),
    ("976", "MN", "Mongolia"),
    ("977", "NP", "Nepal"),
    ("98", "IR", "Iran"),
    ("992", "TJ", "Tajikistan"),
    ("993", "TM", "Turkmenistan"),
    ("994", "AZ", "Azerbaijan"),
    ("995", "GE", "Georgia"),
    ("996", "KG", "Kyrgyzstan"),
    ("998", "UZ", "Uzbekistan"),
)

# Some calling codes are shared by multiple countries or territories.  Their
# following network/area prefix is required for a reliable country label.
SHARED_PREFIXES: tuple[tuple[str, str, str], ...] = (
    # Kazakhstan uses +7 6xx and +7 7xx; other +7 ranges are Russia.
    ("76", "KZ", "Kazakhstan"),
    ("77", "KZ", "Kazakhstan"),
    # Mayotte shares +262 with Réunion.
    ("262639", "YT", "Mayotte"),
    ("262269", "YT", "Mayotte"),
    # Caribbean Netherlands shares +599 with Curaçao.
    ("5993", "BQ", "Caribbean Netherlands"),
    ("5994", "BQ", "Caribbean Netherlands"),
    ("5997", "BQ", "Caribbean Netherlands"),
    ("5999", "CW", "Curaçao"),
)

# Countries and territories sharing the +1 calling code.  The first four
# digits (country code plus area code) are enough to distinguish the common
# NANP assignments without changing the incoming number or message flow.
NANP_PREFIXES: tuple[tuple[str, str, str], ...] = (
    # Canada uses the shared +1 calling code; its area codes must be checked
    # before the United States fallback below.
    ("1204", "CA", "Canada"),
    ("1226", "CA", "Canada"),
    ("1236", "CA", "Canada"),
    ("1249", "CA", "Canada"),
    ("1250", "CA", "Canada"),
    ("1257", "CA", "Canada"),
    ("1289", "CA", "Canada"),
    ("1306", "CA", "Canada"),
    ("1343", "CA", "Canada"),
    ("1354", "CA", "Canada"),
    ("1365", "CA", "Canada"),
    ("1367", "CA", "Canada"),
    ("1368", "CA", "Canada"),
    ("1382", "CA", "Canada"),
    ("1403", "CA", "Canada"),
    ("1416", "CA", "Canada"),
    ("1418", "CA", "Canada"),
    ("1428", "CA", "Canada"),
    ("1431", "CA", "Canada"),
    ("1437", "CA", "Canada"),
    ("1438", "CA", "Canada"),
    ("1450", "CA", "Canada"),
    ("1468", "CA", "Canada"),
    ("1474", "CA", "Canada"),
    ("1506", "CA", "Canada"),
    ("1514", "CA", "Canada"),
    ("1519", "CA", "Canada"),
    ("1548", "CA", "Canada"),
    ("1579", "CA", "Canada"),
    ("1581", "CA", "Canada"),
    ("1584", "CA", "Canada"),
    ("1587", "CA", "Canada"),
    ("1604", "CA", "Canada"),
    ("1613", "CA", "Canada"),
    ("1639", "CA", "Canada"),
    ("1647", "CA", "Canada"),
    ("1672", "CA", "Canada"),
    ("1705", "CA", "Canada"),
    ("1709", "CA", "Canada"),
    ("1742", "CA", "Canada"),
    ("1778", "CA", "Canada"),
    ("1780", "CA", "Canada"),
    ("1782", "CA", "Canada"),
    ("1783", "CA", "Canada"),
    ("1787", "PR", "Puerto Rico"),
    ("1788", "CA", "Canada"),
    ("1807", "CA", "Canada"),
    ("1819", "CA", "Canada"),
    ("1825", "CA", "Canada"),
    ("1829", "DO", "Dominican Republic"),
    ("1837", "CA", "Canada"),
    ("1849", "DO", "Dominican Republic"),
    ("1867", "CA", "Canada"),
    ("1868", "TT", "Trinidad and Tobago"),
    ("1869", "KN", "Saint Kitts and Nevis"),
    ("1873", "CA", "Canada"),
    ("1876", "JM", "Jamaica"),
    ("1879", "CA", "Canada"),
    ("1902", "CA", "Canada"),
    ("1905", "CA", "Canada"),
    ("1907", "CA", "Canada"),
    ("1908", "CA", "Canada"),
    ("1909", "CA", "Canada"),
    ("1938", "CA", "Canada"),
    ("1939", "PR", "Puerto Rico"),
    ("1242", "BS", "Bahamas"),
    ("1246", "BB", "Barbados"),
    ("1264", "AI", "Anguilla"),
    ("1268", "AG", "Antigua and Barbuda"),
    ("1284", "VG", "British Virgin Islands"),
    ("1340", "VI", "U.S. Virgin Islands"),
    ("1345", "KY", "Cayman Islands"),
    ("1441", "BM", "Bermuda"),
    ("1473", "GD", "Grenada"),
    ("1649", "TC", "Turks and Caicos Islands"),
    ("1658", "US", "United States"),
    ("1670", "MP", "Northern Mariana Islands"),
    ("1671", "GU", "Guam"),
    ("1684", "AS", "American Samoa"),
    ("1721", "SX", "Sint Maarten"),
    ("1758", "LC", "Saint Lucia"),
    ("1767", "DM", "Dominica"),
    ("1784", "VC", "Saint Vincent and the Grenadines"),
    ("1809", "DO", "Dominican Republic"),
)


def get_country(record: dict[str, str], phone: str) -> str:
    digits = normalize_number(phone).lstrip("+")
    if digits.startswith("00"):
        digits = digits[2:]

    if digits.startswith("1"):
        for prefix, code, name in NANP_PREFIXES:
            if digits.startswith(prefix):
                return f"{alpha2_flag(code)} {name}"
        return f"{alpha2_flag('US')} United States"

    for prefix, code, name in SHARED_PREFIXES:
        if digits.startswith(prefix):
            return f"{alpha2_flag(code)} {name}"

    # The phone prefix is the source of truth.  API country fields can be
    # stale or inconsistent with the actual number.
    for prefix, code, name in COUNTRY_PREFIXES:
        if digits.startswith(prefix):
            return f"{alpha2_flag(code)} {name}"

    for key in (
        "country",
        "country_name",
        "countryName",
        "country_label",
        "countryLabel",
    ):
        value = _first_field(record, (key,))
        if value:
            return value

    for key in ("country_code", "countryCode", "cc"):
        value = _first_field(record, (key,))
        if value:
            flag = alpha2_flag(value)
            return f"{flag} {value.upper()}".strip() if flag else value

    return "🌐 Unknown"


def get_service(record: dict[str, str]) -> str:
    for key in (
        "service",
        "service_name",
        "serviceName",
        "cli",
        "client",
        "app",
        "app_name",
        "appName",
        "application",
        "platform",
        "site",
        "sender_name",
        "senderName",
        "originator_name",
        "originatorName",
    ):
        value = _first_field(record, (key,))
        # A numeric sender is normally the phone number, not the service name.
        if value and not re.fullmatch(r"[+\d\s().-]+", value):
            return value
    return "Unknown service"


_NUMBER_FIELDS = (
    "num",
    "number",
    "phone",
    "phone_number",
    "phoneNumber",
    "mobile",
    "mobile_number",
    "mobileNumber",
    "msisdn",
    "recipient",
    "recipient_number",
    "recipientNumber",
    "receiver",
    "receiver_number",
    "receiverNumber",
    "sim_number",
    "simNumber",
    "virtual_number",
    "virtualNumber",
    "sender_number",
    "senderNumber",
    "from_number",
    "fromNumber",
)
_MESSAGE_FIELDS = (
    "message",
    "msg",
    "error_message",
    "errorMessage",
    "text",
    "sms",
    "sms_text",
    "smsText",
    "body",
    "content",
    "content_text",
    "contentText",
    "message_text",
    "messageText",
    "otp_message",
    "otpMessage",
    "notification",
)
_SERVICE_FIELDS = (
    "service",
    "service_name",
    "serviceName",
    "cli",
    "client",
    "app",
    "app_name",
    "appName",
    "application",
    "platform",
    "site",
    "sender_name",
    "senderName",
    "originator",
    "originator_name",
    "originatorName",
    "from_name",
    "fromName",
)
_RECORD_CONTAINER_FIELDS = (
    "data",
    "otps",
    "records",
    "result",
    "messages",
    "rows",
    "items",
    "results",
    "sms",
    "inbox",
    "inbox_messages",
    "inboxMessages",
)


def _key_token(value: Any) -> str:
    """Normalize API keys so Number/SMS/created_at variants match reliably."""
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _text_value(value: Any) -> str:
    """Convert panel values without turning nested objects into fake SMS text."""
    if value is None or isinstance(value, (dict, list, tuple)):
        return ""
    return str(value).strip()


def _first_field(item: dict[str, Any], fields: tuple[str, ...]) -> str:
    wanted = {_key_token(field) for field in fields}
    for key, raw_value in item.items():
        if _key_token(key) in wanted:
            value = _text_value(raw_value)
            if value:
                return value
    return ""


def _looks_like_record(item: dict[str, Any]) -> bool:
    return bool(
        _first_field(item, _NUMBER_FIELDS)
        or _first_field(item, _MESSAGE_FIELDS)
        or _first_field(item, _SERVICE_FIELDS)
    )


def _iter_record_items(payload: Any) -> list[dict[str, Any]]:
    """Find rows through the wrapper shapes used by different panel versions."""
    found: list[dict[str, Any]] = []
    seen: set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if id(value) in seen:
                return
            seen.add(id(value))
            if _looks_like_record(value):
                found.append(value)
            container_keys = {
                _key_token(key) for key in _RECORD_CONTAINER_FIELDS
            }
            for key, nested in value.items():
                if _key_token(key) not in container_keys:
                    continue
                if isinstance(nested, (dict, list)):
                    visit(nested)
        elif isinstance(value, list):
            for entry in value:
                visit(entry)

    visit(payload)
    return found


def _is_no_data_text(value: str) -> bool:
    normalized = " ".join(value.split()).casefold().strip(" .!,:;")
    return bool(
        re.fullmatch(
            r"(?:no\s+(?:records?|data|messages?|sms)(?:\s+(?:found|available))?|"
            r"(?:records?|data|messages?|sms)\s+(?:not\s+found|empty)|"
            r"empty|nothing\s+found)",
            normalized,
        )
    )


def _validate_meta_status(payload: dict[str, Any]) -> None:
    """Reject Voltx-style application errors returned with HTTP 200."""
    metadata = []
    for key, value in payload.items():
        if _key_token(key) in {"meta", "metadata"} and isinstance(value, dict):
            metadata.append(value)

    for meta in metadata:
        code = _first_field(meta, ("code", "status_code", "statusCode"))
        if code:
            try:
                numeric_code = int(code)
            except ValueError:
                numeric_code = 0
            if numeric_code and not 200 <= numeric_code < 300:
                status = _first_field(meta, ("status", "message", "error"))
                raise ValueError(
                    f"Panel API reported failure: "
                    f"{status or f'HTTP {numeric_code}'}"
                )

        status = _first_field(meta, ("status", "state"))
        if status.casefold() in {
            "error",
            "failed",
            "failure",
            "false",
            "unauthorized",
            "unauthenticated",
        }:
            message = _first_field(meta, ("message", "error", "detail"))
            raise ValueError(
                f"Panel API reported failure: {message or status}"
            )


def parse_api_response(raw: bytes) -> list[dict[str, str]]:
    # utf-8-sig also accepts responses with a UTF-8 BOM.
    raw_text = raw.decode("utf-8-sig", errors="replace").strip()
    try:
        payload: Any = json.loads(raw_text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # A few panel versions return plain text when there is no traffic.
        # That is a healthy empty result, not an API outage.
        if _is_no_data_text(raw_text):
            return []
        # Do not mistake an HTML/error response for a healthy empty page.
        raise ValueError("Panel API returned invalid JSON") from exc

    if not isinstance(payload, (dict, list)):
        raise ValueError("Panel API returned an unexpected JSON shape")

    # Some panels return HTTP 200 while reporting an application-level error.
    # Treat that as a failed request so startup does not create a false
    # baseline and silently suppress later notifications.
    if isinstance(payload, dict):
        _validate_meta_status(payload)
        for key, value in payload.items():
            if _key_token(key) not in {"status", "success"}:
                continue
            if isinstance(value, bool) and not value:
                message = _first_field(
                    payload,
                    ("message", "msg", "error", "detail", "description"),
                )
                if _is_no_data_text(message):
                    return []
                raise ValueError(
                    f"Panel API reported failure: {message or 'unknown error'}"
                )
            if isinstance(value, str) and value.strip().casefold() in {
                "error",
                "failed",
                "failure",
                "false",
                "unauthorized",
                "unauthenticated",
            }:
                message = _first_field(
                    payload,
                    ("message", "msg", "error", "detail", "description"),
                )
                if _is_no_data_text(message):
                    return []
                raise ValueError(
                    f"Panel API reported failure: {message or 'unknown error'}"
                )

    records: list[dict[str, str]] = []
    for item in _iter_record_items(payload):
        record = {
            "number": _first_field(item, _NUMBER_FIELDS),
            "message": _first_field(item, _MESSAGE_FIELDS),
        }

        # Some panel versions expose the sender as the phone field, while
        # others use it for a brand name (for example, "TikTok"). Preserve it
        # as service metadata and only use it as a number when it is numeric.
        if not record["number"]:
            sender = _first_field(
                item,
                (
                    "sender",
                    "from",
                    "source",
                    "originator",
                    "address",
                    "sender_id",
                    "senderId",
                ),
            )
            if sender and re.search(r"\d", sender):
                record["number"] = sender
            elif sender:
                record["sender"] = sender

        for key in _SERVICE_FIELDS:
            value = _first_field(item, (key,))
            if value:
                record[key] = value

        for key in (
            # Preserve the panel's event identity so repeated OTP text from
            # the same number can still be treated as a new OTP event.
            "otp_id",
            "otpId",
            "record_id",
            "recordId",
            "source_id",
            "sourceId",
            "id",
            "sms_id",
            "smsId",
            "message_id",
            "messageId",
            "timestamp",
            "created_at",
            "createdAt",
            "datetime",
            "date",
            "time",
            "received_at",
            "receivedAt",
            "sent_at",
            "sentAt",
            "dt",
            "sender",
            "from",
            "source",
            "originator",
            "address",
            "sender_id",
            "senderId",
            "country",
            "country_name",
            "countryName",
            "country_label",
            "countryLabel",
            "country_code",
            "countryCode",
            "cc",
            "service",
            "app",
            "application",
            "platform",
            "site",
        ):
            value = _first_field(item, (key,))
            if value:
                record[key] = value

        # Forward every real SMS message, including messages that contain
        # neither a phone number nor an OTP.  Keep panel "no data" responses
        # filtered out so they are not treated as SMS notifications.
        if record["message"] and not re.search(
            r"\b(?:no\s+(?:records?|messages?|sms)|not\s+found|empty)\b",
            record["message"],
            re.IGNORECASE,
        ):
            records.append(record)
    return records


def _fetch_api_page_sync() -> list[dict[str, str]]:
    """Fetch one CR API HADI window using the documented parameters."""
    query = urlencode(
        {
            "token": API_KEY,
            "records": str(API_RECORDS),
        }
    )
    request = Request(
        f"{API_URL}?{query}",
        headers={"User-Agent": "infinity-otp-notification-bot/2.0"},
    )
    with urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
        return parse_api_response(response.read())


def fetch_records_sync() -> list[dict[str, str]]:
    """Fetch the latest CR API HADI window with retry handling."""
    global last_panel_api_ok
    last_error: Optional[Exception] = None

    for attempt in range(1, API_RETRIES + 1):
        try:
            records = _fetch_api_page_sync()
            last_panel_api_ok = True
            return records
        except Exception as exc:
            last_panel_api_ok = False
            last_error = exc
            if attempt < API_RETRIES:
                # This function runs in asyncio.to_thread; never block the
                # event loop while backing off.
                time.sleep(min(2 ** (attempt - 1), 5))

    logger.warning("SMS Hadi API request failed: %s", last_error)
    return []


def fetch_voltx_records_sync() -> list[dict[str, str]]:
    """Fetch OTP records from the Voltx success-otp API."""
    global last_voltx_api_ok
    if not VOLTX_ENABLED:
        last_voltx_api_ok = True
        return []

    last_error: Optional[Exception] = None

    for attempt in range(1, API_RETRIES + 1):
        try:
            request = Request(
                VOLTX_API_URL,
                headers={
                    "User-Agent": "infinity-otp-notification-bot/2.0",
                    "mauthapi": VOLTX_AUTH_KEY,
                },
            )
            with urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
                records = parse_api_response(response.read())

            # Keep Voltx event IDs separate from SMS Hadi event IDs. Different
            # panels may reuse the same numeric ID.
            for record in records:
                record["_source"] = "voltx"

            last_voltx_api_ok = True
            return records
        except Exception as exc:
            last_voltx_api_ok = False
            last_error = exc
            if attempt < API_RETRIES:
                time.sleep(min(2 ** (attempt - 1), 5))

    logger.warning("Voltx API request failed: %s", last_error)
    return []


def _redx_start_date() -> str:
    """Use an explicit date or a small rolling window to avoid missed OTPs."""
    if REDX_START_DATE_OVERRIDE:
        return REDX_START_DATE_OVERRIDE
    start = datetime.now(timezone.utc).date() - timedelta(
        days=REDX_LOOKBACK_DAYS
    )
    return start.isoformat()


def _redx_page_url(page: int, start_date: Optional[str] = None) -> str:
    """Build a Red X page URL while preserving any configured query values."""
    parts = urlsplit(REDX_API_URL)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(
        {
            "start_date": start_date or _redx_start_date(),
            "type": REDX_TYPE,
            "per_page": str(REDX_PER_PAGE),
            "page": str(page),
        }
    )
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def _redx_retry_after_seconds(error: HTTPError, attempt: int) -> float:
    """Return a safe delay for a Red X rate-limit response."""
    retry_after = error.headers.get("Retry-After") if error.headers else None
    if retry_after:
        try:
            return max(1.0, min(300.0, float(retry_after)))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max(
                    1.0,
                    min(
                        300.0,
                        (retry_at - datetime.now(timezone.utc)).total_seconds(),
                    ),
                )
            except (TypeError, ValueError, OverflowError):
                pass

    # Some Red X responses omit Retry-After. Use a slower exponential backoff
    # instead of retrying three times inside the same rate-limit window.
    return min(60.0, 5.0 * float(2 ** (attempt - 1)))


def fetch_redx_records_sync() -> list[dict[str, str]]:
    """Fetch paginated OTP records from the Red X messages API."""
    global last_redx_api_ok, redx_rate_limit_until
    if not REDX_ENABLED:
        last_redx_api_ok = True
        return []

    with redx_request_lock:
        cooldown = redx_rate_limit_until - time.monotonic()
        if cooldown > 0:
            last_redx_api_ok = False
            logger.info(
                "Red X API rate-limit cooldown is active; "
                "next check in %.1fs.",
                cooldown,
            )
            return []

        last_error: Optional[Exception] = None
        for attempt in range(1, API_RETRIES + 1):
            try:
                all_records: list[dict[str, str]] = []
                page = 1
                fingerprints: set[str] = set()
                start_date = _redx_start_date()

                while True:
                    request = Request(
                        _redx_page_url(page, start_date),
                        headers={
                            "User-Agent": "infinity-otp-notification-bot/2.0",
                            "Authorization": f"Bearer {REDX_API_KEY}",
                            "Accept": "application/json",
                        },
                    )
                    with urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
                        raw = response.read()

                    page_records = parse_api_response(raw)
                    fingerprint = hashlib.sha256(raw).hexdigest()
                    if fingerprint in fingerprints:
                        break
                    fingerprints.add(fingerprint)

                    # Red X has no documented event ID in the response. The
                    # received_at value is retained for fallback deduplication.
                    for record in page_records:
                        record["_source"] = "redx"
                    all_records.extend(page_records)

                    try:
                        payload = json.loads(
                            raw.decode("utf-8-sig", errors="replace")
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        raise ValueError(
                            "Red X API returned invalid JSON"
                        ) from exc

                    pagination = (
                        payload.get("pagination")
                        if isinstance(payload, dict)
                        else None
                    )
                    if not isinstance(pagination, dict):
                        break

                    try:
                        last_page = int(pagination.get("last_page", page))
                    except (TypeError, ValueError):
                        last_page = page
                    if page >= last_page:
                        break
                    page += 1

                last_redx_api_ok = True
                return all_records
            except HTTPError as exc:
                last_redx_api_ok = False
                last_error = exc
                if attempt < API_RETRIES:
                    if exc.code == 429:
                        delay = _redx_retry_after_seconds(exc, attempt)
                        redx_rate_limit_until = max(
                            redx_rate_limit_until,
                            time.monotonic() + delay,
                        )
                        logger.warning(
                            "Red X API rate limit reached (HTTP 429); "
                            "retrying in %.1fs (attempt %d/%d).",
                            delay,
                            attempt,
                            API_RETRIES,
                        )
                    else:
                        delay = min(2 ** (attempt - 1), 5)
                    time.sleep(delay)
            except Exception as exc:
                last_redx_api_ok = False
                last_error = exc
                if attempt < API_RETRIES:
                    time.sleep(min(2 ** (attempt - 1), 5))

        if isinstance(last_error, HTTPError) and last_error.code == 429:
            redx_rate_limit_until = max(
                redx_rate_limit_until,
                time.monotonic() + _redx_retry_after_seconds(last_error, API_RETRIES),
            )

    if isinstance(last_error, HTTPError) and last_error.code == 429:
        logger.warning(
            "Red X API is still rate-limited after %d attempts; "
            "it will be checked again on the next polling cycle.",
            API_RETRIES,
        )
    else:
        logger.warning("Red X API request failed: %s", last_error)
    return []


def fetch_all_records_sync() -> list[dict[str, str]]:
    """Combine all configured panel records without changing Hadi parsing."""
    # Fetch all panels concurrently so a slow/unavailable panel does not
    # unnecessarily extend the polling interval of the other panel.
    with ThreadPoolExecutor(max_workers=3) as executor:
        hadi_future = executor.submit(fetch_records_sync)
        voltx_future = executor.submit(fetch_voltx_records_sync)
        redx_future = executor.submit(fetch_redx_records_sync)
        records = hadi_future.result()
        records.extend(voltx_future.result())
        records.extend(redx_future.result())
        return records


def fetch_dynamic_panel_sync(
    panel: dict[str, Any],
) -> tuple[bool, list[dict[str, str]], str]:
    """Fetch one admin-added panel without allowing its failure to escape."""
    try:
        headers = {"User-Agent": "infinity-otp-notification-bot/2.0"}
        api_key = str(panel.get("api_key") or "").strip()
        if api_key and api_key.casefold() != "skip":
            # SMS Hadi-like panels commonly accept the key in a query string,
            # while other compatible panels use one of these headers. Keep the
            # URL's existing query values and provide safe fallbacks.
            headers["Authorization"] = f"Bearer {api_key}"
            headers["mauthapi"] = api_key
            headers["X-API-Key"] = api_key

        panel_url = str(panel["api_url"]).strip()
        url_parts = urlsplit(panel_url)
        query_pairs = parse_qsl(url_parts.query, keep_blank_values=True)
        query_keys = {key.casefold() for key, _ in query_pairs}
        if "records" not in query_keys and "limit" not in query_keys:
            query_pairs.append(("records", str(API_RECORDS)))
        if (
            api_key
            and api_key.casefold() != "skip"
            and not query_keys.intersection(
                {"token", "api_key", "apikey", "api-key", "key", "access_token"}
            )
        ):
            query_pairs.append(("token", api_key))
        request_url = urlunsplit(
            (
                url_parts.scheme,
                url_parts.netloc,
                url_parts.path,
                urlencode(query_pairs),
                url_parts.fragment,
            )
        )

        request = Request(request_url, headers=headers)
        with urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
            records = parse_api_response(response.read())

        source = f"dynamic_{panel['id']}"
        for record in records:
            record["_source"] = source
        return True, records, ""
    except Exception as exc:
        return False, [], f"{type(exc).__name__}: {exc}"


def prime_dynamic_panels_sync() -> None:
    """Baseline active dynamic panels at startup without blocking core panels."""
    for panel in get_active_dynamic_panels():
        ok, records, error = fetch_dynamic_panel_sync(panel)
        if not ok:
            disable_dynamic_panel(int(panel["id"]), error)
            logger.error(
                "Dynamic panel '%s' disabled at startup: %s",
                panel["name"],
                error,
            )
            continue
        baseline_count = prepare_startup_baseline(records)
        logger.info(
            "Dynamic panel '%s' startup baseline ready: %d record(s).",
            panel["name"],
            baseline_count,
        )


def notification_key(record: dict[str, str]) -> str:
    """
    Build a stable event key without using the phone number alone.

    sms_id is the panel's authoritative event identity when available.  Older
    panel responses do not always provide it, so the fallback includes the
    normalized message and event timestamp as well.
    """
    sms_id = next(
        (
            _first_field(record, (key,))
            for key in (
                "otp_id",
                "otpId",
                "sms_id",
                "smsId",
                "record_id",
                "recordId",
                "source_id",
                "sourceId",
                "id",
                "message_id",
                "messageId",
            )
            if _first_field(record, (key,))
        ),
        "",
    )
    event_time = next(
        (
            _first_field(record, (key,))
            for key in (
                "timestamp",
                "created_at",
                "createdAt",
                "datetime",
                "date",
                "time",
                "received_at",
                "receivedAt",
                "sent_at",
                "sentAt",
            )
            if _first_field(record, (key,))
        ),
        "",
    )
    source = _first_field(record, ("_source",))
    if sms_id:
        identity = (
            f"source:{source}|event_id:{sms_id}"
            if source
            else f"event_id:{sms_id}"
        )
    else:
        message = " ".join(_first_field(record, ("message",)).split()).casefold()
        other_id = next(
            (
                _first_field(record, (key,))
                for key in (
                    "otp_id",
                    "otpId",
                    "record_id",
                    "recordId",
                    "source_id",
                    "sourceId",
                    "id",
                    "message_id",
                    "messageId",
                )
                if _first_field(record, (key,))
            ),
            "",
        )
        identity_parts = [
            f"source_id:{other_id}" if other_id else "source_id:",
            f"time:{event_time}",
            f"number:{normalize_number(_first_field(record, ('number',)))}",
            f"service:{get_service(record).casefold()}",
            f"message:{message}",
        ]
        if source:
            identity_parts.insert(0, f"source:{source}")
        identity = "|".join(identity_parts)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def claim_notification(record: dict[str, str]) -> bool:
    phone = normalize_number(record["number"])
    country = get_country(record, phone)
    service = get_service(record)
    dedupe_key = notification_key(record)
    timestamp = now_utc()

    with closing(db_connection()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO seen_notifications(
                    dedupe_key, phone_number, country, service, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (dedupe_key, phone, country, service, timestamp),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                return False

            conn.execute(
                """
                INSERT INTO notification_outbox(
                    dedupe_key, payload_json, status, attempts,
                    next_attempt_at, lease_until, last_error,
                    created_at, updated_at
                ) VALUES (?, ?, 'pending', 0, 0, 0, '', ?, ?)
                """,
                (
                    dedupe_key,
                    json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                    timestamp,
                    timestamp,
                ),
            )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise


def prepare_startup_baseline(records: list[dict[str, str]]) -> int:
    """Suppress everything visible before this process started.

    This is deliberately done before relay_loop starts. The current API window
    is recorded in seen_notifications without creating new outbox rows. Any
    pending outbox rows from an earlier process are preserved so a crash or
    restart cannot discard an OTP that was already queued for delivery.
    """
    timestamp = now_utc()
    inserted = 0
    with closing(db_connection()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for record in records:
                phone = normalize_number(record.get("number", ""))
                message = str(record.get("message", "") or "").strip()
                if not message or re.search(
                    r"\b(?:no\s+(?:records?|messages?|sms)|not\s+found|empty)\b",
                    message,
                    re.IGNORECASE,
                ):
                    continue
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO seen_notifications(
                        dedupe_key, phone_number, country, service, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        notification_key(record),
                        phone,
                        get_country(record, phone),
                        get_service(record),
                        timestamp,
                    ),
                )
                inserted += int(cursor.rowcount == 1)
            conn.commit()
            return inserted
        except Exception:
            conn.rollback()
            raise


def forget_notification(record: dict[str, str]) -> None:
    with closing(db_connection()) as conn:
        conn.execute(
            "DELETE FROM seen_notifications WHERE dedupe_key = ?",
            (notification_key(record),),
        )
        conn.execute(
            "DELETE FROM notification_outbox WHERE dedupe_key = ?",
            (notification_key(record),),
        )
        conn.commit()


def claim_next_outbox_item() -> Optional[tuple[str, dict[str, str], int]]:
    """Atomically lease the oldest ready outbox item for one worker."""
    now = time.time()
    lease_until = now + SEND_LEASE_SECONDS

    with closing(db_connection()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                """
                SELECT dedupe_key, payload_json, attempts
                FROM notification_outbox
                WHERE (
                    status = 'pending'
                    AND next_attempt_at <= ?
                ) OR (
                    status = 'sending'
                    AND lease_until <= ?
                )
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (now, now),
            ).fetchone()
            if row is None:
                conn.rollback()
                return None

            attempts = int(row["attempts"]) + 1
            conn.execute(
                """
                UPDATE notification_outbox
                SET status = 'sending',
                    attempts = ?,
                    lease_until = ?,
                    updated_at = ?
                WHERE dedupe_key = ?
                """,
                (attempts, lease_until, now_utc(), row["dedupe_key"]),
            )
            conn.commit()
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, dict):
                raise ValueError("Outbox payload is not an object")
            return row["dedupe_key"], {
                str(key): str(value) for key, value in payload.items()
            }, attempts
        except Exception:
            conn.rollback()
            raise


def mark_outbox_sent(dedupe_key: str) -> None:
    with closing(db_connection()) as conn:
        conn.execute(
            """
            UPDATE notification_outbox
            SET status = 'sent', lease_until = 0, last_error = '',
                updated_at = ?
            WHERE dedupe_key = ?
            """,
            (now_utc(), dedupe_key),
        )
        conn.commit()


def mark_outbox_failed(dedupe_key: str, error: str) -> None:
    """Keep permanent Telegram failures diagnosable instead of hot-looping."""
    with closing(db_connection()) as conn:
        conn.execute(
            """
            UPDATE notification_outbox
            SET status = 'failed', lease_until = 0, last_error = ?,
                updated_at = ?
            WHERE dedupe_key = ?
            """,
            (error[:1000], now_utc(), dedupe_key),
        )
        conn.commit()


def requeue_outbox_item(
    dedupe_key: str,
    delay_seconds: float,
    error: str,
) -> None:
    with closing(db_connection()) as conn:
        conn.execute(
            """
            UPDATE notification_outbox
            SET status = 'pending',
                next_attempt_at = ?,
                lease_until = 0,
                last_error = ?,
                updated_at = ?
            WHERE dedupe_key = ?
            """,
            (
                time.time() + max(0, delay_seconds),
                error[:1000],
                now_utc(),
                dedupe_key,
            ),
        )
        conn.commit()


def build_notification(
    record: dict[str, str],
) -> tuple[str, InlineKeyboardMarkup]:
    phone = normalize_number(record["number"])
    country = get_country(record, phone)
    message = str(record["message"] or "").strip()
    otp_code = extract_otp_code(message) or "NO OTP"

    text_prefix = (
        "<blockquote><b>Tahachen Otp bot| OTP RCV</b></blockquote>\n\n"
        f"<b>☎️ Number:</b> <code>{html.escape(mask_number(phone))}</code>\n\n"
        f"<b>🌐 Country:</b> {html.escape(country)}\n\n"
    )
    text_suffix = "</blockquote>"
    # Keep the supplied notification body and formatting unchanged.
    escaped_message = html.escape(message)
    text = f"{text_prefix}<blockquote>{escaped_message}{text_suffix}"
    if len(text) > TELEGRAM_MAX_TEXT_LENGTH:
        available = max(
            0,
            TELEGRAM_MAX_TEXT_LENGTH
            - len(text_prefix)
            - len(text_suffix)
            - 1,
        )
        text = (
            f"{text_prefix}<blockquote>"
            f"{html.escape(message[:available])}…{text_suffix}"
        )

    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=otp_code,
                    copy_text=CopyTextButton(text=otp_code),
                ),
            ],
            [
                InlineKeyboardButton(
                    text="Main Channel",
                    url=str(get_setting("MAIN_CHANNEL_URL", MAIN_CHANNEL_URL)),
                ),
                InlineKeyboardButton(
                    text="Number Bot",
                    url=str(get_setting("GET_NUMBER_URL", GET_NUMBER_URL)),
                ),
            ]
        ]
    )
    return text, keyboard


async def send_notification(bot: Bot, record: dict[str, str]) -> None:
    """Send one message through a process-wide Telegram rate gate."""
    global telegram_next_allowed_at, telegram_cooldown_until
    text, keyboard = build_notification(record)
    target_group_id = int(get_setting("GROUP_CHAT_ID", GROUP_CHAT_ID))
    async with telegram_send_lock:
        now = time.monotonic()
        wait_for = max(
            0.0,
            telegram_next_allowed_at - now,
            telegram_cooldown_until - now,
        )
        if wait_for:
            await asyncio.sleep(wait_for)
        try:
            await bot.send_message(
                chat_id=target_group_id,
                text=text,
                reply_markup=keyboard,
            )
        except TelegramRetryAfter as exc:
            # Share Telegram's cooldown with every worker. Without this,
            # all workers independently hit the same flood limit.
            telegram_cooldown_until = time.monotonic() + max(
                1.0, float(exc.retry_after)
            )
            raise
        finally:
            telegram_next_allowed_at = (
                time.monotonic() + TELEGRAM_MIN_INTERVAL_SECONDS
            )


@dispatcher.message(Command("work"))
async def work_command(message: Message) -> None:
    """Respond immediately, then update the message with the API result."""
    try:
        status_message = await message.answer(
            "✅ Bot is online.\n"
            "OTP forwarding: active\n"
            "Panel API: checking..."
        )
    except Exception:
        logger.exception("Could not send /work acknowledgement.")
        return

    try:
        await asyncio.to_thread(fetch_all_records_sync)
        if (
            last_panel_api_ok
            and (not VOLTX_ENABLED or last_voltx_api_ok)
            and (not REDX_ENABLED or last_redx_api_ok)
        ):
            await status_message.edit_text(
                "✅ All OK — bot is working.\n"
                "OTP forwarding: active\n"
                "Panel API connections: OK"
            )
            return

        await status_message.edit_text(
            "⚠️ Bot is running, but the panel API check failed.\n"
            "OTP forwarding will keep retrying automatically."
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("The /work panel API check failed unexpectedly.")
        try:
            await status_message.edit_text(
                "✅ Bot is online.\n"
                "OTP forwarding: active\n"
                "⚠️ Panel API check could not be completed."
            )
        except Exception:
            logger.exception("Could not update /work status message.")


async def notification_worker(
    bot: Bot,
    worker_id: int,
) -> None:
    while True:
        try:
            item = await asyncio.to_thread(claim_next_outbox_item)
        except asyncio.CancelledError:
            raise
        except Exception:
            # A transient SQLite lock/filesystem error must not kill this
            # worker. Other workers continue and the next iteration retries.
            logger.exception("Worker %d could not claim an outbox item.", worker_id)
            await asyncio.sleep(1)
            continue
        if item is None:
            await asyncio.sleep(0.25)
            continue

        dedupe_key, record, attempts = item
        try:
            await send_notification(bot, record)
            await asyncio.to_thread(mark_outbox_sent, dedupe_key)
            logger.info(
                "Worker %d sent notification for %s",
                worker_id,
                mask_number(record["number"]),
            )
        except asyncio.CancelledError:
            await asyncio.to_thread(
                requeue_outbox_item,
                dedupe_key,
                0,
                "Worker cancelled before delivery completed",
            )
            raise
        except TelegramRetryAfter as exc:
            delay = min(
                SEND_RETRY_MAX_SECONDS,
                max(SEND_RETRY_BASE_SECONDS, float(exc.retry_after)),
            )
            await asyncio.to_thread(
                requeue_outbox_item,
                dedupe_key,
                delay,
                f"TelegramRetryAfter: {exc}",
            )
            logger.warning(
                "Worker %d rate-limited for %s; retry #%d in %.1fs",
                worker_id,
                mask_number(record["number"]),
                attempts,
                delay,
            )
        except (
            TelegramNetworkError,
            TelegramServerError,
            asyncio.TimeoutError,
            TimeoutError,
            OSError,
        ) as exc:
            delay = min(
                SEND_RETRY_MAX_SECONDS,
                max(
                    SEND_RETRY_BASE_SECONDS,
                    SEND_RETRY_BASE_SECONDS * (2 ** min(attempts - 1, 5)),
                ),
            )
            await asyncio.to_thread(
                requeue_outbox_item,
                dedupe_key,
                delay,
                f"{type(exc).__name__}: {exc}",
            )
            logger.warning(
                "Worker %d send failed for %s (%s); retry #%d in %.1fs",
                worker_id,
                mask_number(record["number"]),
                type(exc).__name__,
                attempts,
                delay,
            )
        except (TelegramForbiddenError, TelegramBadRequest) as exc:
            # These are normally permanent (bot removed, invalid chat,
            # malformed markup). Keep the row for diagnosis and do not
            # repeatedly hammer Telegram with the same invalid request.
            await asyncio.to_thread(
                mark_outbox_failed,
                dedupe_key,
                f"{type(exc).__name__}: {exc}",
            )
            logger.error(
                "Worker %d permanently failed %s: %s",
                worker_id,
                mask_number(record["number"]),
                exc,
            )
        except Exception as exc:
            delay = SEND_RETRY_MAX_SECONDS
            await asyncio.to_thread(
                requeue_outbox_item,
                dedupe_key,
                delay,
                f"{type(exc).__name__}: {exc}",
            )
            logger.exception(
                "Worker %d unexpected send failure for %s; retrying in %.1fs",
                worker_id,
                mask_number(record["number"]),
                delay,
            )


async def persist_records(records: list[dict[str, str]]) -> None:
    """Put eligible records in the durable outbox without blocking the loop."""
    for record in records:
        claimed = await asyncio.to_thread(claim_notification, record)
        if not claimed:
            continue
        logger.debug(
            "Persisted OTP for %s in the delivery outbox",
            mask_number(record["number"]),
        )


def fetch_other_records_sync() -> list[dict[str, str]]:
    """Fetch non-Hadi panels independently of the fast Hadi scheduler."""
    with ThreadPoolExecutor(max_workers=2) as executor:
        voltx_future = executor.submit(fetch_voltx_records_sync)
        redx_future = executor.submit(fetch_redx_records_sync)
        records = voltx_future.result()
        records.extend(redx_future.result())
        return records


async def hadi_relay_loop() -> None:
    """Poll SMS Hadi on a four-second start-to-start schedule."""
    next_run = time.monotonic()
    while True:
        try:
            records = await asyncio.to_thread(fetch_records_sync)
            logger.info(
                "SMS Hadi API returned %d eligible OTP record(s).",
                len(records),
            )
            await persist_records(records)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("SMS Hadi notification cycle failed.")

        # Schedule from the start of each cycle instead of sleeping a full
        # interval after the API response. This removes response-time +
        # interval latency while still preventing overlapping Hadi requests.
        next_run += HADI_POLL_SECONDS
        await asyncio.sleep(max(0.0, next_run - time.monotonic()))


async def other_panels_relay_loop() -> None:
    """Keep Voltx and Red X on their original, independent schedule."""
    while True:
        try:
            records = await asyncio.to_thread(fetch_other_records_sync)
            await persist_records(records)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Non-Hadi notification cycle failed.")
        await asyncio.sleep(POLL_SECONDS)


async def dynamic_panels_relay_loop() -> None:
    """Poll admin-added panels independently from the existing panel flow."""
    last_polled: dict[int, float] = {}
    startup_baseline_done = False

    while True:
        try:
            if not startup_baseline_done:
                # Run the dynamic startup snapshot inside this task. A slow or
                # broken dynamic panel must not delay Hadi's fast scheduler.
                await asyncio.to_thread(prime_dynamic_panels_sync)
                startup_baseline_done = True
            panels = await asyncio.to_thread(get_active_dynamic_panels)
            now = time.monotonic()
            due_panels: list[dict[str, Any]] = []
            for panel in panels:
                panel_id = int(panel["id"])
                try:
                    interval = max(2, int(panel["poll_seconds"]))
                except (TypeError, ValueError):
                    interval = 7
                if now - last_polled.get(panel_id, 0.0) >= interval:
                    due_panels.append(panel)

            if due_panels:
                results = await asyncio.gather(
                    *(
                        asyncio.to_thread(fetch_dynamic_panel_sync, panel)
                        for panel in due_panels
                    )
                )
                for panel, result in zip(due_panels, results):
                    panel_id = int(panel["id"])
                    last_polled[panel_id] = time.monotonic()
                    ok, records, error = result

                    if not ok:
                        # Only this dynamic panel is disabled. The core relay
                        # loop and every other dynamic panel remain untouched.
                        await asyncio.to_thread(disable_dynamic_panel, panel_id, error)
                        logger.error(
                            "Dynamic panel '%s' disabled after API error: %s",
                            panel["name"],
                            error,
                        )
                        continue

                    await asyncio.to_thread(clear_dynamic_panel_error, panel_id)
                    for record in records:
                        await asyncio.to_thread(claim_notification, record)

        except asyncio.CancelledError:
            raise
        except Exception:
            # A dynamic-panel/database failure must never terminate this task
            # or affect the existing relay loop.
            logger.exception("Dynamic panel relay cycle failed.")

        await asyncio.sleep(1)


def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def valid_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(value.strip())
        return (
            parsed.scheme.casefold() in {"http", "https"}
            and bool(parsed.netloc)
            and bool(parsed.hostname)
        )
    except ValueError:
        return False


def admin_dashboard_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="➕  Add SMS Panel",
                    callback_data="admin_add_panel",
                ),
                InlineKeyboardButton(
                    text="🎛️  Manage Panels",
                    callback_data="admin_manage_panels",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="⚙️  Core Settings",
                    callback_data="admin_settings",
                ),
                InlineKeyboardButton(
                    text="🔄  Refresh",
                    callback_data="admin_refresh",
                ),
            ],
        ]
    )


def admin_back_keyboard(
    callback_data: str = "admin_home",
    label: str = "↩️  Back to Dashboard",
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=label, callback_data=callback_data)]
        ]
    )


def panel_status_label(panel: dict[str, Any]) -> str:
    if panel.get("is_active"):
        return "🟢 ACTIVE"
    if panel.get("last_error"):
        return "⚠️ AUTO-DISABLED"
    return "⚪ INACTIVE"


def masked_api_key(value: Any) -> str:
    key = str(value or "").strip()
    if not key or key.casefold() == "skip":
        return "Not required"
    return "Configured ••••••••"


async def send_admin_dashboard(
    message: Message | CallbackQuery,
    edit: bool = False,
) -> None:
    all_panels = get_all_dynamic_panels()
    active_count = sum(1 for panel in all_panels if panel["is_active"])
    failed_count = sum(
        1 for panel in all_panels if panel.get("last_error") and not panel["is_active"]
    )
    inactive_count = max(0, len(all_panels) - active_count - failed_count)
    group_id = get_setting("GROUP_CHAT_ID", str(GROUP_CHAT_ID))
    text = (
        "<blockquote><b>👑 INFINITY CONTROL CENTER</b>\n"
        "<i>Secure notification operations</i></blockquote>\n\n"
        "<b>📡 LIVE OVERVIEW</b>\n"
        "🟢 <b>Core Relay:</b> Operational\n"
        f"🔵 <b>SMS Panels:</b> {active_count} active  •  "
        f"{failed_count} attention  •  {inactive_count} inactive\n"
        f"👥 <b>Target Group:</b> <code>{html.escape(str(group_id))}</code>\n\n"
        "<b>⚡ QUICK ACTIONS</b>\n"
        "<i>Choose an operation below. Every panel runs in isolation.</i>"
    )
    keyboard = admin_dashboard_keyboard()
    if edit and isinstance(message, CallbackQuery):
        if message.message:
            await message.message.edit_text(text, reply_markup=keyboard)
    else:
        await message.answer(text, reply_markup=keyboard)


@dispatcher.message(Command("admin"))
async def admin_dashboard(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    await state.clear()
    await send_admin_dashboard(message)


@dispatcher.callback_query(F.data == "admin_home")
async def admin_home(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer()
    await state.clear()
    await send_admin_dashboard(call, edit=True)


@dispatcher.callback_query(F.data == "admin_refresh")
async def admin_refresh(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer("Dashboard refreshed.")
    await send_admin_dashboard(call, edit=True)


@dispatcher.message(Command("cancel"))
async def cancel_admin_action(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    current_state = await state.get_state()
    if current_state is None:
        return
    await state.clear()
    await message.answer(
        "<b>✖️ Action cancelled.</b>\n"
        "<i>No settings or panel data was changed.</i>"
    )
    await send_admin_dashboard(message)


@dispatcher.callback_query(F.data == "admin_settings")
async def admin_settings(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer()
    group_id = get_setting("GROUP_CHAT_ID", str(GROUP_CHAT_ID))
    channel_url = get_setting("MAIN_CHANNEL_URL", MAIN_CHANNEL_URL)
    number_url = get_setting("GET_NUMBER_URL", GET_NUMBER_URL)
    text = (
        "<blockquote><b>⚙️ CORE SETTINGS</b>\n"
        "<i>Control the notification destinations</i></blockquote>\n\n"
        f"👥 <b>Group ID</b>\n<code>{html.escape(str(group_id))}</code>\n\n"
        f"📢 <b>Main Channel</b>\n{html.escape(str(channel_url))}\n\n"
        f"🤖 <b>Number Bot</b>\n{html.escape(str(number_url))}"
    )
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✏️  Edit Group ID",
                    callback_data="edit_group",
                ),
                InlineKeyboardButton(
                    text="✏️  Edit Channel",
                    callback_data="edit_channel",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="✏️  Edit Number Bot",
                    callback_data="edit_number_bot",
                )
            ],
            [
                InlineKeyboardButton(
                    text="↩️  Back to Dashboard",
                    callback_data="admin_home",
                )
            ],
        ]
    )
    if call.message:
        await call.message.edit_text(text, reply_markup=keyboard)


@dispatcher.callback_query(F.data == "edit_group")
async def start_edit_group(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer()
    await call.message.answer(
        "<blockquote><b>👥 UPDATE GROUP DESTINATION</b></blockquote>\n\n"
        "Send the new <b>Group Chat ID</b>.\n"
        "Example: <code>-100123456789</code>\n\n"
        "Type /cancel to exit without changing anything."
    )
    await state.set_state(AdminStates.waiting_for_group_chat_id)


@dispatcher.message(AdminStates.waiting_for_group_chat_id)
async def process_group_id(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    value = (message.text or "").strip()
    try:
        group_id = int(value)
    except ValueError:
        await message.answer(
            "❌ <b>Invalid Group ID.</b>\n"
            "Use a numeric Telegram group ID, for example "
            "<code>-100123456789</code>."
        )
        return
    if group_id == 0:
        await message.answer("❌ <b>Group ID cannot be 0.</b>\nPlease try again:")
        return
    set_setting("GROUP_CHAT_ID", str(group_id))
    await state.clear()
    await message.answer(
        "✅ <b>Group destination updated.</b>\n"
        f"New ID: <code>{group_id}</code>"
    )
    await send_admin_dashboard(message)


@dispatcher.callback_query(F.data == "edit_channel")
async def start_edit_channel(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer()
    await call.message.answer(
        "<blockquote><b>📢 UPDATE MAIN CHANNEL</b></blockquote>\n\n"
        "Send a complete <b>http/https URL</b>.\n"
        "Type /cancel to exit without changing anything."
    )
    await state.set_state(AdminStates.waiting_for_main_channel_url)


@dispatcher.message(AdminStates.waiting_for_main_channel_url)
async def process_channel_url(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    value = (message.text or "").strip()
    if not valid_http_url(value):
        await message.answer(
            "❌ <b>Invalid URL.</b>\n"
            "Use a complete URL beginning with <code>http://</code> or "
            "<code>https://</code>."
        )
        return
    set_setting("MAIN_CHANNEL_URL", value)
    await state.clear()
    await message.answer("✅ <b>Main channel URL updated successfully.</b>")
    await send_admin_dashboard(message)


@dispatcher.callback_query(F.data == "edit_number_bot")
async def start_edit_number_bot(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer()
    await call.message.answer(
        "<blockquote><b>🤖 UPDATE NUMBER BOT</b></blockquote>\n\n"
        "Send a complete <b>http/https URL</b>.\n"
        "Type /cancel to exit without changing anything."
    )
    await state.set_state(AdminStates.waiting_for_number_bot_url)


@dispatcher.message(AdminStates.waiting_for_number_bot_url)
async def process_number_bot(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    value = (message.text or "").strip()
    if not valid_http_url(value):
        await message.answer(
            "❌ <b>Invalid URL.</b>\n"
            "Use a complete URL beginning with <code>http://</code> or "
            "<code>https://</code>."
        )
        return
    set_setting("GET_NUMBER_URL", value)
    await state.clear()
    await message.answer("✅ <b>Number bot URL updated successfully.</b>")
    await send_admin_dashboard(message)


@dispatcher.callback_query(F.data == "admin_add_panel")
async def start_add_panel(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        return
    await call.answer()
    await call.message.answer(
        "<blockquote><b>➕ ADD SMS PANEL</b>\n"
        "<i>Two-step secure setup</i></blockquote>\n\n"
        "<b>Step 1 of 2 • API endpoint</b>\n"
        "Send the complete <b>SMS API URL</b>.\n\n"
        "Existing query parameters will be preserved. "
        "The endpoint should return a Hadi-compatible JSON response.\n\n"
        "Type /cancel to exit."
    )
    await state.set_state(AdminStates.waiting_for_panel_url)


@dispatcher.message(AdminStates.waiting_for_panel_url)
async def process_panel_url(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    url = (message.text or "").strip()
    if not valid_http_url(url):
        await message.answer(
            "❌ <b>Invalid API URL.</b>\n"
            "Send a complete URL beginning with <code>http://</code> or "
            "<code>https://</code>."
        )
        return
    await state.update_data(panel_url=url)
    await message.answer(
        "<b>Step 2 of 2 • Authentication</b>\n"
        "Send the <b>API Key/Token</b>.\n\n"
        "The bot will try compatible authentication headers and a token "
        "query fallback. If this endpoint is public, type <code>Skip</code>.\n\n"
        "Type /cancel to exit."
    )
    await state.set_state(AdminStates.waiting_for_panel_key)


@dispatcher.message(AdminStates.waiting_for_panel_key)
async def process_panel_key(message: Message, state: FSMContext) -> None:
    if not message.from_user or not is_admin(message.from_user.id):
        return
    api_key = (message.text or "").strip()
    if not api_key:
        await message.answer(
            "❌ <b>API key cannot be empty.</b>\n"
            "Send a key/token or type <code>Skip</code>."
        )
        return
    data = await state.get_data()
    panel_url = str(data.get("panel_url") or "").strip()
    if not valid_http_url(panel_url):
        await state.clear()
        await message.answer(
            "❌ <b>Setup expired.</b>\n"
            "Please start again from <b>Add SMS Panel</b>."
        )
        await send_admin_dashboard(message)
        return
    host = urlsplit(panel_url).hostname or "sms-panel"
    try:
        with closing(db_connection()) as conn:
            cursor = conn.execute(
                """
                INSERT INTO dynamic_panels(
                    name, api_url, api_key, poll_seconds, is_active,
                    last_error, disabled_at, created_at
                ) VALUES (?, ?, ?, ?, 0, '', '', ?)
                """,
                (
                    "SMS Panel",
                    panel_url,
                    api_key,
                    HADI_POLL_SECONDS,
                    now_utc(),
                ),
            )
            panel_id = int(cursor.lastrowid)
            auto_name = f"{host} #{panel_id}"[:80]
            conn.execute(
                "UPDATE dynamic_panels SET name = ? WHERE id = ?",
                (auto_name, panel_id),
            )
            conn.commit()
    except Exception:
        logger.exception("Could not save a new dynamic panel.")
        await state.clear()
        await message.answer(
            "❌ <b>Panel could not be saved.</b>\n"
            "The database rejected this setup. No partial panel was activated."
        )
        await send_admin_dashboard(message)
        return

    panel = await asyncio.to_thread(get_dynamic_panel, panel_id)
    if panel is None:
        await state.clear()
        await message.answer(
            "❌ <b>Panel could not be loaded after saving.</b>\n"
            "Please try again."
        )
        await send_admin_dashboard(message)
        return

    # Snapshot the panel immediately so existing records are not forwarded as
    # new messages. A failing new panel is disabled right here.
    try:
        ok, records, error = await asyncio.to_thread(fetch_dynamic_panel_sync, panel)
    except Exception as exc:
        logger.exception("Initial verification failed for dynamic panel %s.", panel_id)
        ok, records, error = (
            False,
            [],
            f"{type(exc).__name__}: {exc}",
        )
    if ok:
        try:
            baseline_count = await asyncio.to_thread(
                prepare_startup_baseline,
                records,
            )
            with closing(db_connection()) as conn:
                conn.execute(
                    """
                    UPDATE dynamic_panels
                    SET is_active = 1, last_error = '', disabled_at = ''
                    WHERE id = ?
                    """,
                    (panel_id,),
                )
                conn.commit()
        except Exception as exc:
            logger.exception("Could not activate dynamic panel %s.", panel_id)
            ok = False
            error = f"{type(exc).__name__}: {exc}"

    if ok:
        status_text = (
            "<blockquote><b>✅ PANEL ACTIVATED</b></blockquote>\n\n"
            f"🏷️ <b>Name:</b> {html.escape(str(panel['name']))}\n"
            f"⚡ <b>Polling:</b> {HADI_POLL_SECONDS}s\n"
            "🔐 <b>Verification:</b> Successful\n"
            f"🧹 <b>Old records skipped:</b> {baseline_count}\n\n"
            "<i>This panel is now running in an isolated relay loop.</i>"
        )
    else:
        await asyncio.to_thread(disable_dynamic_panel, panel_id, error)
        status_text = (
            "<blockquote><b>⚠️ PANEL SAVED — VERIFICATION FAILED</b></blockquote>\n\n"
            f"🏷️ <b>Name:</b> {html.escape(str(panel['name']))}\n"
            "🔴 <b>Status:</b> Auto-disabled\n\n"
            "The existing panels were not affected. Fix the endpoint or key, "
            "then enable this panel from Manage Panels.\n\n"
            f"<code>{html.escape(error[:500])}</code>"
        )

    await state.clear()
    await message.answer(status_text)
    await send_admin_dashboard(message)


@dispatcher.callback_query(F.data == "admin_manage_panels")
async def manage_panels(
    call: CallbackQuery,
    acknowledge: bool = True,
) -> None:
    if not is_admin(call.from_user.id):
        return
    if acknowledge:
        await call.answer()
    panels = get_all_dynamic_panels()
    if not panels:
        keyboard = InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="➕  Add SMS Panel",
                        callback_data="admin_add_panel",
                    )
                ],
                [
                    InlineKeyboardButton(
                        text="↩️  Back to Dashboard",
                        callback_data="admin_home",
                    )
                ],
            ]
        )
        if call.message:
            await call.message.edit_text(
                "<blockquote><b>🎛️ PANEL MANAGER</b></blockquote>\n\n"
                "📭 <b>No SMS panels added yet.</b>\n"
                "<i>Add a compatible endpoint to start isolated forwarding.</i>",
                reply_markup=keyboard,
            )
        return

    buttons = []
    for panel in panels:
        buttons.append(
            [
                InlineKeyboardButton(
                    text=f"{panel_status_label(panel)}  {str(panel['name'])[:34]}",
                    callback_data=f"panel_dtl_{panel['id']}",
                )
            ]
        )
    buttons.append(
        [
            InlineKeyboardButton(
                text="➕  Add Another Panel",
                callback_data="admin_add_panel",
            )
        ]
    )
    buttons.append(
        [
            InlineKeyboardButton(
                text="↩️  Back to Dashboard",
                callback_data="admin_home",
            )
        ]
    )
    if call.message:
        active_count = sum(1 for panel in panels if panel["is_active"])
        await call.message.edit_text(
            "<blockquote><b>🎛️ PANEL MANAGER</b>\n"
            f"<i>{active_count}/{len(panels)} panels currently active</i></blockquote>\n\n"
            "Select a panel to view status, toggle relay, or remove it.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
        )


@dispatcher.callback_query(F.data.startswith("panel_dtl_"))
async def panel_detail(call: CallbackQuery, acknowledge: bool = True) -> None:
    if not is_admin(call.from_user.id):
        return
    try:
        panel_id = int(str(call.data).rsplit("_", 1)[1])
    except (AttributeError, ValueError):
        await call.answer("Invalid panel.", show_alert=True)
        return
    panel = get_dynamic_panel(panel_id)
    if panel is None:
        await call.answer("Panel not found.", show_alert=True)
        return
    if acknowledge:
        await call.answer()

    status = panel_status_label(panel)
    toggle_text = "⏸️  Disable Panel" if panel["is_active"] else "▶️  Enable Panel"
    last_error = str(panel.get("last_error") or "").strip()
    text = (
        "<blockquote><b>📝 PANEL DETAILS</b>\n"
        f"<i>{html.escape(str(panel['name']))}</i></blockquote>\n\n"
        f"📍 <b>Status:</b> {status}\n"
        f"⚡ <b>Polling:</b> {panel['poll_seconds']} seconds\n"
        f"🔐 <b>API Key:</b> <code>{masked_api_key(panel.get('api_key'))}</code>\n"
        f"🔗 <b>Endpoint:</b>\n<code>{html.escape(str(panel['api_url']))}</code>\n"
    )
    if last_error:
        text += (
            "\n⚠️ <b>Last error</b>\n"
            f"<code>{html.escape(last_error[:800])}</code>\n"
        )
    text += "\n<i>Panel failures are isolated from the core relay.</i>"
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text=toggle_text, callback_data=f"toggle_p_{panel_id}"
                )
            ],
            [
                InlineKeyboardButton(
                    text="🗑️  Delete Panel", callback_data=f"del_p_{panel_id}"
                )
            ],
            [
                InlineKeyboardButton(
                    text="↩️  Back to Panel Manager",
                    callback_data="admin_manage_panels",
                )
            ],
        ]
    )
    if call.message:
        await call.message.edit_text(text, reply_markup=keyboard)


@dispatcher.callback_query(F.data.startswith("toggle_p_"))
async def toggle_panel(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        return
    try:
        panel_id = int(str(call.data).rsplit("_", 1)[1])
    except (AttributeError, ValueError):
        await call.answer("Invalid panel.", show_alert=True)
        return
    await call.answer()
    with closing(db_connection()) as conn:
        conn.execute(
            """
            UPDATE dynamic_panels
            SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END,
                last_error = CASE WHEN is_active = 1 THEN last_error ELSE '' END,
                disabled_at = CASE WHEN is_active = 1 THEN disabled_at ELSE '' END
            WHERE id = ?
            """,
            (panel_id,),
        )
        conn.commit()
    await manage_panels(call, acknowledge=False)


@dispatcher.callback_query(F.data.startswith("del_p_"))
async def request_delete_panel(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        return
    try:
        panel_id = int(str(call.data).rsplit("_", 1)[1])
    except (AttributeError, ValueError):
        await call.answer("Invalid panel.", show_alert=True)
        return
    panel = get_dynamic_panel(panel_id)
    if panel is None:
        await call.answer("Panel not found.", show_alert=True)
        return
    await call.answer("Confirm panel deletion.", show_alert=True)
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅  Yes, Delete",
                    callback_data=f"confirm_del_p_{panel_id}",
                ),
                InlineKeyboardButton(
                    text="✖️  Keep Panel",
                    callback_data=f"cancel_del_p_{panel_id}",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="↩️  Back to Panel Details",
                    callback_data=f"panel_dtl_{panel_id}",
                )
            ],
        ]
    )
    if call.message:
        await call.message.edit_text(
            "<blockquote><b>⚠️ CONFIRM DELETION</b></blockquote>\n\n"
            f"Delete <b>{html.escape(str(panel['name']))}</b> permanently?\n\n"
            "This removes the panel configuration and stops its relay. "
            "Existing core panels will not be affected.",
            reply_markup=keyboard,
        )


@dispatcher.callback_query(F.data.startswith("cancel_del_p_"))
async def cancel_delete_panel(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        return
    try:
        panel_id = int(str(call.data).rsplit("_", 1)[1])
    except (AttributeError, ValueError):
        await call.answer("Invalid panel.", show_alert=True)
        return
    await call.answer("Panel kept.")
    await panel_detail(call, acknowledge=False)


@dispatcher.callback_query(F.data.startswith("confirm_del_p_"))
async def delete_panel(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        return
    try:
        panel_id = int(str(call.data).rsplit("_", 1)[1])
    except (AttributeError, ValueError):
        await call.answer("Invalid panel.", show_alert=True)
        return
    panel = get_dynamic_panel(panel_id)
    if panel is None:
        await call.answer("Panel already removed.", show_alert=True)
        await manage_panels(call, acknowledge=False)
        return
    with closing(db_connection()) as conn:
        conn.execute("DELETE FROM dynamic_panels WHERE id = ?", (panel_id,))
        conn.commit()
    await call.answer("Panel deleted.")
    await manage_panels(call, acknowledge=False)


async def main() -> None:
    init_db()
    if not get_setting("GROUP_CHAT_ID", ""):
        set_setting("GROUP_CHAT_ID", str(GROUP_CHAT_ID))
    if not get_setting("MAIN_CHANNEL_URL", ""):
        set_setting("MAIN_CHANNEL_URL", MAIN_CHANNEL_URL)
    if not get_setting("GET_NUMBER_URL", ""):
        set_setting("GET_NUMBER_URL", GET_NUMBER_URL)

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    try:
        me = await bot.get_me()
        logger.info("Notification bot started as @%s", me.username)
        logger.info("Target group chat ID: %s", GROUP_CHAT_ID)
        await bot.delete_webhook(drop_pending_updates=True)
        # Establish the exact startup boundary before starting relay workers.
        # If the panel is temporarily unavailable, do not start forwarding:
        # otherwise an old latest-N window could be mistaken for new OTPs.
        while True:
            startup_records = await asyncio.to_thread(fetch_all_records_sync)
            if (
                last_panel_api_ok
                and (not VOLTX_ENABLED or last_voltx_api_ok)
                and (not REDX_ENABLED or last_redx_api_ok)
            ):
                break
            logger.warning(
                "Waiting for a successful API baseline; old OTPs will not be "
                "forwarded until the startup snapshot is complete."
            )
            await asyncio.sleep(5)
        baseline_count = await asyncio.to_thread(
            prepare_startup_baseline,
            startup_records,
        )
        logger.info(
            "Startup baseline ready: %d existing OTP records suppressed.",
            baseline_count,
        )
        hadi_task = asyncio.create_task(hadi_relay_loop())
        other_panels_task = asyncio.create_task(other_panels_relay_loop())
        dynamic_panels_task = asyncio.create_task(dynamic_panels_relay_loop())
        worker_tasks = [
            asyncio.create_task(notification_worker(bot, worker_id))
            for worker_id in range(1, SEND_WORKERS + 1)
        ]
        try:
            await dispatcher.start_polling(bot, handle_signals=False)
        finally:
            hadi_task.cancel()
            other_panels_task.cancel()
            dynamic_panels_task.cancel()
            for worker_task in worker_tasks:
                worker_task.cancel()
            await asyncio.gather(
                hadi_task,
                other_panels_task,
                dynamic_panels_task,
                *worker_tasks,
                return_exceptions=True,
            )
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Notification bot stopped.")