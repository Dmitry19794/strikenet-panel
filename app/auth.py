"""
HTTP Basic Authentication для StrikeNet панели.

Закрывает ВСЁ подряд:
  • панель      GET /
  • REST API    /api/*
  • WebSocket   /ws/runs, /ws/logs/{id}   ← handshake тоже, иначе логи читаются без пароля
  • /static, /docs, /openapi.json

Пароль хранится ТОЛЬКО хешем PBKDF2-SHA256 в auth.json (права 0600).
Plaintext на диск никогда не пишется и не логируется.

FAILOK-CLOSED: если auth.json отсутствует, битый или пустой — 401 на всё.
Панель не отдаётся «открытой» ни при каком стечении обстоятельств.

Клиент (браузер) сам пришлёт заголовок Authorization и на fetch, и на
WS-handshake → панель (orchestrator-panel.html) править НЕ нужно.

Управление:
    printf '%s' '<пароль>' | python -m app.auth set       # записать/сменить хеш
    printf '%s' '<пароль>' | python -m app.auth verify    # проверить
    python -m app.auth info                               # показать метаданные
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path

AUTH_FILE = Path(__file__).resolve().parent.parent / "auth.json"
DEFAULT_USER = "admin"
DEFAULT_REALM = "StrikeNet"
ALGO = "pbkdf2_sha256"
ITERATIONS = 600_000
SALT_BYTES = 16

# ── хеширование ─────────────────────────────────────────────


def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = ITERATIONS) -> dict:
    salt = salt or secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "algo": ALGO,
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": dk.hex(),
    }


def _matches(password: str, record: dict) -> bool:
    if record.get("algo") != ALGO:
        return False
    try:
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["hash"])
        iterations = int(record["iterations"])
    except (KeyError, ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)


def save_credentials(user: str, password: str,
                     path: Path = AUTH_FILE) -> dict:
    from datetime import datetime, timezone
    record = hash_password(password)
    record["user"] = user
    record["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps(record, indent=2))
    path.chmod(0o600)
    return record


def load_credentials(path: Path = AUTH_FILE) -> dict | None:
    """Возвращает {'user','salt','hash','iterations','algo'} либо None (fail-closed)."""
    try:
        raw = path.read_text()
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("user") or not data.get("salt") or not data.get("hash"):
        return None
    if data.get("algo") != ALGO:
        return None
    return data


# ── разбор заголовка ────────────────────────────────────────


def _header(scope: dict, name: bytes) -> bytes | None:
    for key, value in scope.get("headers") or []:
        if key.lower() == name:
            return value
    return None


def _parse_basic(header: bytes | None) -> tuple[str, str] | None:
    if not header:
        return None
    try:
        scheme, sep, payload = header.partition(b" ")
        if not sep or scheme.lower() != b"basic":
            return None
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None
    user, colon, password = raw.partition(b":")
    if not colon:
        return None
    try:
        return user.decode("utf-8"), password.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ── middleware ──────────────────────────────────────────────


class BasicAuthMiddleware:
    """
    Чистый ASGI-милдвар (НЕ BaseHTTPMiddleware) — иначе WebSocket-скоупы
    провалились бы мимо проверки и /ws/* остались бы открыты.
    """

    def __init__(self, app, credentials_path: str | Path | None = None,
                 realm: str = DEFAULT_REALM, username: str | None = None):
        self.app = app
        self.credentials_path = Path(credentials_path) if credentials_path else AUTH_FILE
        self.realm = realm
        self.username = username  # None → берём из auth.json
        self._cache: tuple[int, dict] | None = None

    # ── загрузка учётки с кешем по mtime (pbkdf2 на каждый запрос — дорого) ──
    def _creds(self) -> dict | None:
        try:
            mtime = self.credentials_path.stat().st_mtime_ns
        except OSError:
            self._cache = None
            return None
        if self._cache is not None and self._cache[0] == mtime:
            return self._cache[1]
        record = load_credentials(self.credentials_path)
        self._cache = (mtime, record)
        return record

    def _is_authorized(self, scope: dict) -> bool:
        creds = self._creds()
        if not creds:
            return False  # fail-closed
        parsed = _parse_basic(_header(scope, b"authorization"))
        if parsed is None:
            return False
        user, password = parsed
        # всегда считаем pbkdf2, даже если юзер не совпал — против тайминг-атаки
        ok_pw = _matches(password, creds)
        ok_user = hmac.compare_digest(
            user.encode("utf-8"), str(creds["user"]).encode("utf-8")
        )
        if self.username is not None:
            ok_user = ok_user and hmac.compare_digest(
                user.encode("utf-8"), self.username.encode("utf-8")
            )
        return ok_pw and ok_user

    def _challenge(self) -> bytes:
        return (
            f'Basic realm="{self.realm}", charset="UTF-8"'.encode("utf-8")
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        if self._is_authorized(scope):
            return await self.app(scope, receive, send)

        if scope["type"] == "websocket":
            # отказ ДО accept — клиент получает неудачный handshake
            await send({"type": "websocket.close", "code": 1008})
            return

        body = b"401 Unauthorized\n"
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"www-authenticate", self._challenge()),
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        })
        await send({"type": "http.response.body", "body": body})


# ── CLI ─────────────────────────────────────────────────────


def _read_password() -> str:
    """Пароль читаем ТОЛЬКО из stdin — он не должен попасть в argv/ps."""
    data = sys.stdin.read()
    pw = data.splitlines()[0] if data.splitlines() else ""
    if not pw:
        print("auth: пустой пароль из stdin", file=sys.stderr)
        sys.exit(2)
    return pw


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "info"
    if cmd == "set":
        user = DEFAULT_USER
        if "--user" in argv:
            user = argv[argv.index("--user") + 1]
        save_credentials(user, _read_password())
        print(f"auth: хеш записан в {AUTH_FILE} (права 600, plaintext не сохранён)")
        return 0
    if cmd == "verify":
        creds = load_credentials()
        if not creds:
            print("auth: FAIL — auth.json отсутствует или битый")
            return 1
        print("auth: " + ("OK — пароль верный"
                          if _matches(_read_password(), creds)
                          else "FAIL — неверный пароль"))
        return 0
    if cmd == "info":
        creds = load_credentials()
        if not creds:
            print(f"auth: {AUTH_FILE} отсутствует/битый → ВСЁ закрыто 401 (fail-closed)")
            return 1
        print(f"auth: файл     {AUTH_FILE}")
        print(f"auth: юзер     {creds['user']}")
        print(f"auth: алгоритм {creds['algo']} iter={creds['iterations']} "
              f"salt={len(creds['salt'])//2}б")
        print(f"auth: создан   {creds.get('created_at','?')}")
        print(f"auth: права    {oct(AUTH_FILE.stat().st_mode & 0o777)}")
        print("auth: пароль в файле НЕ хранится (только pbkdf2-хеш)")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
