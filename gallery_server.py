import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import webbrowser
from contextlib import closing
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit


ROOT = Path(__file__).resolve().parent
IMAGE_DIR = ROOT / "polaroid-images"
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif", ".bmp"}
PUBLIC_ROOT_FILES = {
    "IMG_3605.JPG",
    "IMG_3607.JPG",
    "IMG_4598.JPG",
    "IMG_4607.JPG",
    "appointment.html",
    "cafe-date.svg",
    "index.html",
    "letter.html",
    "movie-date.svg",
    "polaroid.html",
    "style.css",
    "tải xuống (1).jpg",
    "tải xuống.jpg",
    "vault.html",
}
DATABASE_PATH = Path(
    os.environ.get(
        "DATABASE_PATH",
        str(ROOT.parent / ".boysdays_data" / "appointment_responses.sqlite3"),
    )
)
AUTH_API_PATH = "/api/login"
RESPONSE_API_PATH = "/api/appointment-response"
AUTH_COOKIE_NAME = "babi_site_session"
AUTH_SESSION_TTL_SECONDS = 8 * 60 * 60
AUTH_PASSWORDS = tuple(
    password.strip()
    for password in os.environ.get("SITE_PASSWORDS", "150306,050105").split(",")
    if password.strip()
)
AUTH_PASSWORD_SALT = secrets.token_bytes(16)
AUTH_PASSWORD_ITERATIONS = 200_000
AUTH_PASSWORD_HASHES = tuple(
    hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        AUTH_PASSWORD_SALT,
        AUTH_PASSWORD_ITERATIONS,
    )
    for password in AUTH_PASSWORDS
)
AUTHENTICATION_PUBLIC_PATHS = {"/index.html", "/style.css"}
MAX_LOGIN_FAILURES = 10
LOGIN_FAILURE_WINDOW_SECONDS = 300
_sessions = {}
_sessions_lock = threading.Lock()
_login_failures = {}
_login_failures_lock = threading.Lock()
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
URL = f"http://127.0.0.1:{PORT}/vault.html"


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DATABASE_PATH)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS appointment_response (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                activity TEXT CHECK (activity IS NULL OR activity IN ('cafe', 'movie')),
                answer TEXT CHECK (answer IS NULL OR answer IN ('accept', 'decline')),
                updated_at TEXT NOT NULL
            )
            """
        )


class GalleryHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def translate_path(self, path):
        requested_path = Path(super().translate_path(path)).resolve()
        try:
            relative_path = requested_path.relative_to(ROOT)
        except ValueError:
            return str(ROOT / "__blocked_static_resource__" / "not-found")

        parts = relative_path.parts
        is_authenticated = self._is_authenticated()
        if (
            len(parts) == 1
            and parts[0] in PUBLIC_ROOT_FILES
            and (is_authenticated or f"/{parts[0]}" in AUTHENTICATION_PUBLIC_PATHS)
        ):
            return str(requested_path)
        if (
            len(parts) == 2
            and parts[0] == IMAGE_DIR.name
            and requested_path.suffix.lower() in IMAGE_EXTENSIONS
            and requested_path.is_file()
            and is_authenticated
        ):
            return str(requested_path)
        return str(ROOT / "__blocked_static_resource__" / "not-found")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == AUTH_API_PATH:
            self.send_error(405)
            return
        if path == RESPONSE_API_PATH:
            if not self._is_authenticated():
                self._send_json(401, {"error": "Authentication required."})
                return
            self._get_appointment_response()
            return
        if path == "/":
            self.path = "/index.html"
            path = "/index.html"
        if path == "/api/photos":
            if not self._is_authenticated():
                self._send_json(401, {"error": "Authentication required."})
                return
            self._get_photos()
            return

        if not self._is_authenticated() and path not in AUTHENTICATION_PUBLIC_PATHS:
            self._redirect_to_index()
            return
        super().do_GET()

    def do_HEAD(self):
        path = urlsplit(self.path).path
        if path == "/":
            self.path = "/index.html"
            path = "/index.html"
        if not self._is_authenticated() and path not in AUTHENTICATION_PUBLIC_PATHS:
            if path.startswith("/api/"):
                self.send_response(401)
                self.end_headers()
            else:
                self._redirect_to_index()
            return
        super().do_HEAD()

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == AUTH_API_PATH:
            self._login()
            return
        if path != RESPONSE_API_PATH:
            self.send_error(404)
            return
        if not self._is_authenticated():
            self._send_json(401, {"error": "Authentication required."})
            return

        payload = self._read_json_payload()
        if payload is None:
            return

        activity = payload.get("activity")
        answer = payload.get("answer")
        if activity not in (None, "cafe", "movie"):
            self._send_json(400, {"error": "Activity must be cafe or movie."})
            return
        if answer not in (None, "accept", "decline"):
            self._send_json(400, {"error": "Answer must be accept or decline."})
            return
        if activity is None and answer is None:
            self._send_json(400, {"error": "An activity or answer is required."})
            return

        updated_at = datetime.now(timezone.utc).isoformat()
        try:
            with closing(sqlite3.connect(DATABASE_PATH)) as connection, connection:
                connection.execute(
                    """
                    INSERT INTO appointment_response (id, activity, answer, updated_at)
                    VALUES (1, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        activity = excluded.activity,
                        answer = excluded.answer,
                        updated_at = excluded.updated_at
                    """,
                    (activity, answer, updated_at),
                )
                saved_response = connection.execute(
                    "SELECT activity, answer, updated_at FROM appointment_response WHERE id = 1"
                ).fetchone()
        except sqlite3.Error as error:
            self.log_error("Could not save appointment response: %s", error)
            self._send_json(500, {"error": "Could not save the response."})
            return

        self._send_json(
            200,
            {
                "response": {
                    "activity": saved_response[0],
                    "answer": saved_response[1],
                    "updated_at": saved_response[2],
                }
            },
        )

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def _get_photos(self):
        photos = [
            {
                "src": f"polaroid-images/{quote(path.name)}",
                "name": path.name,
            }
            for path in IMAGE_DIR.iterdir()
            if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
        ]
        photos.sort(key=lambda photo: photo["name"].casefold())
        payload = json.dumps(photos, ensure_ascii=False).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_payload(self):
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            self._send_json(411, {"error": "Content-Length is required."})
            return None
        try:
            body_length = int(content_length)
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length."})
            return None
        if body_length < 0 or body_length > 4096:
            self._send_json(413, {"error": "Request body is too large."})
            return None

        try:
            payload = json.loads(self.rfile.read(body_length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "Request body must be valid JSON."})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "Request body must be a JSON object."})
            return None
        return payload

    def _login(self):
        payload = self._read_json_payload()
        if payload is None:
            return

        if self._is_login_rate_limited():
            self._send_json(429, {"error": "Too many failed login attempts. Try again later."})
            return

        password = payload.get("password")
        if (
            not isinstance(password, str)
            or len(password) > 128
            or not self._password_is_valid(password)
        ):
            self._record_failed_login()
            self._send_json(401, {"error": "Invalid password."})
            return

        self._clear_login_failures()
        token = secrets.token_urlsafe(32)
        with _sessions_lock:
            _sessions[token] = time.time() + AUTH_SESSION_TTL_SECONDS

        cookie = (
            f"{AUTH_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; "
            f"Max-Age={AUTH_SESSION_TTL_SECONDS}"
        )
        if self.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip().lower() == "https":
            cookie += "; Secure"
        self._send_json(
            200,
            {"authenticated": True},
            (("Set-Cookie", cookie),),
        )

    def _password_is_valid(self, password):
        candidate_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            AUTH_PASSWORD_SALT,
            AUTH_PASSWORD_ITERATIONS,
        )
        return any(
            hmac.compare_digest(candidate_hash, expected_hash)
            for expected_hash in AUTH_PASSWORD_HASHES
        )

    def _is_authenticated(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return False
        session_cookie = cookie.get(AUTH_COOKIE_NAME)
        if session_cookie is None:
            return False

        token = session_cookie.value
        now = time.time()
        with _sessions_lock:
            expires_at = _sessions.get(token)
            if expires_at is None:
                return False
            if expires_at <= now:
                del _sessions[token]
                return False
            _sessions[token] = now + AUTH_SESSION_TTL_SECONDS
        return True

    def _login_client_key(self):
        forwarded_ip = self.headers.get("CF-Connecting-IP", "").split(",", 1)[0].strip()
        return forwarded_ip or self.client_address[0]

    def _is_login_rate_limited(self):
        now = time.monotonic()
        client_key = self._login_client_key()
        with _login_failures_lock:
            failures = [
                attempt
                for attempt in _login_failures.get(client_key, [])
                if now - attempt < LOGIN_FAILURE_WINDOW_SECONDS
            ]
            if failures:
                _login_failures[client_key] = failures
            else:
                _login_failures.pop(client_key, None)
            return len(failures) >= MAX_LOGIN_FAILURES

    def _record_failed_login(self):
        now = time.monotonic()
        client_key = self._login_client_key()
        with _login_failures_lock:
            failures = [
                attempt
                for attempt in _login_failures.get(client_key, [])
                if now - attempt < LOGIN_FAILURE_WINDOW_SECONDS
            ]
            failures.append(now)
            _login_failures[client_key] = failures

    def _clear_login_failures(self):
        client_key = self._login_client_key()
        with _login_failures_lock:
            _login_failures.pop(client_key, None)

    def _redirect_to_index(self):
        self.send_response(302)
        self.send_header("Location", "/index.html")
        self.end_headers()

    def _get_appointment_response(self):
        try:
            with closing(sqlite3.connect(DATABASE_PATH)) as connection:
                connection.row_factory = sqlite3.Row
                saved_response = connection.execute(
                    "SELECT activity, answer, updated_at FROM appointment_response WHERE id = 1"
                ).fetchone()
        except sqlite3.Error as error:
            self.log_error("Could not read appointment response: %s", error)
            self._send_json(500, {"error": "Could not read the response."})
            return

        response = dict(saved_response) if saved_response else None
        self._send_json(200, {"response": response})

    def _send_json(self, status_code, payload, extra_headers=()):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for header_name, header_value in extra_headers:
            self.send_header(header_name, header_value)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    IMAGE_DIR.mkdir(exist_ok=True)
    initialize_database()
    server = ThreadingHTTPServer((HOST, PORT), GalleryHandler)
    print(f"Album đang chạy tại {URL}. Nhấn Ctrl+C để dừng.")
    if "PORT" not in os.environ:
        threading.Timer(0.5, webbrowser.open, args=(URL,)).start()
    server.serve_forever()
