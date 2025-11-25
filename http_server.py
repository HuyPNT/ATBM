import json
import base64
import hmac
import hashlib
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def b64url_decode(data_str: str) -> bytes:
    padding = '=' * (-len(data_str) % 4)
    return base64.urlsafe_b64decode(data_str + padding)


def jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = b64url_encode(json.dumps(payload).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    sig = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def jwt_decode(token: str, secret: str) -> dict | None:
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(sig_b64)):
            return None
        payload = json.loads(b64url_decode(payload_b64).decode('utf-8'))
        exp = payload.get('exp')
        if exp and int(time.time()) > int(exp):
            return None
        return payload
    except Exception:
        return None


class ServerApp:
    def __init__(self, db, secret: str):
        self.db = db
        self.secret = secret or 'change_me'

    def make_handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _send_json(self, code: int, obj: dict):
                data = json.dumps(obj).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _read_json(self) -> dict:
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    raw = self.rfile.read(length) if length > 0 else b''
                    return json.loads(raw.decode('utf-8')) if raw else {}
                except Exception:
                    return {}

            def _auth_user(self) -> int | None:
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    return None
                token = auth.split(' ', 1)[1]
                payload = jwt_decode(token, app.secret)
                if not payload:
                    return None
                return payload.get('uid')

            def do_POST(self):
                if self.path == '/auth/register':
                    body = self._read_json()
                    u = body.get('username', '')
                    p = body.get('password', '')
                    if not u or not p:
                        self._send_json(400, {'error': 'Thiếu dữ liệu'})
                        return
                    ok, uid = app.db.create_user(u, p)
                    if not ok:
                        self._send_json(409, {'error': 'Tài khoản đã tồn tại'})
                        return
                    self._send_json(200, {'ok': True, 'uid': uid})
                    return

                if self.path == '/auth/login':
                    body = self._read_json()
                    u = body.get('username', '')
                    p = body.get('password', '')
                    uid = app.db.verify_user(u, p)
                    if not uid:
                        self._send_json(401, {'error': 'Sai thông tin đăng nhập'})
                        return
                    payload = {'uid': uid, 'exp': int(time.time()) + 3600}
                    token = jwt_encode(payload, app.secret)
                    self._send_json(200, {'token': token})
                    return

                if self.path == '/resources/upload':
                    uid = self._auth_user()
                    if not uid:
                        self._send_json(401, {'error': 'Unauthorized'})
                        return
                    body = self._read_json()
                    name = body.get('filename', '')
                    data_b64 = body.get('data_b64', '')
                    if not name or not data_b64:
                        self._send_json(400, {'error': 'Thiếu dữ liệu'})
                        return
                    data = base64.b64decode(data_b64)
                    ok = app.db.store_resource(uid, name, data)
                    if not ok:
                        self._send_json(500, {'error': 'Lưu trữ thất bại'})
                        return
                    self._send_json(200, {'ok': True})
                    return

                if self.path == '/permissions/grant':
                    uid = self._auth_user()
                    if not uid:
                        self._send_json(401, {'error': 'Unauthorized'})
                        return
                    body = self._read_json()
                    name = body.get('filename', '')
                    grantee_name = body.get('grantee_username', '')
                    if not name or not grantee_name:
                        self._send_json(400, {'error': 'Thiếu dữ liệu'})
                        return
                    owner_id, _ = app.db.get_resource(name)
                    if owner_id is None:
                        self._send_json(404, {'error': 'Không tìm thấy'})
                        return
                    if owner_id != uid:
                        self._send_json(403, {'error': 'Forbidden'})
                        return
                    gid = app.db.get_user_id(grantee_name)
                    if not gid:
                        self._send_json(404, {'error': 'Không tìm thấy người dùng'})
                        return
                    ok = app.db.grant_permission(owner_id, name, gid)
                    if not ok:
                        self._send_json(500, {'error': 'Cấp quyền thất bại'})
                        return
                    self._send_json(200, {'ok': True})
                    return

                if self.path == '/permissions/revoke':
                    uid = self._auth_user()
                    if not uid:
                        self._send_json(401, {'error': 'Unauthorized'})
                        return
                    body = self._read_json()
                    name = body.get('filename', '')
                    grantee_name = body.get('grantee_username', '')
                    if not name or not grantee_name:
                        self._send_json(400, {'error': 'Thiếu dữ liệu'})
                        return
                    owner_id, _ = app.db.get_resource(name)
                    if owner_id is None:
                        self._send_json(404, {'error': 'Không tìm thấy'})
                        return
                    if owner_id != uid:
                        self._send_json(403, {'error': 'Forbidden'})
                        return
                    gid = app.db.get_user_id(grantee_name)
                    if not gid:
                        self._send_json(404, {'error': 'Không tìm thấy người dùng'})
                        return
                    ok = app.db.revoke_permission(owner_id, name, gid)
                    if not ok:
                        self._send_json(500, {'error': 'Thu hồi quyền thất bại'})
                        return
                    self._send_json(200, {'ok': True})
                    return

                if self.path == '/permissions/mode':
                    uid = self._auth_user()
                    if not uid:
                        self._send_json(401, {'error': 'Unauthorized'})
                        return
                    body = self._read_json()
                    name = body.get('filename', '')
                    mode = body.get('mode', '')
                    if not name or mode not in ('anyone', 'owner_only', 'userlist'):
                        self._send_json(400, {'error': 'Dữ liệu không hợp lệ'})
                        return
                    owner_id, _ = app.db.get_resource(name)
                    if owner_id is None:
                        self._send_json(404, {'error': 'Không tìm thấy'})
                        return
                    if owner_id != uid:
                        self._send_json(403, {'error': 'Forbidden'})
                        return
                    ok = app.db.set_access_mode(owner_id, name, mode)
                    if not ok:
                        self._send_json(500, {'error': 'Thiết lập chế độ thất bại'})
                        return
                    self._send_json(200, {'ok': True})
                    return

                self._send_json(404, {'error': 'Not found'})

            def do_GET(self):
                if self.path.startswith('/resources/download'):
                    uid = self._auth_user()
                    if not uid:
                        self._send_json(401, {'error': 'Unauthorized'})
                        return
                    qs = parse_qs(urlparse(self.path).query)
                    name = (qs.get('filename') or [''])[0]
                    owner_id, data = app.db.get_resource(name)
                    if owner_id is None:
                        self._send_json(404, {'error': 'Không tìm thấy'})
                        return
                    mode = app.db.get_access_mode(name)
                    if owner_id != uid:
                        if mode == 'owner_only':
                            self._send_json(403, {'error': 'Forbidden'})
                            return
                        if mode == 'userlist' and not app.db.has_permission(owner_id, name, uid):
                            self._send_json(403, {'error': 'Forbidden'})
                            return
                        # mode == 'anyone' cho phép
                    b64 = base64.b64encode(data).decode('utf-8')
                    self._send_json(200, {'filename': name, 'data_b64': b64})
                    return
                self._send_json(404, {'error': 'Not found'})

        return Handler


def start_http_server(host: str, port: int, db, secret: str) -> ThreadingHTTPServer:
    app = ServerApp(db, secret)
    server = ThreadingHTTPServer((host, port), app.make_handler())
    return server

