import socket
import threading
import json
import base64
import os
import hashlib
from typing import Callable, Optional


class FileInfoServer:

    def __init__(self, db_handler=None):
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._on_receive: Optional[Callable[[dict], None]] = None
        self._db = db_handler
        self._secret_hash: Optional[bytes] = None

    def set_secret(self, secret_text: str) -> None:
        if secret_text:
            self._secret_hash = hashlib.sha256(secret_text.encode('utf-8')).digest()
        else:
            self._secret_hash = None

    def start(self, host: str, port: int, on_receive: Callable[[dict], None]) -> None:
        if self._running:
            return
        self._on_receive = on_receive
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((host, port))
        self._server_sock.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        assert self._server_sock is not None
        while self._running:
            try:
                self._server_sock.settimeout(1.0)
                try:
                    conn, addr = self._server_sock.accept()
                except socket.timeout:
                    continue
                with conn:
                    data = b""
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    try:
                        payload = json.loads(data.decode('utf-8'))
                        if isinstance(payload, dict) and payload.get('cmd') == 'get_file':
                            name = payload.get('name') or ''
                            provided_secret = payload.get('secret') or ''
                            resp = {"ok": False}
                            try:
                                if self._secret_hash is not None:
                                    ph = hashlib.sha256(provided_secret.encode('utf-8')).digest()
                                    if ph != self._secret_hash:
                                        resp = {"ok": False, "error": "Secret không hợp lệ"}
                                        conn.sendall(json.dumps(resp).encode('utf-8'))
                                        continue
                                path = None
                                if self._db and name:
                                    path = self._db.find_file_by_name(name)
                                if path:
                                    if os.path.exists(path):
                                        with open(path, 'rb') as f:
                                            content = f.read()
                                        resp = {
                                            "ok": True,
                                            "name": os.path.basename(path),
                                            "size": len(content),
                                            "data_b64": base64.b64encode(content).decode('utf-8')
                                        }
                                    else:
                                        resp = {"ok": False, "error": "File không tồn tại"}
                                else:
                                    resp = {"ok": False, "error": "Không tìm thấy theo tên"}
                            except Exception as e:
                                resp = {"ok": False, "error": str(e)}
                            try:
                                conn.sendall(json.dumps(resp).encode('utf-8'))
                            except Exception:
                                pass
                        else:
                            if self._on_receive:
                                self._on_receive(payload)
                            try:
                                conn.sendall(json.dumps({"ok": True}).encode('utf-8'))
                            except Exception:
                                pass
                    except Exception:
                        try:
                            conn.sendall(json.dumps({"ok": False, "error": "payload lỗi"}).encode('utf-8'))
                        except Exception:
                            pass
            except Exception:
                continue

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None


class FileInfoClient:
    """Client TCP để gửi thông tin file dưới dạng JSON"""

    @staticmethod
    def send(server_ip: str, port: int, payload: dict, timeout: float = 5.0) -> bool:
        try:
            data = json.dumps(payload).encode('utf-8')
            with socket.create_connection((server_ip, port), timeout=timeout) as sock:
                sock.sendall(data)
            return True
        except Exception:
            return False


class FileDownloadClient:

    @staticmethod
    def download(server_ip: str, port: int, file_name: str, save_dir: str, secret: str = "", timeout: float = 8.0) -> tuple[bool, str]:
        try:
            req = json.dumps({"cmd": "get_file", "name": file_name, "secret": secret}).encode('utf-8')
            with socket.create_connection((server_ip, port), timeout=timeout) as sock:
                sock.sendall(req)
                sock.shutdown(socket.SHUT_WR)
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            resp = json.loads(data.decode('utf-8'))
            if not resp.get('ok'):
                return False, resp.get('error', 'Yêu cầu thất bại')
            name = resp.get('name') or file_name
            b64 = resp.get('data_b64')
            content = base64.b64decode(b64)
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, name)
            with open(save_path, 'wb') as f:
                f.write(content)
            return True, save_path
        except Exception as e:
            return False, str(e)
