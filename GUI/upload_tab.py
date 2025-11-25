import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List
import os

from file_utils import FileUtils
import threading
import json
import base64
from urllib import request, parse
from http_server import start_http_server


class ShareTab:
    """Tab chia sẻ/trao đổi thông tin file giữa hai client"""

    def __init__(self, parent_frame, db_handler=None):
        self.frame = parent_frame
        self.selected_files: List[str] = []
        self.db = db_handler
        self.http_server = None
        self.server_thread = None
        self.jwt_token = ''
        self.default_host = "127.0.0.1"
        self.default_port = 5000

        self._setup_ui()

    def _setup_ui(self):
        # Khối máy chủ
        server_frame = tk.LabelFrame(self.frame, text="Máy chủ nhận thông tin", font=("Arial", 11, "bold"), padx=15, pady=10, bg="#f9f9f9")
        server_frame.pack(fill=tk.X, pady=(10, 5), padx=20)
        server_frame.pack_forget()

        host_port_container = tk.Frame(server_frame, bg="#f9f9f9")
        host_port_container.pack(fill=tk.X)

        tk.Label(host_port_container, text="Host:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.host_entry = tk.Entry(host_port_container, width=18)
        self.host_entry.insert(0, "0.0.0.0")
        self.host_entry.pack(side=tk.LEFT, padx=(5, 15))

        tk.Label(host_port_container, text="Port:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(host_port_container, width=8)
        self.port_entry.insert(0, "5000")
        self.port_entry.pack(side=tk.LEFT, padx=(5, 10))

        secret_container = tk.Frame(server_frame, bg="#f9f9f9")
        secret_container.pack(fill=tk.X, pady=(8,0))
        tk.Label(secret_container, text="JWT Secret:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.server_secret_entry = tk.Entry(secret_container, width=18)
        self.server_secret_entry.pack(side=tk.LEFT, padx=(5, 10))

        host_port_container.pack_forget()

        # Nút khởi động/dừng máy chủ trên cùng một hàng
        button_row = tk.Frame(server_frame, bg="#f9f9f9")
        button_row.pack(fill=tk.X, pady=(8, 0))
        secret_container.pack_forget()
        button_row.pack_forget()
        self.server_btn = tk.Button(button_row, text="KHỞI ĐỘNG MÁY CHỦ", command=self.start_server, bg="#27ae60", fg="white", font=("Arial", 10, "bold"), cursor="hand2")
        self.server_btn.pack(side=tk.LEFT)
        self.stop_btn = tk.Button(button_row, text="DỪNG MÁY CHỦ", command=self.stop_server, bg="#e74c3c", fg="white", font=("Arial", 10, "bold"), cursor="hand2")
        self.stop_btn.pack(side=tk.LEFT, padx=(10,0))

        auth_section = tk.LabelFrame(self.frame, text="Tài khoản", font=("Arial", 11, "bold"), padx=15, pady=10, bg="#f9f9f9")
        auth_section.pack(fill=tk.X, pady=5, padx=20)
        auth_frame = tk.Frame(auth_section, bg="#f9f9f9")
        auth_frame.pack(fill=tk.X)
        tk.Label(auth_frame, text="Username:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.username_entry = tk.Entry(auth_frame, width=15)
        self.username_entry.pack(side=tk.LEFT, padx=(5, 10))
        tk.Label(auth_frame, text="Password:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.password_entry = tk.Entry(auth_frame, show='*', width=15)
        self.password_entry.pack(side=tk.LEFT, padx=(5, 10))
        tk.Button(auth_frame, text="REGISTER", command=self.register_user, bg="#8e44ad", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)
        tk.Button(auth_frame, text="LOGIN", command=self.login_user, bg="#2980b9", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=(10,0))
        upload_section = tk.LabelFrame(self.frame, text="Upload .AES", font=("Arial", 11, "bold"), padx=15, pady=10, bg="#f9f9f9")
        upload_section.pack(fill=tk.X, pady=5, padx=20)
        file_select_frame = tk.Frame(upload_section, bg="#f9f9f9")
        file_select_frame.pack(fill=tk.X)
        tk.Button(file_select_frame, text="CHỌN FILE", command=self.select_files, bg="#3498db", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)
        self.selected_files_label = tk.Label(file_select_frame, text="Chưa chọn tập tin nào", bg="#f9f9f9", fg="#7f8c8d")
        self.selected_files_label.pack(side=tk.LEFT, padx=(10, 0))
        tk.Button(file_select_frame, text="TẢI LÊN FILE", command=self.upload_files, bg="#27ae60", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=(10,0))

        # Loại bỏ phần Download trong tab Tải lên
        # (đã tách sang tab "Tải xuống Tập tin")

        perm_section = tk.LabelFrame(self.frame, text="Chia sẻ quyền tải", font=("Arial", 11, "bold"), padx=15, pady=10, bg="#f9f9f9")
        perm_section.pack(fill=tk.X, pady=5, padx=20)
        perm_frame = tk.Frame(perm_section, bg="#f9f9f9")
        perm_frame.pack(fill=tk.X)
        tk.Label(perm_frame, text="Tên file (.aes):", bg="#f9f9f9").pack(side=tk.LEFT)
        self.perm_file_entry = tk.Entry(perm_frame, width=24)
        self.perm_file_entry.pack(side=tk.LEFT, padx=(5, 10))
        tk.Button(perm_frame, text="CHỌN FILE", command=self.select_perm_file, bg="#3498db", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)
        mode_row = tk.Frame(perm_section, bg="#f9f9f9")
        mode_row.pack(fill=tk.X, pady=(6,0))
        tk.Label(mode_row, text="Chế độ truy cập:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value='owner_only')
        ttk.Radiobutton(mode_row, text="Chỉ mình tôi", value='owner_only', variable=self.mode_var, command=self._on_mode_change).pack(side=tk.LEFT, padx=(8,8))
        ttk.Radiobutton(mode_row, text="Username được chọn", value='userlist', variable=self.mode_var, command=self._on_mode_change).pack(side=tk.LEFT, padx=(8,8))
        ttk.Radiobutton(mode_row, text="Bất kì ai", value='anyone', variable=self.mode_var, command=self._on_mode_change).pack(side=tk.LEFT, padx=(8,8))
        tk.Button(perm_section, text="LƯU QUYỀN", command=self.save_access_mode, bg="#16a085", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(anchor="w", pady=(8, 0))

        self.perm_user_row = tk.Frame(perm_section, bg="#f9f9f9")
        self.perm_user_row.pack(fill=tk.X)
        tk.Label(self.perm_user_row, text="Username được chọn:", bg="#f9f9f9").pack(side=tk.LEFT)
        self.perm_user_entry = tk.Entry(self.perm_user_row, width=18)
        self.perm_user_entry.pack(side=tk.LEFT, padx=(5, 10))
        tk.Button(self.perm_user_row, text="CẤP QUYỀN", command=self.grant_permission, bg="#f39c12", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)
        tk.Button(self.perm_user_row, text="THU HỒI QUYỀN", command=self.revoke_permission, bg="#c0392b", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT, padx=(10,0))
        self.perm_user_row.pack_forget()

        # Kết quả
        result_frame = tk.LabelFrame(self.frame, text="Nhật ký trao đổi", font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10), padx=20)

        self.log_text = tk.Text(result_frame, height=12, font=("Consolas", 9), wrap=tk.WORD, bg="white", state=tk.NORMAL)
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def start_server(self):
        host = self.default_host
        port = int(self.default_port)

        try:
            secret_text = self.server_secret_entry.get().strip()
            if not secret_text:
                import secrets
                secret_text = secrets.token_hex(32)
                self.server_secret_entry.insert(0, secret_text)
                self.log_text.insert(tk.END, "[SERVER] Tự tạo JWT Secret ngẫu nhiên\n")
            server = start_http_server(host, port, self.db, secret_text)
            self.http_server = server
            def _run():
                server.serve_forever()
            self.server_thread = threading.Thread(target=_run, daemon=True)
            self.server_thread.start()
            self.server_btn.config(text="MÁY CHỦ HTTP ĐANG CHẠY", state=tk.DISABLED)
            self.server_secret_entry.config(state=tk.DISABLED)
            self.log_text.insert(tk.END, f"[SERVER] HTTP {host}:{port}\n")
            self.log_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể khởi động máy chủ: {e}")

    def stop_server(self):
        try:
            if self.http_server:
                self.http_server.shutdown()
                self.http_server.server_close()
                self.http_server = None
            if self.server_thread:
                self.server_thread.join(timeout=1)
                self.server_thread = None
            self.server_btn.config(text="KHỞI ĐỘNG MÁY CHỦ", state=tk.NORMAL)
            self.server_secret_entry.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, "[SERVER] Đã dừng máy chủ\n")
            self.log_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể dừng máy chủ: {e}")

    def select_files(self):
        files = filedialog.askopenfilenames(title="Chọn tập tin", filetypes=[("Tất cả file", "*.*")])
        if files:
            self.selected_files = list(files)
            names = [os.path.basename(f) for f in files]
            display = f"{len(names)} tập tin" if len(names) > 3 else ", ".join(names)
            self.selected_files_label.config(text=display, fg="#2c3e50")

    def _server_base(self) -> str:
        return f"http://127.0.0.1:{int(self.default_port)}"

    def _post_json(self, url: str, obj: dict, auth: bool = False) -> tuple[bool, dict]:
        data = json.dumps(obj).encode('utf-8')
        req = request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        if auth and self.jwt_token:
            req.add_header('Authorization', f'Bearer {self.jwt_token}')
        try:
            with request.urlopen(req, timeout=5) as resp:
                body = resp.read()
                return True, json.loads(body.decode('utf-8'))
        except Exception as e:
            return False, {'error': str(e)}

    def _get_json(self, url: str, auth: bool = False) -> tuple[bool, dict]:
        req = request.Request(url, method='GET')
        if auth and self.jwt_token:
            req.add_header('Authorization', f'Bearer {self.jwt_token}')
        try:
            with request.urlopen(req, timeout=5) as resp:
                body = resp.read()
                return True, json.loads(body.decode('utf-8'))
        except Exception as e:
            return False, {'error': str(e)}

    def register_user(self):
        base = self._server_base()
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        ok, res = self._post_json(f"{base}/auth/register", {'username': u, 'password': p})
        if ok and res.get('ok'):
            self.log_text.insert(tk.END, f"[CLIENT] Register ok uid={res.get('uid')}\n")
        else:
            self.log_text.insert(tk.END, f"[CLIENT] Register failed {res.get('error')}\n")
        self.log_text.see(tk.END)

    def login_user(self):
        base = self._server_base()
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        ok, res = self._post_json(f"{base}/auth/login", {'username': u, 'password': p})
        if ok and res.get('token'):
            self.jwt_token = res.get('token')
            self.log_text.insert(tk.END, "[CLIENT] Login ok\n")
        else:
            self.log_text.insert(tk.END, f"[CLIENT] Login failed {res.get('error')}\n")
        self.log_text.see(tk.END)

    def upload_files(self):
        if not self.selected_files:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tập tin .aes!")
            return
        base = self._server_base()
        sent = 0
        for p in self.selected_files:
            try:
                with open(p, 'rb') as f:
                    data = f.read()
                name = os.path.basename(p)
                b64 = base64.b64encode(data).decode('utf-8')
                ok, res = self._post_json(f"{base}/resources/upload", {'filename': name, 'data_b64': b64}, auth=True)
                if ok and res.get('ok'):
                    sent += 1
            except Exception:
                pass
        self.log_text.insert(tk.END, f"[CLIENT] Uploaded {sent}/{len(self.selected_files)}\n")
        self.log_text.see(tk.END)
    
    def select_save_dir(self):
        d = filedialog.askdirectory(title="Chọn thư mục lưu")
        if d:
            self.save_dir_label.config(text=d, fg="#2c3e50")
    
    def download_file(self):
        name = self.file_name_entry.get().strip()
        if not name:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập đúng tên file .aes")
            return
        save_dir = self.save_dir_label.cget("text")
        base = self._server_base()
        ok, res = self._get_json(f"{base}/resources/download?filename={parse.quote(name)}", auth=True)
        if ok and res.get('data_b64'):
            b64 = res.get('data_b64')
            content = base64.b64decode(b64)
            save_path = os.path.join(save_dir, name)
            with open(save_path, 'wb') as f:
                f.write(content)
            self.log_text.insert(tk.END, f"[CLIENT] Đã tải file về: {save_path}\n")
            self.log_text.see(tk.END)
            messagebox.showinfo("Thành công", f"Đã tải file về: {save_path}")
        else:
            messagebox.showerror("Lỗi", res.get('error', 'Lỗi tải xuống'))

    def grant_permission(self):
        base = self._server_base()
        name = self.perm_file_entry.get().strip()
        user = self.perm_user_entry.get().strip()
        if not name or not user:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập tên file và username")
            return
        ok, res = self._post_json(f"{base}/permissions/grant", {'filename': name, 'grantee_username': user}, auth=True)
        if ok and res.get('ok'):
            self.log_text.insert(tk.END, f"[CLIENT] Đã cấp quyền tải {user} cho {name}\n")
        else:
            self.log_text.insert(tk.END, f"[CLIENT] Cấp quyền thất bại {res.get('error')}\n")
        self.log_text.see(tk.END)

    def revoke_permission(self):
        base = self._server_base()
        name = self.perm_file_entry.get().strip()
        user = self.perm_user_entry.get().strip()
        if not name or not user:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập tên file và username")
            return
        ok, res = self._post_json(f"{base}/permissions/revoke", {'filename': name, 'grantee_username': user}, auth=True)
        if ok and res.get('ok'):
            self.log_text.insert(tk.END, f"[CLIENT] Đã thu hồi quyền tải {user} cho {name}\n")
        else:
            self.log_text.insert(tk.END, f"[CLIENT] Thu hồi quyền thất bại {res.get('error')}\n")
        self.log_text.see(tk.END)

    def select_perm_file(self):
        files = filedialog.askopenfilenames(title="Chọn tập tin .aes", filetypes=[("File AES", "*.aes"), ("Tất cả file", "*.*")])
        if files:
            name = os.path.basename(files[0])
            self.perm_file_entry.delete(0, tk.END)
            self.perm_file_entry.insert(0, name)

    def save_access_mode(self):
        base = self._server_base()
        name = self.perm_file_entry.get().strip()
        mode = self.mode_var.get()
        if not name:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập tên file")
            return
        ok, res = self._post_json(f"{base}/permissions/mode", {'filename': name, 'mode': mode}, auth=True)
        if ok and res.get('ok'):
            self.log_text.insert(tk.END, f"[CLIENT] Đã lưu chế độ truy cập: {mode} cho {name}\n")
        else:
            self.log_text.insert(tk.END, f"[CLIENT] Lưu chế độ thất bại {res.get('error')}\n")
        self.log_text.see(tk.END)

    def _on_mode_change(self):
        mode = self.mode_var.get()
        if mode == 'userlist':
            self.perm_user_row.pack(fill=tk.X)
        else:
            self.perm_user_row.pack_forget()

    
