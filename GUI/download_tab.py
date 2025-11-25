import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List
import os
import json
import base64
from urllib import request, parse


class DownloadTab:
    def __init__(self, parent_frame, db_handler=None):
        self.frame = parent_frame
        self.db = db_handler
        self.jwt_token = ''
        self._setup_ui()

    def _setup_ui(self):
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

        download_section = tk.LabelFrame(self.frame, text="Download .AES", font=("Arial", 11, "bold"), padx=15, pady=10, bg="#f9f9f9")
        download_section.pack(fill=tk.X, pady=5, padx=20)
        download_frame = tk.Frame(download_section, bg="#f9f9f9")
        download_frame.pack(fill=tk.X)
        tk.Label(download_frame, text="Tên file (.aes):", bg="#f9f9f9").pack(side=tk.LEFT)
        self.file_name_entry = tk.Entry(download_frame, width=28)
        self.file_name_entry.pack(side=tk.LEFT, padx=(5, 10))
        tk.Button(download_frame, text="CHỌN THƯ MỤC LƯU", command=self.select_save_dir, bg="#95a5a6", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)
        self.save_dir_label = tk.Label(download_frame, text=os.getcwd(), bg="#f9f9f9", fg="#7f8c8d")
        self.save_dir_label.pack(side=tk.LEFT, padx=(10,0))
        tk.Button(download_section, text="TẢI XUỐNG FILE", command=self.download_file, bg="#2ecc71", fg="white", font=("Arial", 11, "bold"), cursor="hand2").pack(anchor="w", pady=(8, 0))

        result_frame = tk.LabelFrame(self.frame, text="Nhật ký tải xuống", font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10), padx=20)
        self.log_text = tk.Text(result_frame, height=12, font=("Consolas", 9), wrap=tk.WORD, bg="white", state=tk.NORMAL)
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _server_base(self) -> str:
        return "http://127.0.0.1:5000"

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

