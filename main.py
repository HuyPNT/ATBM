import tkinter as tk
from tkinter import messagebox
import sys
import os

# Thêm thư mục hiện tại vào path để import được các module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    """Hàm chính khởi chạy ứng dụng"""
    
    # Kiểm tra thư viện cryptography
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Thiếu thư viện",
                           "Vui lòng cài đặt thư viện cryptography:\n\n"
                           "pip install cryptography\n\n"
                           "Sau đó chạy lại chương trình.")
        return
    
    # Import các module
    try:
        from aes_crypto import AESCrypto
        from file_utils import FileUtils
        from GUI.main_window import AESFileManagerApp
        
    except ImportError as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Lỗi Import",
                           f"Không thể import module: {str(e)}\n\n"
                           "Đảm bảo cấu trúc thư mục đúng:\n"
                           "- aes_crypto.py\n"
                           "- file_utils.py\n"
                           "- GUI/__init__.py\n"
                           "- GUI/main_window.py\n"
                           "- GUI/encrypt_tab.py\n"
                           "- GUI/decrypt_tab.py\n"
                           "- GUI/manage_tab.py")
        return
    
    # Khởi tạo các handler
    crypto = AESCrypto()
    file_utils = FileUtils()
    # Khởi tạo database
    try:
        from db_manager import DatabaseManager
        db = DatabaseManager()
        db.initialize()
    except Exception:
        db = None

    # Khởi động HTTP server nền tự động
    http_server = None
    try:
        from http_server import start_http_server
        import threading, secrets
        secret = secrets.token_hex(32)
        http_server = start_http_server('127.0.0.1', 5000, db, secret)
        t = threading.Thread(target=http_server.serve_forever, daemon=True)
        t.start()
    except Exception:
        http_server = None

    # Tạo ứng dụng
    root = tk.Tk()
    app = AESFileManagerApp(root, crypto, file_utils, db)
    if http_server:
        def _on_close():
            try:
                http_server.shutdown()
                http_server.server_close()
            except Exception:
                pass
            root.destroy()
        root.protocol('WM_DELETE_WINDOW', _on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
