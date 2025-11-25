import tkinter as tk
from tkinter import ttk, messagebox
from .encrypt_tab import EncryptTab
from .decrypt_tab import DecryptTab
from .manage_tab import ManageTab
from .upload_tab import ShareTab


class AESFileManagerApp:
    """Lớp chính quản lý ứng dụng"""
    
    def __init__(self, root, crypto_handler, file_utils_handler, db_handler=None):
        self.root = root
        self.root.title("Quản lý Tập tin với Mã hóa AES")
        self.root.geometry("900x700")
        self.root.configure(bg="#f5f5f5")
        
        self.crypto = crypto_handler
        self.file_utils = file_utils_handler
        self.db = db_handler
        
        self.create_widgets()
    
    def create_widgets(self):
        """Tạo giao diện chính"""
        # Frame tiêu đề
        title_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="QUẢN LÝ TẬP TIN VỚI MÃ HÓA AES",
            font=("Arial", 16, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(expand=True)
        
        # Frame chính
        main_frame = tk.Frame(self.root, padx=20, pady=15, bg="#f5f5f5")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tạo các tab
        encrypt_frame = tk.Frame(self.notebook, bg="#f9f9f9")
        decrypt_frame = tk.Frame(self.notebook, bg="#f9f9f9")
        manage_frame = tk.Frame(self.notebook, bg="#f9f9f9")
        share_frame = tk.Frame(self.notebook, bg="#f9f9f9")
        download_frame2 = tk.Frame(self.notebook, bg="#f9f9f9")
        
        self.notebook.add(encrypt_frame, text="Mã hóa Tập tin")
        self.notebook.add(decrypt_frame, text="Giải mã Tập tin")
        self.notebook.add(manage_frame, text="Quản lý Tập tin")
        self.notebook.add(share_frame, text="Tải lên Tập tin")
        self.notebook.add(download_frame2, text="Tải xuống Tập tin")
        
        # Khởi tạo các tab
        self.encrypt_tab = EncryptTab(encrypt_frame, self.crypto, self.db)
        self.decrypt_tab = DecryptTab(decrypt_frame, self.crypto)
        self.manage_tab = ManageTab(manage_frame, self.file_utils)
        from .download_tab import DownloadTab
        self.share_tab = ShareTab(share_frame, self.db)
        self.download_tab2 = DownloadTab(download_frame2, self.db)
