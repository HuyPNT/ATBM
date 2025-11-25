import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from file_utils import FileUtils
import os


class EncryptTab:
    """Lớp quản lý giao diện tab mã hóa"""
    
    def __init__(self, parent_frame, crypto_handler, db_handler=None):
        self.frame = parent_frame
        self.crypto = crypto_handler
        self.db = db_handler
        self.selected_files = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Thiết lập giao diện"""
        # Frame chọn file
        file_frame = tk.LabelFrame(self.frame, text="Chọn tập tin cần mã hóa", 
                                  font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        file_frame.pack(fill=tk.X, pady=(10, 5), padx=20)
        
        select_btn = tk.Button(
            file_frame,
            text="CHỌN TẬP TIN",
            command=self.select_files,
            bg="#3498db",
            fg="white",
            font=("Arial", 11, "bold"),
            width=15,
            cursor="hand2"
        )
        select_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.selected_files_label = tk.Label(file_frame, text="Chưa chọn tập tin nào", 
                                            bg="#f9f9f9", fg="#7f8c8d")
        self.selected_files_label.pack(side=tk.LEFT)
        
        # Frame mật khẩu
        password_frame = tk.LabelFrame(self.frame, text="Mật khẩu mã hóa", 
                                      font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        password_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(password_frame, text="Nhập mật khẩu:", bg="#f9f9f9").pack(anchor="w")
        self.password_entry = tk.Entry(password_frame, show="*", font=("Arial", 11), width=30)
        self.password_entry.pack(anchor="w", pady=(5, 8))
        
        tk.Label(password_frame, text="Xác nhận mật khẩu:", bg="#f9f9f9").pack(anchor="w")
        self.confirm_password_entry = tk.Entry(password_frame, show="*", font=("Arial", 11), width=30)
        self.confirm_password_entry.pack(anchor="w", pady=(5, 0))
        
        # Frame chọn độ dài khóa
        aes_frame = tk.LabelFrame(self.frame, text="Chọn độ dài khóa", 
                                 font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        aes_frame.pack(fill=tk.X, pady=5, padx=20)
        
        self.key_size_var = tk.StringVar(value="256")
        
        radio_container = tk.Frame(aes_frame, bg="#f9f9f9")
        radio_container.pack(anchor="w")
        
        aes128_radio = tk.Radiobutton(radio_container, text="AES-128 (Nhanh)", 
                                     variable=self.key_size_var, value="128", bg="#f9f9f9", font=("Arial", 10))
        aes128_radio.pack(side=tk.LEFT, padx=(0, 20))
        
        aes192_radio = tk.Radiobutton(radio_container, text="AES-192 (Cân bằng)", 
                                     variable=self.key_size_var, value="192", bg="#f9f9f9", font=("Arial", 10))
        aes192_radio.pack(side=tk.LEFT, padx=(0, 20))
        
        aes256_radio = tk.Radiobutton(radio_container, text="AES-256 (An toàn nhất)", 
                                     variable=self.key_size_var, value="256", bg="#f9f9f9", font=("Arial", 10))
        aes256_radio.pack(side=tk.LEFT)
        
        # Nút mã hóa
        encrypt_btn = tk.Button(
            self.frame,
            text="MÃ HÓA TẬP TIN",
            command=self.encrypt_files,
            bg="#27ae60",
            fg="white",
            font=("Arial", 13, "bold"),
            width=20,
            height=2,
            cursor="hand2"
        )
        encrypt_btn.pack(pady=8)
        
        # Kết quả
        result_frame = tk.LabelFrame(self.frame, text="Kết quả", 
                                    font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10), padx=20)
        
        self.result_text = tk.Text(result_frame, height=10, font=("Consolas", 9), 
                                  wrap=tk.WORD, bg="white", state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def select_files(self):
        """Chọn file để mã hóa"""
        files = filedialog.askopenfilenames(
            title="Chọn tập tin cần mã hóa",
            filetypes=[("Tất cả file", "*.*")]
        )
        if files:
            self.selected_files = list(files)
            file_names = [os.path.basename(f) for f in files]
            if len(file_names) > 3:
                display_text = f"{len(file_names)} tập tin: {', '.join(file_names[:3])}..."
            else:
                display_text = ', '.join(file_names)
            self.selected_files_label.config(text=display_text, fg="#2c3e50")
    
    def encrypt_files(self):
        """Mã hóa các file đã chọn"""
        if not self.selected_files:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tập tin cần mã hóa!")
            return
        
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        is_valid, message = FileUtils.validate_password(password)
        if not is_valid:
            messagebox.showwarning("Cảnh báo", message)
            return
        
        if password != confirm_password:
            messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp!")
            return
        
        key_size = int(self.key_size_var.get())
        
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, f"Sử dụng mã hóa AES-{key_size}\n\n")
        
        success_count = 0
        total_files = len(self.selected_files)
        
        for i, file_path in enumerate(self.selected_files):
            self.result_text.insert(tk.END, f"Đang mã hóa ({i+1}/{total_files}): {os.path.basename(file_path)}...")
            self.result_text.see(tk.END)
            self.frame.update()
            
            success, message = self.crypto.encrypt_file(file_path, password, key_size)
            if success:
                self.result_text.insert(tk.END, " ✓ Thành công\n")
                success_count += 1
                # Lưu mật khẩu đã mã hóa vào database (nếu khả dụng)
                try:
                    if self.db:
                        self.db.store_password_for_file(file_path + '.aes', password)
                        self.result_text.insert(tk.END, "  -> Đã lưu mật khẩu (đã mã hóa) vào cơ sở dữ liệu\n")
                except Exception as e:
                    self.result_text.insert(tk.END, f"  -> Lỗi lưu mật khẩu vào DB: {e}\n")
                try:
                    os.remove(file_path)
                    self.result_text.insert(tk.END, f"  -> Đã xóa file gốc: {os.path.basename(file_path)}\n")
                except OSError as e:
                    self.result_text.insert(tk.END, f"  -> Lỗi khi xóa file gốc: {e}\n")
            else:
                self.result_text.insert(tk.END, f" ✗ Thất bại\n  {message}\n")
        
        self.result_text.insert(tk.END, f"\n=== KẾT QUẢ ===\n")
        self.result_text.insert(tk.END, f"Mã hóa thành công: {success_count}/{total_files} tập tin\n")
        self.result_text.insert(tk.END, f"Thuật toán: AES-{key_size} (CBC mode)\n")
        self.result_text.insert(tk.END, f"File mã hóa được lưu với phần mở rộng .aes\n")
        
        self.result_text.config(state=tk.DISABLED)
        
        self.password_entry.delete(0, tk.END)
        self.confirm_password_entry.delete(0, tk.END)
        self.selected_files = []
        self.selected_files_label.config(text="Chưa chọn tập tin nào", fg="#7f8c8d")
