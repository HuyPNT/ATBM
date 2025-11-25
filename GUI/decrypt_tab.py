import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os


class DecryptTab:
    """Lớp quản lý giao diện tab giải mã"""
    
    def __init__(self, parent_frame, crypto_handler):
        self.frame = parent_frame
        self.crypto = crypto_handler
        self.selected_files = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Thiết lập giao diện"""
        # Frame chọn file
        file_frame = tk.LabelFrame(self.frame, text="Chọn tập tin cần giải mã", 
                                  font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        file_frame.pack(fill=tk.X, pady=(10, 5), padx=20)
        
        select_btn = tk.Button(
            file_frame,
            text="CHỌN TẬP TIN .AES",
            command=self.select_files,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 11, "bold"),
            width=16,
            cursor="hand2"
        )
        select_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.selected_files_label = tk.Label(file_frame, text="Chưa chọn tập tin nào", 
                                            bg="#f9f9f9", fg="#7f8c8d")
        self.selected_files_label.pack(side=tk.LEFT)
        
        # Frame mật khẩu
        password_frame = tk.LabelFrame(self.frame, text="Mật khẩu giải mã", 
                                      font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        password_frame.pack(fill=tk.X, pady=5, padx=20)
        
        tk.Label(password_frame, text="Nhập mật khẩu:", bg="#f9f9f9").pack(anchor="w")
        self.password_entry = tk.Entry(password_frame, show="*", font=("Arial", 11), width=30)
        self.password_entry.pack(anchor="w", pady=(5, 0))
        
        # Nút giải mã
        decrypt_btn = tk.Button(
            self.frame,
            text="GIẢI MÃ TẬP TIN",
            command=self.decrypt_files,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 13, "bold"),
            width=20,
            height=2,
            cursor="hand2"
        )
        decrypt_btn.pack(pady=8)
        
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
        """Chọn file để giải mã"""
        files = filedialog.askopenfilenames(
            title="Chọn tập tin cần giải mã",
            filetypes=[("File AES", "*.aes"), ("Tất cả file", "*.*")]
        )
        if files:
            self.selected_files = list(files)
            file_names = [os.path.basename(f) for f in files]
            if len(file_names) > 3:
                display_text = f"{len(file_names)} tập tin: {', '.join(file_names[:3])}..."
            else:
                display_text = ', '.join(file_names)
            self.selected_files_label.config(text=display_text, fg="#2c3e50")
    
    def decrypt_files(self):
        """Giải mã các file đã chọn"""
        if not self.selected_files:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tập tin cần giải mã!")
            return
        
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập mật khẩu!")
            return
        
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        
        success_count = 0
        total_files = len(self.selected_files)
        
        for i, file_path in enumerate(self.selected_files):
            self.result_text.insert(tk.END, f"Đang giải mã ({i+1}/{total_files}): {os.path.basename(file_path)}...")
            self.result_text.see(tk.END)
            self.frame.update()
            
            success, message = self.crypto.decrypt_file(file_path, password)
            if success:
                self.result_text.insert(tk.END, " ✓ Thành công\n")
                success_count += 1
                try:
                    os.remove(file_path)
                    self.result_text.insert(tk.END, f"  -> Đã xóa file gốc: {os.path.basename(file_path)}\n")
                except OSError as e:
                    self.result_text.insert(tk.END, f"  -> Lỗi khi xóa file gốc: {e}\n")
            else:
                self.result_text.insert(tk.END, f" ✗ Thất bại\n  {message}\n")
        
        self.result_text.insert(tk.END, f"\n=== KẾT QUẢ ===\n")
        self.result_text.insert(tk.END, f"Giải mã thành công: {success_count}/{total_files} tập tin\n")
        
        self.result_text.config(state=tk.DISABLED)
        
        self.password_entry.delete(0, tk.END)
        self.selected_files = []
        self.selected_files_label.config(text="Chưa chọn tập tin nào", fg="#7f8c8d")
