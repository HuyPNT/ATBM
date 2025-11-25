import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os


class ManageTab:
    """Lớp quản lý giao diện tab quản lý file"""
    
    def __init__(self, parent_frame, file_utils):
        self.frame = parent_frame
        self.file_utils = file_utils
        self.files_data = []
        
        self.setup_ui()
    
    def setup_ui(self):
        """Thiết lập giao diện"""
        # Frame tìm kiếm
        search_frame = tk.LabelFrame(self.frame, text="Tìm kiếm tập tin", 
                                   font=("Arial", 11, "bold"), padx=15, pady=10, bg="#f9f9f9")
        search_frame.pack(fill=tk.X, pady=(10, 5), padx=20)
        
        tk.Label(search_frame, text="Tập tin:", bg="#f9f9f9").pack(anchor="w")
        
        path_frame = tk.Frame(search_frame, bg="#f9f9f9")
        path_frame.pack(fill=tk.X, pady=(5, 8))
        
        self.search_path_entry = tk.Entry(path_frame, font=("Arial", 10), width=50)
        self.search_path_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        browse_btn = tk.Button(
            path_frame,
            text="CHỌN TẬP TIN",
            command=self.select_files,
            bg="#95a5a6",
            fg="white",
            font=("Arial", 10, "bold"),
            cursor="hand2"
        )
        browse_btn.pack(side=tk.LEFT)

        tk.Label(search_frame, text="Thư mục:", bg="#f9f9f9").pack(anchor="w")
        dir_frame = tk.Frame(search_frame, bg="#f9f9f9")
        dir_frame.pack(fill=tk.X, pady=(5, 8))
        self.directory_entry = tk.Entry(dir_frame, font=("Arial", 10), width=50)
        self.directory_entry.pack(side=tk.LEFT, padx=(5, 10))
        tk.Button(dir_frame, text="CHỌN THƯ MỤC", command=self.browse_directory, bg="#95a5a6", fg="white", font=("Arial", 10, "bold"), cursor="hand2").pack(side=tk.LEFT)
        
        
        search_btn = tk.Button(
            search_frame,
            text="TÌM KIẾM",
            command=self.search_files,
            bg="#3498db",
            fg="white",
            font=("Arial", 11, "bold"),
            width=15,
            cursor="hand2"
        )
        search_btn.pack(anchor="w")

        
        
        # Frame danh sách file
        list_frame = tk.LabelFrame(self.frame, text="Danh sách tập tin", 
                                 font=("Arial", 11, "bold"), padx=15, pady=8, bg="#f9f9f9")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=20)
        
        # Treeview
        columns = ("name", "type", "size", "path")
        self.file_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)
        
        self.file_tree.heading("name", text="Tên tập tin")
        self.file_tree.heading("type", text="Loại")
        self.file_tree.heading("size", text="Kích thước")
        self.file_tree.heading("path", text="Đường dẫn")
        
        self.file_tree.column("name", width=200)
        self.file_tree.column("type", width=100)
        self.file_tree.column("size", width=100)
        self.file_tree.column("path", width=300)
        
        # Scrollbar
        tree_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Frame thống kê
        stats_frame = tk.Frame(self.frame, bg="#f9f9f9")
        stats_frame.pack(fill=tk.X, padx=20, pady=(5, 10))
        
        self.stats_label = tk.Label(stats_frame, text="Chưa có dữ liệu", 
                                   bg="#f9f9f9", fg="#7f8c8d", font=("Arial", 10))
        self.stats_label.pack(anchor="w")
    
    def select_files(self):
        files = filedialog.askopenfilenames(title="Chọn tập tin", filetypes=[("Tất cả file", "*.*")])
        if files:
            self.files_data = []
            self.selected_files = list(files)
            display = "; ".join(self.selected_files[:3]) if len(self.selected_files) > 3 else "; ".join(self.selected_files)
            self.search_path_entry.delete(0, tk.END)
            self.search_path_entry.insert(0, display)
    
    def browse_directory(self):
        d = filedialog.askdirectory(title="Chọn thư mục")
        if d:
            if hasattr(self, 'directory_entry'):
                self.directory_entry.delete(0, tk.END)
                self.directory_entry.insert(0, d)
    
    def search_files(self):
        """Tìm kiếm file đã chọn hoặc quét thư mục"""
        use_files = hasattr(self, 'selected_files') and self.selected_files
        directory = self.directory_entry.get().strip() if hasattr(self, 'directory_entry') else ''
        if not use_files and not directory:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn tập tin hoặc thư mục!")
            return
        if not use_files and directory and not os.path.isdir(directory):
            messagebox.showerror("Lỗi", "Thư mục không hợp lệ")
            return
        
        # Xóa dữ liệu cũ
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        files_info = []
        if use_files:
            for p in self.selected_files:
                info = self.file_utils.get_file_info(p)
                if info:
                    files_info.append(info)
        else:
            files_info = self.file_utils.scan_directory(directory)
        
        total_files = 0
        encrypted_files = 0
        total_size = 0
        
        for info in files_info:
            self.file_tree.insert("", tk.END, values=(
                info['name'],
                info['type'],
                info['size_formatted'],
                info['path']
            ))
            
            total_files += 1
            total_size += info['size']
            if info['is_encrypted']:
                encrypted_files += 1
        
        # Cập nhật thống kê
        total_size_str = self.file_utils.format_file_size(total_size)
        stats_text = f"Tổng cộng: {total_files} tập tin | Đã mã hóa: {encrypted_files} tập tin | Tổng dung lượng: {total_size_str}"
        self.stats_label.config(text=stats_text, fg="#2c3e50")
        if hasattr(self, 'search_path_entry'):
            self.search_path_entry.delete(0, tk.END)
        if hasattr(self, 'directory_entry'):
            self.directory_entry.delete(0, tk.END)
        if hasattr(self, 'selected_files'):
            self.selected_files = []

    
