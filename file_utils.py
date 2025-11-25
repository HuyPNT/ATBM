import os


class FileUtils:
    """Lớp tiện ích cho các thao tác file"""
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Định dạng kích thước file thành chuỗi dễ đọc"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    @staticmethod
    def get_file_info(file_path: str) -> dict:
        """Lấy thông tin chi tiết về file"""
        try:
            stat = os.stat(file_path)
            file_name = os.path.basename(file_path)
            file_size = stat.st_size
            
            return {
                'name': file_name,
                'path': file_path,
                'size': file_size,
                'size_formatted': FileUtils.format_file_size(file_size),
                'is_encrypted': file_name.endswith('.aes'),
                'type': 'Mã hóa AES' if file_name.endswith('.aes') else 'Thông thường'
            }
        except Exception as e:
            return None
    
    @staticmethod
    def scan_directory(directory: str) -> list:
        """Quét toàn bộ file trong thư mục và thư mục con"""
        files_info = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    info = FileUtils.get_file_info(file_path)
                    if info:
                        files_info.append(info)
        except Exception as e:
            print(f"Lỗi khi quét thư mục: {e}")
        
        return files_info
    
    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> tuple[bool, str]:
        """Kiểm tra tính hợp lệ của mật khẩu"""
        if not password:
            return False, "Mật khẩu không được để trống"
        
        if len(password) < min_length:
            return False, f"Mật khẩu phải có ít nhất {min_length} ký tự"
        
        return True, "Mật khẩu hợp lệ"