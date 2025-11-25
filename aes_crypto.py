from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import os


class AESCrypto:
    """Lớp xử lý mã hóa và giải mã AES"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key_from_password(self, password: str, salt: bytes, key_size: int = 256) -> bytes:
        """
        Tạo khóa AES từ mật khẩu sử dụng PBKDF2
        
        Args:
            password: Mật khẩu người dùng nhập
            salt: Salt ngẫu nhiên 16 bytes
            key_size: Độ dài khóa (128, 192, hoặc 256 bits)
            
        Returns:
            Khóa AES đã được tạo
        """
        key_length = key_size // 8
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_file(self, file_path: str, password: str, key_size: int = 256) -> tuple[bool, str]:
        """
        Mã hóa một file bằng AES-CBC
        
        Args:
            file_path: Đường dẫn file cần mã hóa
            password: Mật khẩu mã hóa
            key_size: Độ dài khóa (128, 192, hoặc 256)
            
        Returns:
            (success, message): Tuple chứa trạng thái và thông báo
        """
        try:
            if not os.path.exists(file_path):
                return False, f"File không tồn tại: {file_path}"
            
            salt = secrets.token_bytes(16)
            key = self.derive_key_from_password(password, salt, key_size)
            iv = secrets.token_bytes(16)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            with open(file_path, 'rb') as file:
                plaintext = file.read()
            
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            encrypted_file_path = file_path + '.aes'
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(key_size.to_bytes(2, 'big') + salt + iv + ciphertext)
            
            return True, f"Mã hóa thành công: {os.path.basename(encrypted_file_path)}"
            
        except Exception as e:
            return False, f"Lỗi mã hóa: {str(e)}"
    
    def decrypt_file(self, encrypted_file_path: str, password: str) -> tuple[bool, str]:
        """
        Giải mã một file AES
        
        Args:
            encrypted_file_path: Đường dẫn file .aes cần giải mã
            password: Mật khẩu giải mã
            
        Returns:
            (success, message): Tuple chứa trạng thái và thông báo
        """
        try:
            if not os.path.exists(encrypted_file_path):
                return False, f"File không tồn tại: {encrypted_file_path}"
            
            with open(encrypted_file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            if len(encrypted_data) < 35:
                return False, "File không đúng định dạng AES"
            
            key_size = int.from_bytes(encrypted_data[:2], 'big')
            salt = encrypted_data[2:18]
            iv = encrypted_data[18:34]
            ciphertext = encrypted_data[34:]
            
            if key_size not in [128, 192, 256]:
                return False, f"Độ dài khóa không hợp lệ: {key_size}"
            
            key = self.derive_key_from_password(password, salt, key_size)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            original_file_path = encrypted_file_path.replace('.aes', '')
            with open(original_file_path, 'wb') as decrypted_file:
                decrypted_file.write(plaintext)
            
            return True, f"Giải mã thành công: {os.path.basename(original_file_path)}"
            
        except ValueError as e:
            return False, "Mật khẩu không đúng hoặc file bị hỏng"
        except Exception as e:
            return False, f"Lỗi giải mã: {str(e)}"
