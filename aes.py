import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidTag
import secrets

class KeyManager:
    def __init__(self, salt_length=16, iterations=100000, key_length=32):
        self.salt_length = salt_length
        self.iterations = iterations
        self.key_length = key_length

    def generate_salt(self):
        return secrets.token_bytes(self.salt_length)

    def derive_key(self, password, salt):
        try:
            password_bytes = password.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=self.iterations,
                backend=default_backend()
            )
            key = kdf.derive(password_bytes)
            return key
        except Exception as e:
            raise Exception(f"Lỗi dẫn xuất khóa: {str(e)}")

class AESCipher:
    def __init__(self, key):
        self.key = key

    def _pad(self, data):
        # PKCS7 padding
        pad_length = 16 - (len(data) % 16)
        if pad_length == 0:
            pad_length = 16
        padding = bytes([pad_length] * pad_length)
        return data + padding

    def _unpad(self, data):
        if len(data) == 0:
            return data
        pad_length = data[-1]
        # Kiểm tra padding hợp lệ
        if pad_length > len(data) or pad_length < 1 or pad_length > 16:
            raise ValueError("Invalid padding")
        # Kiểm tra tất cả bytes padding
        for i in range(1, pad_length + 1):
            if data[-i] != pad_length:
                raise ValueError("Invalid padding")
        return data[:-pad_length]

    def encrypt(self, plaintext):
        try:
            iv = secrets.token_bytes(16)
            # Đảm bảo dữ liệu được padding đúng
            padded_data = self._pad(plaintext)
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), 
                          backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return iv + ciphertext  # IV (16) + Ciphertext
        except Exception as e:
            raise Exception(f"Lỗi mã hóa: {str(e)}")

    def decrypt(self, encrypted_data):
        try:
            if len(encrypted_data) < 16:
                raise ValueError("Dữ liệu mã hóa quá ngắn")
                
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), 
                          backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return self._unpad(padded_plaintext)
        except (ValueError, InvalidKey) as e:
            raise InvalidKey("Sai mật khẩu hoặc file đã bị hỏng")
        except Exception as e:
            raise Exception(f"Lỗi giải mã: {str(e)}")

class FileProcessor:
    def __init__(self):
        self.key_manager = KeyManager()

    def encrypt_file(self, input_path, output_path, password, progress_callback=None):
        try:
            if not os.path.exists(input_path):
                raise FileNotFoundError("File nguồn không tồn tại")

            # Tạo salt và khóa
            salt = self.key_manager.generate_salt()
            key = self.key_manager.derive_key(password, salt)
            cipher = AESCipher(key)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Ghi salt vào đầu file
                fout.write(salt)
                
                # Đọc và mã hóa toàn bộ file
                file_data = fin.read()
                encrypted_data = cipher.encrypt(file_data)
                fout.write(encrypted_data)
                
                if progress_callback:
                    progress_callback(100)

            return True
        except Exception as e:
            raise e

    def decrypt_file(self, input_path, output_path, password, progress_callback=None):
        try:
            if not os.path.exists(input_path):
                raise FileNotFoundError("File mã hóa không tồn tại")

            file_size = os.path.getsize(input_path)
            if file_size < 32:  # Salt (16) + IV (16) + tối thiểu 1 block
                raise ValueError("File mã hóa không hợp lệ hoặc quá nhỏ")

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Đọc salt (16 byte đầu)
                salt = fin.read(16)
                if len(salt) != 16:
                    raise ValueError("File mã hóa bị hỏng: không đọc được salt")
                
                # Đọc toàn bộ dữ liệu mã hóa còn lại
                encrypted_data = fin.read()
                
                key = self.key_manager.derive_key(password, salt)
                cipher = AESCipher(key)
                
                # Giải mã toàn bộ
                decrypted_data = cipher.decrypt(encrypted_data)
                fout.write(decrypted_data)

                if progress_callback:
                    progress_callback(100)

            return True
        except Exception as e:
            raise e

# PHẦN GUI GIỮ NGUYÊN
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ứng Dụng Mã Hóa File AES-256 - FIXED")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        self.file_processor = FileProcessor()
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_label = ttk.Label(main_frame, text="ỨNG DỤNG MÃ HÓA FILE AES-256", 
                               font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        file_frame = ttk.LabelFrame(main_frame, text="Lựa Chọn File", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(file_frame, text="File nguồn:").grid(row=0, column=0, sticky=tk.W)
        self.input_entry = ttk.Entry(file_frame, width=50)
        self.input_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Button(file_frame, text="Duyệt...", 
                  command=self.browse_input_file).grid(row=1, column=1)
        
        ttk.Label(file_frame, text="Thư mục đích:").grid(row=2, column=0, sticky=tk.W, pady=(10, 0))
        self.output_entry = ttk.Entry(file_frame, width=50)
        self.output_entry.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        ttk.Button(file_frame, text="Duyệt...", 
                  command=self.browse_output_dir).grid(row=3, column=1, pady=(5, 0))
        
        pass_frame = ttk.LabelFrame(main_frame, text="Mật Khẩu", padding="10")
        pass_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(pass_frame, text="Nhập mật khẩu:").grid(row=0, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(pass_frame, show="*", width=50)
        self.password_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.show_pass_var = tk.BooleanVar()
        ttk.Checkbutton(pass_frame, text="Hiện mật khẩu", 
                       variable=self.show_pass_var,
                       command=self.toggle_password_visibility).grid(row=1, column=1)
        
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        self.encrypt_btn = ttk.Button(control_frame, text="Mã Hóa File", 
                                     command=self.start_encryption)
        self.encrypt_btn.grid(row=0, column=0, padx=(0, 10))
        
        self.decrypt_btn = ttk.Button(control_frame, text="Giải Mã File", 
                                     command=self.start_decryption)
        self.decrypt_btn.grid(row=0, column=1, padx=(0, 10))
        
        self.clear_btn = ttk.Button(control_frame, text="Xóa", 
                                   command=self.clear_all)
        self.clear_btn.grid(row=0, column=2)
        
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, 
                                       length=580, mode='determinate')
        self.progress.grid(row=4, column=0, columnspan=3, pady=(0, 10))
        
        log_frame = ttk.LabelFrame(main_frame, text="Nhật Ký Hoạt Động", padding="10")
        log_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=70)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Sẵn sàng", foreground="green")
        self.status_label.grid(row=6, column=0, columnspan=3, pady=(5, 0))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        file_frame.columnconfigure(0, weight=1)
        pass_frame.columnconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Chọn file để mã hóa/giải mã",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, filename)
            file_size = os.path.getsize(filename)
            self.status_label.config(text=f"Đã chọn: {os.path.basename(filename)} ({file_size} bytes)")
            
    def browse_output_dir(self):
        directory = filedialog.askdirectory(title="Chọn thư mục đích")
        if directory:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, directory)
            
    def toggle_password_visibility(self):
        if self.show_pass_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            
    def log_message(self, message, level="INFO"):
        self.log_text.insert(tk.END, f"{message}\n")
        if level == "ERROR":
            self.log_text.tag_add("error", "end-2l", "end-1l")
            self.log_text.tag_config("error", foreground="red")
            self.status_label.config(text="Lỗi!", foreground="red")
        elif level == "SUCCESS":
            self.log_text.tag_add("success", "end-2l", "end-1l")
            self.log_text.tag_config("success", foreground="green")
            self.status_label.config(text="Thành công!", foreground="green")
        else:
            self.status_label.config(text=message, foreground="blue")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_progress(self, value):
        self.progress['value'] = value
        self.root.update_idletasks()
        
    def disable_controls(self):
        self.encrypt_btn.config(state='disabled')
        self.decrypt_btn.config(state='disabled')
        self.clear_btn.config(state='disabled')
        
    def enable_controls(self):
        self.encrypt_btn.config(state='normal')
        self.decrypt_btn.config(state='normal')
        self.clear_btn.config(state='normal')
        
    def validate_inputs(self):
        if not self.input_entry.get():
            messagebox.showerror("Lỗi", "Vui lòng chọn file nguồn!")
            return False
        if not self.output_entry.get():
            messagebox.showerror("Lỗi", "Vui lòng chọn thư mục đích!")
            return False
        if not self.password_entry.get():
            messagebox.showerror("Lỗi", "Vui lòng nhập mật khẩu!")
            return False
        return True
        
    def start_encryption(self):
        if not self.validate_inputs():
            return
        thread = threading.Thread(target=self.encrypt_file_thread)
        thread.daemon = True
        thread.start()
        
    def start_decryption(self):
        if not self.validate_inputs():
            return
        thread = threading.Thread(target=self.decrypt_file_thread)
        thread.daemon = True
        thread.start()
        
    def encrypt_file_thread(self):
        try:
            self.disable_controls()
            self.progress['value'] = 0
            self.log_message("Bắt đầu mã hóa file...")
            
            input_path = self.input_entry.get()
            output_dir = self.output_entry.get()
            password = self.password_entry.get()
            
            filename = os.path.basename(input_path)
            output_path = os.path.join(output_dir, filename + ".enc")
            
            def progress_callback(value):
                self.update_progress(value)
                
            success = self.file_processor.encrypt_file(
                input_path, output_path, password, progress_callback
            )
            
            if success:
                self.log_message(f"✅ Mã hóa thành công! File: {output_path}", "SUCCESS")
                messagebox.showinfo("Thành công", "Mã hóa file hoàn tất!")
            else:
                self.log_message("❌ Mã hóa thất bại!", "ERROR")
                
        except Exception as e:
            self.log_message(f"❌ Lỗi khi mã hóa: {str(e)}", "ERROR")
            messagebox.showerror("Lỗi", f"Không thể mã hóa file: {str(e)}")
        finally:
            self.enable_controls()
            self.update_progress(0)
            
    def decrypt_file_thread(self):
        try:
            self.disable_controls()
            self.progress['value'] = 0
            self.log_message("Bắt đầu giải mã file...")
            
            input_path = self.input_entry.get()
            output_dir = self.output_entry.get()
            password = self.password_entry.get()
            
            filename = os.path.basename(input_path)
            if filename.endswith('.enc'):
                original_name = filename[:-4]
            else:
                original_name = filename + ".decrypted"
                
            output_path = os.path.join(output_dir, original_name)
            
            def progress_callback(value):
                self.update_progress(value)
                
            success = self.file_processor.decrypt_file(
                input_path, output_path, password, progress_callback
            )
            
            if success:
                self.log_message(f"✅ Giải mã thành công! File: {output_path}", "SUCCESS")
                messagebox.showinfo("Thành công", "Giải mã file hoàn tất!")
            else:
                self.log_message("❌ Giải mã thất bại!", "ERROR")
                
        except InvalidKey as e:
            self.log_message(f"❌ {str(e)}", "ERROR")
            messagebox.showerror("Lỗi", str(e))
        except Exception as e:
            self.log_message(f"❌ Lỗi khi giải mã: {str(e)}", "ERROR")
            messagebox.showerror("Lỗi", f"Không thể giải mã file: {str(e)}")
        finally:
            self.enable_controls()
            self.update_progress(0)
            
    def clear_all(self):
        self.input_entry.delete(0, tk.END)
        self.output_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.log_text.delete(1.0, tk.END)
        self.progress['value'] = 0
        self.show_pass_var.set(False)
        self.toggle_password_visibility()
        self.status_label.config(text="Sẵn sàng", foreground="green")

def main():
    try:
        root = tk.Tk()
        app = EncryptionApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Lỗi khởi chạy ứng dụng: {e}")

if __name__ == "__main__":
    main()