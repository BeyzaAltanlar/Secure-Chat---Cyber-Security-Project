import os
import tkinter as tk
from tkinter import messagebox
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_salt():
    return os.urandom(16)

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def save_key(filename, key):
    serialized_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as key_file:
        key_file.write(serialized_key)

def load_key(filename):
    with open(filename, 'rb') as key_file:
        serialized_key = key_file.read()
        return serialization.load_pem_private_key(
            serialized_key,
            password=None,
            backend=default_backend()
        )

def perform_authentication(username, password):
    # Kullanıcı adı ve parolaların saklandığı bir dosyayı kontrol et veya oluştur
    if not os.path.exists("user_credentials.txt"):
        open("user_credentials.txt", "w").close()

    # Kullanıcı adı ve parolayı kontrol et
    with open("user_credentials.txt", "r") as file:
        user_credentials = [line.strip().split(":") for line in file]

    for stored_username, stored_password in user_credentials:
        if username == stored_username and password == stored_password:
            return True

    return False

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def register_user(username, password):
    # Tuz oluştur
    salt = generate_salt()

    # Parolayı tuzla ve türet
    key = derive_key(password, salt)

    # Simetrik anahtar oluştur
    symmetric_key = os.urandom(32)

    # Asimetrik anahtar çifti oluştur
    private_key = generate_key()
    public_key = private_key.public_key()

    # Anahtarları güvenli bir şekilde kaydet
    save_key(username + "_key.pem", private_key)
    with open(username + "_symmetric_key.bin", 'wb') as symmetric_key_file:
        symmetric_key_file.write(symmetric_key)
    with open(username + "_public_key.pem", 'wb') as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Tuzu kaydet
    with open(username + "_salt.bin", 'wb') as salt_file:
        salt_file.write(salt)

    # Kullanıcı adı ve parolayı dosyaya ekle
    with open("user_credentials.txt", "a") as credentials_file:
        credentials_file.write(f"{username}:{password}\n")

def authenticate_user(username, password):
    # Tuzu yükle
    with open(username + "_salt.bin", 'rb') as salt_file:
        salt = salt_file.read()

    # Parolayı tuzla ve türet
    key = derive_key(password, salt)

    # Simetrik anahtarı yükle
    with open(username + "_symmetric_key.bin", 'rb') as symmetric_key_file:
        symmetric_key = symmetric_key_file.read()

    # Asimetrik anahtarı yükle
    with open(username + "_public_key.pem", 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    # Kaydedilmiş anahtarı yükle
    private_key = load_key(username + "_key.pem")

    # Kullanıcı bilgilerini getir, gerçek bir kimlik doğrulama işlemi gerçekleştir
    authenticated = perform_authentication(username, password)

    if authenticated:
        print("Kimlik doğrulama başarılı.")

        # Tkinter ile bir sohbet uygulaması oluştur
        class ChatApp:
            def __init__(self, root):
                self.root = root
                self.root.title("Sohbet Uygulaması")

                self.message_listbox = tk.Listbox(root, width=50, height=20)
                self.message_listbox.pack()

                self.message_entry = tk.Entry(root, width=50)
                self.message_entry.pack()

                self.send_button = tk.Button(root, text="Gönder", command=self.send_message)
                self.send_button.pack()

            def send_message(self):
                message = self.message_entry.get()
                encrypted_message = encrypt_message(message, symmetric_key)

                # Mesajı imzala
                signature = sign_message(message.encode(), private_key)

                # Mesajı şifrele ve gönder
                encrypted_symmetric_key = public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                print(f"Gönderilen şifrelenmiş simetrik anahtar: {encrypted_symmetric_key}")
                print(f"Gönderilen şifrelenmiş mesaj: {encrypted_message}")
                print(f"İmza: {signature}\n")

                # Mesajı al ve çöz
                decrypted_symmetric_key = private_key.decrypt(
                    encrypted_symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_message = decrypt_message(encrypted_message, decrypted_symmetric_key)

                # İmza doğrulama
                if verify_signature(decrypted_message, signature, public_key):
                    print("İmza doğrulama başarılı.")
                    print(f"Alınan çözülen simetrik anahtar: {decrypted_symmetric_key}")
                    print(f"Alınan çözülen mesaj: {decrypted_message.decode('utf-8')}\n")
                else:
                    print("İmza doğrulama başarısız.")

                # Sohbet penceresine mesajı ekle
                self.message_listbox.insert(tk.END, f"{username}: {decrypted_message.decode('utf-8')}")

        chat_root = tk.Tk()
        chat_app = ChatApp(chat_root)
        chat_root.mainloop()

    else:
        print("Kimlik doğrulama başarısız.")

# Tkinter ile bir arayüz oluştur
class SecureMessagingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Güvenli Mesajlaşma Uygulaması")

        self.username_label = tk.Label(root, text="Kullanıcı Adı:")
        self.username_label.pack()

        self.username_entry = tk.Entry(root)
        self.username_entry.pack()

        self.password_label = tk.Label(root, text="Parola:")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(root, text="Giriş Yap", command=self.login)
        self.login_button.pack()

        self.register_button = tk.Button(root, text="Kayıt Ol", command=self.register)
        self.register_button.pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        authenticate_user(username, password)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        register_user(username, password)

def main():
    root = tk.Tk()
    app = SecureMessagingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()