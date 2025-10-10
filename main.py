import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLineEdit, QLabel, QPushButton
from PyQt5.QtGui import QIcon
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(dotenv_path=env_path)

env_key = os.getenv("FERNET_KEY")
if not env_key:
    raise EnvironmentError(f"FERNET_KEY not found in {env_path}")
key = env_key.encode()

data = r"C:\Coding\Python\AccountSystem\EncryptedData"

class MyWindow(QWidget):
    closed_eye_icon = r"C:\Coding\Python\AccountSystem\Images\ClosedEye.png"
    open_eye_icon = r"C:\Coding\Python\AccountSystem\Images\OpenEye.png"
    revealed = False

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Database Testing")
        self.setGeometry(660, 340, 600, 400)

        self.label_0 = QLabel(self)
        self.label_0.setText("Enter your username and password")
        self.label_0.move(225, 20)
        self.label_0.resize(250, 40)

        self.label_1 = QLabel(self)
        self.label_1.setText("Username")
        self.label_1.move(280, 60)
        self.label_1.resize(250, 40)

        self.username = QLineEdit(self)
        self.username.move(180, 100)
        self.username.resize(250, 40)

        self.label_2 = QLabel(self)
        self.label_2.setText("Password")
        self.label_2.move(280, 160)
        self.label_2.resize(250, 40)

        self.password = QLineEdit(self)
        self.password.move(180, 200)
        self.password.resize(250, 40)
        self.password.setEchoMode(QLineEdit.Password)

        self.reveal = QPushButton(self)
        self.reveal.clicked.connect(self.toggle_password_visibility)
        self.update_eye_icon()
        self.reveal.move(440, 200)
        self.reveal.resize(40, 40)

        self.login = QPushButton(self)
        self.login.clicked.connect(self.login_to_account)
        self.login.setText("Log in")
        self.login.move(205, 280)
        self.login.resize(100, 40)

        self.register = QPushButton(self)
        self.register.clicked.connect(self.register_account)
        self.register.setText("Register")
        self.register.move(305, 280)
        self.register.resize(100, 40)

    def toggle_password_visibility(self):
        self.revealed = not self.revealed
        self.update_eye_icon()
        if self.revealed:
            self.password.setEchoMode(QLineEdit.Normal)
        else:
            self.password.setEchoMode(QLineEdit.Password)

    def update_eye_icon(self):
        if self.revealed:
            icon = QIcon(self.open_eye_icon)
        else:
            icon = QIcon(self.closed_eye_icon)
        self.reveal.setIcon(icon)

    def login_to_account(self):
        username_input = self.username.text()
        password_input = self.password.text()
        cipher_suite = Fernet(key)
        found = False

        if os.path.exists(data):
            with open(data, "r") as file:
                for line in file:
                    encrypted_data = line.strip().encode()
                    try:
                        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                        stored_username, stored_password = decrypted_data.split(":")
                        if stored_username == username_input and stored_password == password_input:
                            found = True
                            break
                    except:
                        continue

        if found:
            print("Login successful")
            self.username.setText("")
            self.password.setText("")
            self.label_0.setText("Login successful")
            self.label_0.move(265, 20)
        else:
            print("Invalid username or password")
            self.password.setText("")
            self.label_0.setText("Invalid username or password")
            self.label_0.move(235, 20)

    def register_account(self):
        username_input = self.username.text()
        password_input = self.password.text()
        cipher_suite = Fernet(key)

        encoded_data = cipher_suite.encrypt(f"{username_input}:{password_input}".encode())
        found = False

        if os.path.exists(data):
            with open(data, "r") as file:
                for line in file:
                    encrypted_data = line.strip().encode()
                    try:
                        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                        stored_username, stored_password = decrypted_data.split(":")
                        if stored_username == username_input:
                            found = True
                            break
                    except:
                        continue

        if not found:
            with open(data, "a") as file:
                file.write(f"{encoded_data.decode()}\n")
            print("Registration successful")
            self.username.setText("")
            self.password.setText("")
            self.label_0.setText("Registration successful")
            self.label_0.move(250, 20)
        else:
            print("Username already registered")
            self.username.setText("")
            self.password.setText("")
            self.label_0.setText("Username already registered")
            self.label_0.move(235, 20)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())
