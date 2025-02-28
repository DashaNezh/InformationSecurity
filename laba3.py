import sys
import json
import hashlib
import re
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QDialog,
                               QListWidget, QHBoxLayout, QInputDialog, QComboBox, QSpinBox)

USERS_FILE = "users.json"

PASSWORD_POLICIES = {
    "Только цифры": r"^[0-9]+$",
    "Буквы и цифры": r"^[A-Za-z0-9]+$",
    "Все символы": r"^.*$",
    "Только буквы": r"^[A-Za-z]+$",
    "Одна заглавная буква": r"^[A-Z]{1}$",
    "Без простых паролей": None  # Проверка будет по списку
}

SIMPLE_PASSWORDS = {"123456", "password", "qwerty", "abc123", "111111"}


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    # Проверка на наличие файла пользователей
    try:
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        # Если файл не найден, создаем файл с админом и пустым паролем
        users = {"ADMIN": {"password": hash_password(""), "blocked": False, "restrictions": {}}}
        save_users(users)
        return users


def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)


def validate_password(password, restrictions):
    if "min_length" in restrictions and len(password) < restrictions["min_length"]:
        return False, "Пароль слишком короткий"

    if "policy" in restrictions and restrictions["policy"] in PASSWORD_POLICIES:
        policy = PASSWORD_POLICIES[restrictions["policy"]]
        if policy and not re.match(policy, password):
            return False, "Пароль не соответствует требованиям"

    if "policy" in restrictions and restrictions["policy"] == "Без простых паролей" and password in SIMPLE_PASSWORDS:
        return False, "Пароль слишком простой"

    return True, ""


class AdminWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Админ панель")
        self.setGeometry(200, 200, 400, 500)

        layout = QVBoxLayout()

        self.user_list = QListWidget()
        self.load_users()
        layout.addWidget(self.user_list)

        self.block_button = QPushButton("Заблокировать пользователя")
        self.unblock_button = QPushButton("Разблокировать пользователя")
        self.add_user_button = QPushButton("Добавить пользователя")
        self.change_password_button = QPushButton("Сменить пароль")
        self.set_restriction_button = QPushButton("Установить ограничения на пароль")
        self.remove_restriction_button = QPushButton("Снять ограничения на пароль")
        self.logout_button = QPushButton("Выйти в главное меню")

        self.block_button.clicked.connect(self.block_user)
        self.unblock_button.clicked.connect(self.unblock_user)
        self.add_user_button.clicked.connect(self.add_user)
        self.change_password_button.clicked.connect(self.change_password)
        self.set_restriction_button.clicked.connect(self.set_restriction)
        self.remove_restriction_button.clicked.connect(self.remove_restriction)
        self.logout_button.clicked.connect(self.logout)

        layout.addWidget(self.block_button)
        layout.addWidget(self.unblock_button)
        layout.addWidget(self.add_user_button)
        layout.addWidget(self.change_password_button)
        layout.addWidget(self.set_restriction_button)
        layout.addWidget(self.remove_restriction_button)
        layout.addWidget(self.logout_button)

        self.setLayout(layout)

    def load_users(self):
        self.user_list.clear()
        users = load_users()
        for user in users:
            status = "(Заблокирован)" if users[user]["blocked"] else "(Активен)"
            restrictions = "(Ограничения)" if users[user]["restrictions"] else ""
            self.user_list.addItem(f"{user} {status} {restrictions}")

    def block_user(self):
        selected = self.user_list.currentItem()
        if selected:
            username = selected.text().split()[0]
            users = load_users()
            if username != "ADMIN" and username in users:
                users[username]["blocked"] = True
                save_users(users)
                self.load_users()
                QMessageBox.information(self, "Успех", f"Пользователь {username} заблокирован")

    def unblock_user(self):
        selected = self.user_list.currentItem()
        if selected:
            username = selected.text().split()[0]
            users = load_users()
            if username in users:
                users[username]["blocked"] = False
                save_users(users)
                self.load_users()
                QMessageBox.information(self, "Успех", f"Блокировка с {username} снята")

    def add_user(self):
        username, ok = QInputDialog.getText(self, "Добавить пользователя", "Введите имя пользователя:")
        if ok and username:
            users = load_users()
            if username in users:
                QMessageBox.warning(self, "Ошибка", "Такой пользователь уже существует")
            else:
                users[username] = {"password": hash_password(""), "blocked": False, "restrictions": {}}
                save_users(users)
                self.load_users()
                QMessageBox.information(self, "Успех", f"Пользователь {username} добавлен")

    def change_password(self):
        users = load_users()
        username = "ADMIN"
        old_password, ok1 = QInputDialog.getText(self, "Сменить пароль", "Введите старый пароль:", QLineEdit.Password)
        if ok1 and old_password and hash_password(old_password) == users[username]["password"]:
            new_password, ok2 = QInputDialog.getText(self, "Сменить пароль", "Введите новый пароль:", QLineEdit.Password)
            if ok2 and new_password:
                confirm_password, ok3 = QInputDialog.getText(self, "Подтверждение пароля", "Подтвердите новый пароль:", QLineEdit.Password)
                if ok3 and new_password == confirm_password:
                    users[username]["password"] = hash_password(new_password)
                    save_users(users)
                    QMessageBox.information(self, "Успех", "Пароль администратора изменен")
                else:
                    QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            else:
                QMessageBox.warning(self, "Ошибка", "Пароль не может быть пустым")
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный старый пароль")

    def set_restriction(self):
        selected = self.user_list.currentItem()
        if selected:
            username = selected.text().split()[0]
            users = load_users()
            if username in users:
                dialog = QDialog(self)
                dialog.setWindowTitle("Ограничения на пароль")
                layout = QVBoxLayout()

                min_length_label = QLabel("Минимальная длина:")
                min_length_input = QSpinBox()
                min_length_input.setMinimum(1)
                min_length_input.setValue(users[username].get("restrictions", {}).get("min_length", 6))

                policy_label = QLabel("Политика пароля:")
                policy_input = QComboBox()
                policy_input.addItems(PASSWORD_POLICIES.keys())
                policy_input.setCurrentText(users[username].get("restrictions", {}).get("policy", "Все символы"))

                save_button = QPushButton("Сохранить")

                layout.addWidget(min_length_label)
                layout.addWidget(min_length_input)
                layout.addWidget(policy_label)
                layout.addWidget(policy_input)
                layout.addWidget(save_button)

                dialog.setLayout(layout)

                def save_restrictions():
                    users[username]["restrictions"] = {
                        "min_length": min_length_input.value(),
                        "policy": policy_input.currentText()
                    }
                    save_users(users)
                    QMessageBox.information(self, "Успех", "Ограничения обновлены")
                    dialog.accept()

                save_button.clicked.connect(save_restrictions)
                dialog.exec()

    def remove_restriction(self):
        selected = self.user_list.currentItem()
        if selected:
            username = selected.text().split()[0]
            users = load_users()
            if username in users:
                users[username]["restrictions"] = {}
                save_users(users)
                self.load_users()
                QMessageBox.information(self, "Успех", f"Ограничения на пароль для {username} сняты")

    def logout(self):
        self.close()
        self.main_window.show()


class UserWindow(QWidget):
    def __init__(self, username, main_window):
        super().__init__()
        self.username = username  # Сохраняем имя пользователя
        self.main_window = main_window  # Ссылаемся на главное окно
        self.setWindowTitle("Пользователь")
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()

        self.change_password_button = QPushButton("Сменить пароль")
        self.logout_button = QPushButton("Выйти в главное меню")

        self.change_password_button.clicked.connect(self.change_password)
        self.logout_button.clicked.connect(self.logout)

        layout.addWidget(self.change_password_button)
        layout.addWidget(self.logout_button)

        self.setLayout(layout)

    def change_password(self):
        """НЕ РАБОТАЮТ ОГРАНИЧЕНИЯ АДМИНА НА ПАРОЛЬ. НУЖНО ИСПРАВИТЬ"""
        users = load_users()
        username = self.username  # Получаем имя текущего пользователя

        # Шаг 1: Запрашиваем старый пароль
        old_password, ok1 = QInputDialog.getText(self, "Сменить пароль", "Введите старый пароль:", QLineEdit.Password)

        if ok1:
            # Проверка старого пароля
            if old_password == "" or hash_password(old_password) == users[username]["password"]:
                # Шаг 2: Запрашиваем новый пароль
                new_password, ok2 = QInputDialog.getText(self, "Сменить пароль", "Введите новый пароль:",
                                                         QLineEdit.Password)

                if ok2 and new_password:
                    # Шаг 3: Проверка на ограничения (если они есть)
                    if users[username]["restrictions"]:
                        min_length = 6  # Пример ограничения на минимальную длину пароля
                        if len(new_password) < min_length:
                            QMessageBox.warning(self, "Ошибка", f"Пароль должен быть не короче {min_length} символов")
                            return

                    # Шаг 4: Подтверждение нового пароля
                    confirm_password, ok3 = QInputDialog.getText(self, "Подтверждение пароля",
                                                                 "Подтвердите новый пароль:", QLineEdit.Password)

                    if ok3 and new_password == confirm_password:
                        users[username]["password"] = hash_password(new_password)
                        save_users(users)
                        QMessageBox.information(self, "Успех", "Пароль изменен")
                    else:
                        QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
                else:
                    QMessageBox.warning(self, "Ошибка", "Пароль не может быть пустым")
            else:
                QMessageBox.warning(self, "Ошибка", "Неверный старый пароль")

    def logout(self):
        self.close()  # Закрываем окно пользователя
        self.main_window.show()  # Показываем окно входа в систему


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход в систему")
        self.setGeometry(100, 100, 300, 200)

        layout = QVBoxLayout()

        self.label = QLabel("Введите имя пользователя:")
        self.username_input = QLineEdit()
        self.password_label = QLabel("Введите пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.login)

        layout.addWidget(self.label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        users = load_users()

        if username not in users:
            QMessageBox.warning(self, "Ошибка", "Пользователь не найден")
            return

        if users[username]["blocked"]:
            QMessageBox.warning(self, "Ошибка", "Пользователь заблокирован")
            return

        if users[username]["password"] == hash_password(password):
            QMessageBox.information(self, "Успех", f"Добро пожаловать, {username}")
            if username == "ADMIN":
                self.admin_window = AdminWindow(self)
                self.admin_window.show()
                self.hide()
            else:
                self.user_window = UserWindow(username, self)  # Передаем ссылку на окно входа
                self.user_window.show()
                self.hide()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный пароль")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())
