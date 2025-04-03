import sys
import json
import hashlib
import re
import time
import string
import requests
from itertools import product
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
                               QMessageBox, QDialog, QListWidget, QHBoxLayout, QInputDialog,
                               QComboBox, QSpinBox, QTextEdit, QTabWidget)
from PySide6.QtCore import QThread, Signal, QObject

# --- Общие функции ---
USERS_FILE = "users.json"
SIMPLE_PASSWORDS = {"123456", "password", "qwerty", "abc123", "111111"}

# Таблица перевода русских букв в латинскую раскладку
RUS_TO_LAT = {
    'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y', 'г': 'u', 'ш': 'i', 'щ': 'o', 'з': 'p',
    'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f', 'п': 'g', 'р': 'h', 'о': 'j', 'л': 'k', 'д': 'l', 'ж': ';',
    'я': 'z', 'ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n', 'ь': 'm', 'б': ',', 'ю': '.', 'ё': '`',
    'э': '[', 'ъ': ']', ' ': ' '
}


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    try:
        with open(USERS_FILE, "r", encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        users = {"ADMIN": {"password": hash_password("admin"), "blocked": False, "restrictions": {}}}
        save_users(users)
        return users


def save_users(users):
    with open(USERS_FILE, "w", encoding='utf-8') as file:
        json.dump(users, file, ensure_ascii=False, indent=4)


def download_russian_words(url="https://raw.githubusercontent.com/danakt/russian-words/master/russian.txt"):
    """Скачивает список русских слов (если нет файла)."""
    try:
        response = requests.get(url)
        words = response.text.splitlines()
        with open("russian_words.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(words))
        return words
    except Exception:
        return ["пароль", "привет", "админ", "qwerty"]  # Fallback-словарь


def generate_password_dictionary(russian_words):
    """Переводит русские слова в латинскую раскладку."""
    dictionary = {}
    for word in russian_words:
        translated = ''.join([RUS_TO_LAT.get(char.lower(), char) for char in word])
        dictionary[word] = translated
    return dictionary


# --- Функции для оценки надежности ---
def calculate_combinations(password_length: int, alphabet_power: int) -> int:
    return alphabet_power ** password_length


def calculate_crack_time(password_length: int, alphabet_power: int, speed: float = 10,
                         max_attempts: int = 13, delay: int = 10) -> tuple:
    total_combinations = calculate_combinations(password_length, alphabet_power)
    time_without_delay = total_combinations / speed
    time_with_delay = (total_combinations // max_attempts) * delay
    return time_without_delay + time_with_delay, total_combinations


def format_time(seconds: int) -> str:
    years, seconds = divmod(seconds, 365 * 24 * 3600)
    months, seconds = divmod(seconds, 30 * 24 * 3600)
    days, seconds = divmod(seconds, 24 * 3600)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{years} лет {months} месяцев {days} дней {hours} часов {minutes} минут {seconds} секунд"


def get_alphabet_power(password: str) -> int:
    has_digit = any(c.isdigit() for c in password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if has_special:
        return 95
    elif has_digit and (has_lower or has_upper):
        return 36
    elif has_lower or has_upper:
        return 26
    else:
        return 10


# --- Класс для работы в отдельном потоке ---
class PasswordCracker(QObject):
    finished = Signal()
    progress = Signal(str)
    password_found = Signal(str, str, float)  # русское слово, пароль, время
    dictionary_loaded = Signal(int)

    def __init__(self, target_hash, max_length=6):
        super().__init__()
        self.target_hash = target_hash
        self.max_length = max_length
        self._is_running = True
        self.password_dictionary = {}

    def load_dictionary(self):
        """Загружает и генерирует словарь паролей."""
        try:
            with open("russian_words.txt", "r", encoding="utf-8") as f:
                russian_words = [line.strip() for line in f if 3 <= len(line.strip()) <= 12]
        except FileNotFoundError:
            russian_words = download_russian_words()

        self.password_dictionary = generate_password_dictionary(russian_words)
        self.dictionary_loaded.emit(len(self.password_dictionary))

    def run(self):
        """Основной метод подбора пароля."""
        self.load_dictionary()

        # Подбор по словарю
        for russian_word, latin_word in self.password_dictionary.items():
            if not self._is_running:
                return

            if hash_password(latin_word) == self.target_hash:
                self.password_found.emit(russian_word, latin_word, 0)
                self.finished.emit()
                return
            self.progress.emit(f"Проверен: {russian_word} -> {latin_word}")

        # Brute-force с русскими буквами
        self.progress.emit("Словарный подбор не удался. Запуск brute-force...")
        start_time = time.time()
        alphabet = string.ascii_lowercase + string.digits + 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'

        for length in range(1, self.max_length + 1):
            if not self._is_running:
                return
            self.progress.emit(f"Проверяем длину {length}...")
            for attempt in product(alphabet, repeat=length):
                if not self._is_running:
                    return
                attempt = ''.join(attempt)
                if hash_password(attempt) == self.target_hash:
                    self.password_found.emit("", attempt, time.time() - start_time)
                    self.finished.emit()
                    return
        self.progress.emit("Пароль не найден. Увеличьте max_length.")
        self.finished.emit()

    def stop(self):
        self._is_running = False

# --- Класс админ-панели ---
class AdminWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Админ панель")
        self.setGeometry(200, 200, 400, 500)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Кнопка смены пароля ADMIN
        self.change_admin_password_button = QPushButton("Сменить пароль ADMIN")
        self.change_admin_password_button.clicked.connect(self.change_admin_password)

        # Кнопка возврата
        self.back_button = QPushButton("Назад")
        self.back_button.clicked.connect(self.close)

        layout.addWidget(self.change_admin_password_button)
        layout.addWidget(self.back_button)
        self.setLayout(layout)

    def change_admin_password(self):
        users = load_users()

        # Запрос текущего пароля
        current_password, ok = QInputDialog.getText(
            self, "Подтверждение", "Введите текущий пароль ADMIN:", QLineEdit.Password
        )
        if not ok:
            return

        if hash_password(current_password) != users["ADMIN"]["password"]:
            QMessageBox.warning(self, "Ошибка", "Неверный текущий пароль!")
            return

        # Запрос нового пароля
        new_password, ok = QInputDialog.getText(
            self, "Смена пароля", "Введите новый пароль (мин. 8 символов):", QLineEdit.Password
        )
        if not ok or not new_password:
            return

        # Проверка длины
        if len(new_password) < 8:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать минимум 8 символов!")
            return

        # Подтверждение пароля
        confirm_password, ok = QInputDialog.getText(
            self, "Подтверждение", "Повторите новый пароль:", QLineEdit.Password
        )
        if new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают!")
            return

        # Сохранение
        users["ADMIN"]["password"] = hash_password(new_password)
        save_users(users)
        QMessageBox.information(self, "Успех", "Пароль ADMIN успешно изменен!")

# --- Класс анализа паролей ---
class PasswordAnalysisWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Анализ устойчивости пароля")
        self.setGeometry(200, 200, 600, 500)
        self.cracker_thread = None
        self.cracker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.tabs = QTabWidget()

        # Вкладка проверки надежности
        self.tab1 = QWidget()
        self.setup_tab1()
        self.tabs.addTab(self.tab1, "Проверка надежности")

        # Вкладка подбора пароля
        self.tab2 = QWidget()
        self.setup_tab2()
        self.tabs.addTab(self.tab2, "Подбор пароля")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def setup_tab1(self):
        layout = QVBoxLayout()

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Введите пароль для анализа")

        self.check_button = QPushButton("Проверить надежность")
        self.check_button.clicked.connect(self.check_password_strength)

        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)

        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.check_button)
        layout.addWidget(self.result_display)
        self.tab1.setLayout(layout)

    def setup_tab2(self):
        layout = QVBoxLayout()

        self.target_login = QLineEdit()
        self.target_login.setPlaceholderText("Введите логин пользователя")

        # Настройки подбора
        settings_layout = QHBoxLayout()

        self.max_length_spin = QSpinBox()
        self.max_length_spin.setRange(1, 8)
        self.max_length_spin.setValue(4)
        self.max_length_spin.setPrefix("Макс. длина: ")

        self.dictionary_info = QLabel("Словарь: не загружен")

        settings_layout.addWidget(self.max_length_spin)
        settings_layout.addWidget(self.dictionary_info)

        # Кнопки
        self.start_attack_button = QPushButton("Начать подбор")
        self.start_attack_button.clicked.connect(self.start_attack)

        self.stop_attack_button = QPushButton("Остановить")
        self.stop_attack_button.clicked.connect(self.stop_attack)
        self.stop_attack_button.setEnabled(False)

        self.attack_progress = QTextEdit()
        self.attack_progress.setReadOnly(True)

        layout.addWidget(QLabel("Логин для подбора:"))
        layout.addWidget(self.target_login)
        layout.addLayout(settings_layout)
        layout.addWidget(self.start_attack_button)
        layout.addWidget(self.stop_attack_button)
        layout.addWidget(self.attack_progress)
        self.tab2.setLayout(layout)

    def start_attack(self):
        login = self.target_login.text()
        users = load_users()

        if login not in users:
            QMessageBox.warning(self, "Ошибка", "Пользователь не найден!")
            return

        self.start_attack_button.setEnabled(False)
        self.stop_attack_button.setEnabled(True)
        self.attack_progress.clear()

        target_hash = users[login]["password"]
        max_len = self.max_length_spin.value()

        self.attack_progress.append(f"Начало подбора пароля для {login}...")

        # Создаем и запускаем поток
        self.cracker_thread = QThread()
        self.cracker = PasswordCracker(target_hash, max_length=max_len)
        self.cracker.moveToThread(self.cracker_thread)

        # Подключаем сигналы
        self.cracker_thread.started.connect(self.cracker.run)
        self.cracker.finished.connect(self.cracker_thread.quit)
        self.cracker.finished.connect(self.on_attack_finished)
        self.cracker.progress.connect(self.update_progress)
        self.cracker.password_found.connect(self.on_password_found)
        self.cracker.dictionary_loaded.connect(self.update_dictionary_info)

        self.cracker_thread.start()

    def stop_attack(self):
        if self.cracker:
            self.cracker.stop()
        self.attack_progress.append("Подбор пароля остановлен")
        self.on_attack_finished()

    def update_progress(self, message):
        self.attack_progress.append(message)

    def update_dictionary_info(self, count):
        self.dictionary_info.setText(f"Словарь: {count} слов")

    def on_password_found(self, russian_word, password, time_taken):
        if russian_word:
            msg = f"Пароль найден: '{password}' (исходное слово: '{russian_word}')"
        else:
            msg = f"Пароль взломан: '{password}' (время: {time_taken:.2f} сек)"
        self.attack_progress.append(msg)

    def on_attack_finished(self):
        self.start_attack_button.setEnabled(True)
        self.stop_attack_button.setEnabled(False)
        if self.cracker:
            self.cracker.deleteLater()
        if self.cracker_thread:
            self.cracker_thread.deleteLater()

    def closeEvent(self, event):
        self.stop_attack()
        super().closeEvent(event)


# --- Главное окно (остается без изменений) ---
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Вход в систему")
        self.setGeometry(100, 100, 300, 200)
        layout = QVBoxLayout()

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Логин")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Пароль")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.login)

        self.analysis_button = QPushButton("Анализ паролей")
        self.analysis_button.clicked.connect(self.open_analysis)

        layout.addWidget(QLabel("Логин:"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Пароль:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.analysis_button)
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
            QMessageBox.information(self, "Успех", f"Добро пожаловать, {username}!")
            if username == "ADMIN":
                self.admin_window = AdminWindow(self)
                self.admin_window.show()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный пароль")

    def open_analysis(self):
        self.analysis_window = PasswordAnalysisWindow(self)
        self.analysis_window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())