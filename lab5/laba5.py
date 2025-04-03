import sys
import json
import hashlib
import re
import time
import string
import requests
from itertools import product
from multiprocessing import Pool, cpu_count
from PySide6.QtCore import QTimer
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
    has_lower = any(c.islower() for c in password) and any(c in 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя' for c in password.lower())
    has_upper = any(c.isupper() for c in password) and any(c in 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ' for c in password.upper())
    has_special = any(not c.isalnum() for c in password)

    if has_special:
        return 95  # Все возможные символы
    elif has_digit and (has_lower or has_upper):
        return 33 + 10  # 33 русские буквы + цифры
    elif has_lower or has_upper:
        return 33  # Только русские буквы
    else:
        return 10  # Только цифры


# --- Класс для работы в отдельном потоке ---
class PasswordCracker(QObject):
    finished = Signal()
    progress = Signal(str)
    password_found = Signal(str, str, float)  # русское слово, пароль, время
    dictionary_loaded = Signal(int)
    speed_updated = Signal(int)  # Новый сигнал для обновления скорости

    def __init__(self, target_hash, max_length=6):
        super().__init__()
        self.target_hash = target_hash
        self.max_length = max_length
        self._is_running = True
        self.password_dictionary = {}
        self.workers = []  # Будем хранить словари с worker и thread
        self.threads = []  # Отдельный список для потоков

        # Добавляем счетчики для скорости
        self.total_attempts = 0
        self.last_update_time = time.time()
        self.last_attempts = 0

        # Таймер для обновления скорости
        self.speed_timer = QTimer()
        self.speed_timer.timeout.connect(self.update_speed)
        self.speed_timer.start(1000)  # Обновляем каждую секунду

    def update_speed(self):
        """Вычисляет и отправляет текущую скорость"""
        current_time = time.time()
        elapsed = current_time - self.last_update_time
        if elapsed > 0:
            speed = int((self.total_attempts - self.last_attempts) / elapsed)
            self.speed_updated.emit(speed)
            self.last_update_time = current_time
            self.last_attempts = self.total_attempts


    def load_dictionary(self):
        """Загружает и генерирует словарь паролей."""
        try:
            with open("russian_words.txt", "r", encoding="utf-8") as f:
                russian_words = [line.strip() for line in f if 3 <= len(line.strip()) <= 12]
        except FileNotFoundError:
            russian_words = download_russian_words()

        self.password_dictionary = {word: ''.join([RUS_TO_LAT.get(char.lower(), char)
                                                   for char in word])
                                    for word in russian_words}
        self.dictionary_loaded.emit(len(self.password_dictionary))

    def run(self):
        self.load_dictionary()
        start_time = time.time()

        # 1. Проверка простых паролей
        self.progress.emit("🔍 Проверка простых паролей...")
        for pwd in ["123456", "password", "admin", "qwerty", "12345", "123456789"]:
            if not self._is_running:
                self.cleanup_workers()
                return
            if hash_password(pwd) == self.target_hash:
                self.password_found.emit("", pwd, time.time() - start_time)
                self.cleanup_workers()
                return

        # 2. Словарная атака
        self.progress.emit("📚 Словарная атака...")
        for word in self.password_dictionary.values():
            if not self._is_running:
                self.cleanup_workers()
                return
            if hash_password(word) == self.target_hash:
                self.password_found.emit("", word, time.time() - start_time)
                self.cleanup_workers()
                return

        # 3. Проверка русских слов как есть
        self.progress.emit("🔠 Проверка русских слов...")
        for russian_word in self.password_dictionary:
            if not self._is_running:
                self.cleanup_workers()
                return
            if hash_password(russian_word) == self.target_hash:
                self.password_found.emit(russian_word, russian_word, time.time() - start_time)
                self.cleanup_workers()
                return

        # 4. Brute-force атака
        self.progress.emit("⚡ Запускаем brute-force...")
        alphabet = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя' + \
                   'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ' + \
                   string.digits + '!@#$%'

        # Создаем worker'ов для каждой длины
        for length in range(1, self.max_length + 1):
            if not self._is_running:
                self.cleanup_workers()
                return

            self.progress.emit(f"🔢 Проверяем комбинации длины {length}...")

            worker = BruteForceWorker(self.target_hash, alphabet, length)
            thread = QThread()
            worker.moveToThread(thread)

            # Подключаем сигналы
            thread.started.connect(worker.run)
            worker.finished.connect(thread.quit)
            worker.finished.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)

            worker.attempt_made.connect(self.count_attempt)

            # Обработчик найденного пароля
            worker.password_found.connect(lambda pwd, st=start_time: (
                self.password_found.emit("", pwd, time.time() - st),
                self.stop()
            ))

            thread.start()
            self.workers.append(worker)
            self.threads.append(thread)

        # Ждем завершения всех потоков
        for thread in self.threads:
            thread.wait()

        if self._is_running:  # Если не было найдено и не было остановки
            self.progress.emit("❌ Пароль не найден")
            self.finished.emit()

    def count_attempt(self):
        """Увеличивает счетчик попыток"""
        self.total_attempts += 1

    def cleanup_workers(self):
        """Останавливает и очищает все рабочие потоки"""
        self._is_running = False  # Устанавливаем флаг первым делом
        self.speed_timer.stop()  # Останавливаем таймер

        # Останавливаем все потоки
        for thread in self.threads:
            try:
                thread.quit()
                thread.wait(500)
            except Exception as e:
                print(f"Error stopping thread: {e}")

        # Очищаем списки
        self.workers = []
        self.threads = []

    def stop(self):
        self._is_running = False
        self.cleanup_workers()
        self.progress.emit("🛑 Подбор принудительно остановлен")


class BruteForceWorker(QObject):
    finished = Signal()
    password_found = Signal(str)
    attempt_made = Signal()  # Новый сигнал о каждой попытке

    def __init__(self, target_hash, alphabet, length):
        super().__init__()
        self.target_hash = target_hash
        self.alphabet = alphabet
        self.length = length
        self._is_running = True

    def run(self):
        try:
            for attempt in product(self.alphabet, repeat=self.length):
                if not self._is_running:
                    break

                self.attempt_made.emit()  # Отправляем сигнал о попытке

                if hash_password(''.join(attempt)) == self.target_hash:
                    if self._is_running:  # Проверка перед отправкой сигнала
                        self.password_found.emit(''.join(attempt))
                    break
        except Exception as e:
            print(f"Worker error: {e}")
        finally:
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
            self, "Смена пароля", "Введите новый пароль (мин. 4 символа):", QLineEdit.Password
        )
        if not ok or not new_password:
            return

        # Проверка длины
        if len(new_password) < 4:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать минимум 4 символа!")
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

    def check_password_strength(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для анализа!")
            return

        alphabet_power = get_alphabet_power(password)
        crack_time, combinations = calculate_crack_time(len(password), alphabet_power)

        result = [
            f"Анализ пароля: {password}",
            f"Длина: {len(password)} символов",
            f"Мощность алфавита: {alphabet_power}",
            f"Возможных комбинаций: {combinations:,}",
            f"Примерное время перебора: {format_time(int(crack_time))}"
        ]

        if password.lower() in SIMPLE_PASSWORDS:
            result.append("\n⚠ Внимание: пароль слишком простой!")
        elif len(password) < 8:
            result.append("\n⚠ Внимание: рекомендуется длина от 8 символов!")

        self.result_display.setText("\n".join(result))

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

        self.speed_label = QLabel("Скорость: 0 попыток/сек")
        layout.addWidget(self.speed_label)

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
        self.cracker.speed_updated.connect(self.update_speed_display)
        self.cracker_thread.started.connect(self.cracker.run)
        self.cracker.finished.connect(self.cracker_thread.quit)
        self.cracker.finished.connect(self.on_attack_finished)
        self.cracker.progress.connect(self.update_progress)
        self.cracker.password_found.connect(self.on_password_found)
        self.cracker.dictionary_loaded.connect(self.update_dictionary_info)

        self.cracker_thread.start()

    def update_speed_display(self, speed):
        """Обновляет отображение скорости"""
        self.speed_label.setText(f"Скорость: {speed:,} попыток/сек")
        QApplication.processEvents()  # Принудительно обновляем интерфейс

    def stop_attack(self):
        if self.cracker:
            self.cracker.stop()
        self.attack_progress.append("Подбор пароля остановлен")
        self.on_attack_finished()

    def update_dictionary_info(self, count):
        self.dictionary_info.setText(f"Словарь: {count} слов")

    def on_password_found(self, russian_word, password, time_taken):
        try:
            if not self.cracker:
                return

            msg = f"✅ Пароль {'найден' if russian_word else 'взломан'}!\n"
            if russian_word:
                msg += f"Слово: '{russian_word}'\n"
            msg += f"Пароль: '{password}'\n"
            msg += f"Время: {time_taken:.2f} сек\n"
            self.attack_progress.append(msg)
            self.attack_progress.append("=" * 40)
        except Exception as e:
            print(f"Error displaying password: {e}")

    def update_progress(self, message):
        # Очищаем предыдущие сообщения о прогрессе, оставляя только итоговые
        if "🔍" in message or "📚" in message or "⚡" in message or "🔢" in message:
            self.attack_progress.append(message)

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


# --- Главное окно  ---
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
