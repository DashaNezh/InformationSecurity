import os
import json
import hashlib
import itertools
import time
from queue import Queue
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox, QStackedWidget, QHBoxLayout,
    QRadioButton, QButtonGroup, QProgressBar
)
from PySide6.QtCore import Qt, QThread, Signal, QMutex, QEvent

# Конфигурация
USERS_FILE = "users.json"
DICTIONARY_FILE = "russian_words.txt"
MAX_WORKERS = 4
BATCH_SIZE = 50


class UpdatePasswordEvent(QEvent):
    """Событие для обновления пароля в UI"""
    EVENT_TYPE = QEvent.Type(QEvent.registerEventType())

    def __init__(self, password):
        super().__init__(UpdatePasswordEvent.EVENT_TYPE)
        self.password = password


class PasswordCracker(QThread):
    update_signal = Signal(str, int, int)
    result_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self, login_window, attack_type, length=None):
        super().__init__()
        self.login_window = login_window
        self.attack_type = attack_type
        self.password_length = length
        self.russian_chars = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
        self.is_running = True
        self.mutex = QMutex()
        self.found = False
        self.lock = QMutex()

    def run(self):
        if self.attack_type == 'brute':
            self.brute_force_attack()
        elif self.attack_type == 'dictionary':
            self.dictionary_attack()

        if not self.found:
            msg = "Пароль не найден"
            if self.attack_type == 'dictionary':
                msg += " в словаре"
            self.result_signal.emit(msg)
        self.finished_signal.emit()

    def brute_force_attack(self):
        total = len(self.russian_chars) ** self.password_length
        chunk_size = 10000  # Увеличиваем размер чанка для эффективности

        # Генерируем все варианты заранее для стабильности
        all_combinations = list(itertools.product(self.russian_chars, repeat=self.password_length))
        total = len(all_combinations)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []

            for i in range(0, total, chunk_size):
                if not self.is_running or self.found:
                    break

                chunk = [''.join(c) for c in all_combinations[i:i + chunk_size]]
                futures.append(executor.submit(
                    self.process_bruteforce_chunk,
                    chunk,
                    i,
                    total
                ))

                # Ограничиваем количество одновременно выполняемых задач
                if len(futures) >= MAX_WORKERS * 2:
                    for future in as_completed(futures):
                        if future.result():
                            self.found = True
                            break
                    futures = []

            # Проверяем оставшиеся задачи
            for future in futures:
                if future.result():
                    self.found = True
                    break

    def process_bruteforce_chunk(self, chunk, start_idx, total):
        """Обработка блока паролей для bruteforce"""
        for i, candidate in enumerate(chunk):
            if not self.is_running or self.found:
                return False

            # Безопасное обновление UI
            self.lock.lock()
            try:
                QApplication.postEvent(
                    self.login_window,
                    UpdatePasswordEvent(candidate))

                # Минимальная задержка для обработки событий
                time.sleep(0.001)

                if self.login_window.last_login_success:
                    self.result_signal.emit(f"Пароль найден: {candidate}")
                return True

                # Обновляем прогресс каждые 100 итераций
                if i % 100 == 0:
                    current = start_idx + i
                    self.update_signal.emit(candidate, current, total)
            finally:
                self.lock.unlock()

        return False

    def dictionary_attack(self):
        try:
            with open(DICTIONARY_FILE, 'r', encoding='utf-8') as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.result_signal.emit(f"Ошибка чтения словаря: {str(e)}")
            return

        total = len(words)
        chunk_size = min(BATCH_SIZE, max(10, total // (MAX_WORKERS * 2)))

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i in range(0, total, chunk_size):
                if not self.is_running or self.found:
                    break
                chunk = words[i:i + chunk_size]
                futures.append(executor.submit(self.process_chunk, chunk, i, total))

                if len(futures) >= MAX_WORKERS * 2:
                    for future in as_completed(futures):
                        if future.result():
                            self.found = True
                            break
                    futures = []

            for future in futures:
                if future.result():
                    self.found = True
                    break

    def process_chunk(self, chunk, start_idx=0, total=0):
        """Обработка блока паролей в отдельном потоке"""
        for i, candidate in enumerate(chunk):
            if not self.is_running or self.found:
                return False

            # Блокируем для безопасного доступа к UI
            self.lock.lock()
            try:
                # Эмулируем ввод пароля
                QApplication.postEvent(
                    self.login_window,
                    UpdatePasswordEvent(candidate)
                )
                # Небольшая задержка для обработки UI
                time.sleep(0.01)

                # Проверяем результат
                if self.login_window.last_login_success:
                    self.result_signal.emit(f"Пароль найден: {candidate}")
                    return True

                # Обновляем прогресс
                if total > 0 and i % 5 == 0:
                    current = start_idx + i
                    self.update_signal.emit(candidate, current, total)
            finally:
                self.lock.unlock()
        return False

    def stop(self):
        self.mutex.lock()
        self.is_running = False
        self.mutex.unlock()

class LoginWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.cracker_thread = None
        self.last_login_success = False
        self.init_ui()
        self.check_users_file()

    def event(self, event):
        """Обработчик событий для обновления UI"""
        if isinstance(event, UpdatePasswordEvent):
            self.password_input.setText(event.password)
            # Автоматически вызываем проверку пароля
            self.handle_login(silent=True)
            return True
        return super().event(event)

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("Вход в систему")
        self.label.setAlignment(Qt.AlignCenter)

        # Поля ввода
        self.username_label = QLabel("Логин:")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        # Кнопка входа
        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.handle_login)

        # Выбор типа атаки
        self.attack_type_group = QButtonGroup()

        self.brute_force_radio = QRadioButton("Полный перебор")
        self.brute_force_radio.setChecked(True)
        self.attack_type_group.addButton(self.brute_force_radio)

        self.dictionary_radio = QRadioButton("Атака по словарю")
        self.attack_type_group.addButton(self.dictionary_radio)

        attack_type_layout = QHBoxLayout()
        attack_type_layout.addWidget(self.brute_force_radio)
        attack_type_layout.addWidget(self.dictionary_radio)

        # Параметры атаки
        self.attack_params_layout = QVBoxLayout()

        self.brute_params = QWidget()
        brute_layout = QVBoxLayout()
        self.attack_length_label = QLabel("Длина пароля:")
        self.attack_length_input = QLineEdit()
        self.attack_length_input.setText("3")
        brute_layout.addWidget(self.attack_length_label)
        brute_layout.addWidget(self.attack_length_input)
        self.brute_params.setLayout(brute_layout)

        self.dictionary_params = QWidget()
        dictionary_layout = QVBoxLayout()
        self.dictionary_info = QLabel(f"Словарь: {DICTIONARY_FILE}")
        dictionary_layout.addWidget(self.dictionary_info)
        self.dictionary_params.setLayout(dictionary_layout)
        self.dictionary_params.hide()

        self.attack_params_layout.addWidget(self.brute_params)
        self.attack_params_layout.addWidget(self.dictionary_params)

        # Кнопки атаки
        self.attack_button = QPushButton("Начать атаку")
        self.attack_button.clicked.connect(self.start_attack)

        self.stop_attack_button = QPushButton("Остановить атаку")
        self.stop_attack_button.clicked.connect(self.stop_attack)
        self.stop_attack_button.setEnabled(False)

        # Прогресс
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.status_label = QLabel("Готово")

        # Соединения
        self.brute_force_radio.toggled.connect(self.update_attack_params)

        # Компоновка
        layout.addWidget(self.label)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addLayout(attack_type_layout)
        layout.addLayout(self.attack_params_layout)
        layout.addWidget(self.attack_button)
        layout.addWidget(self.stop_attack_button)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)

        self.last_login_success = False

        self.setLayout(layout)

    def simulate_login_attempt(self, password):
        """Эмулирует попытку входа и возвращает True если успешно"""
        self.password_input.setText(password)
        return self.handle_login(silent=True)

    def update_attack_params(self, checked):
        """Обновляет отображаемые параметры в зависимости от выбранного типа атаки"""
        self.brute_params.setVisible(checked)
        self.dictionary_params.setVisible(not checked)

    def check_users_file(self):
        """Проверяет и создает файл пользователей при необходимости"""
        if not os.path.exists(USERS_FILE):
            default_password = "пароль"
            hashed_password = hashlib.sha256(default_password.encode()).hexdigest()

            users = {
                "admin": {
                    "password": hashed_password,
                    "is_admin": True
                }
            }

            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)

            QMessageBox.information(
                self, "Создан администратор",
                f"Создан пользователь admin с паролем '{default_password}'\n"
                "Измените пароль после первого входа!"
            )

    def handle_login(self, silent=False):
        username = self.username_input.text()
        password = self.password_input.text()

        self.last_login_success = False

        if not username or not password:
            if not silent:
                QMessageBox.warning(self, "Ошибка", "Введите логин и пароль")
            self.last_login_success = False
            return False

        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            if not silent:
                QMessageBox.critical(self, "Ошибка", f"Ошибка чтения файла: {str(e)}")
            self.last_login_success = False
            return False

        if username not in users:
            if not silent:
                QMessageBox.warning(self, "Ошибка", "Пользователь не найден")
            self.last_login_success = False
            return False

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if users[username]["password"] != hashed_password:
            if not silent:
                QMessageBox.warning(self, "Ошибка", "Неверный пароль")
            self.last_login_success = False
            return False

        self.parent.current_user = username
        self.parent.is_admin = users[username].get("is_admin", False)
        self.last_login_success = True

        if not silent:
            if self.parent.is_admin:
                self.parent.stacked_widget.setCurrentIndex(1)
            else:
                QMessageBox.information(self, "Успех", "Вход выполнен")

        return True

    def start_attack(self):
        """Запускает выбранный тип атаки"""
        username = self.username_input.text()
        if not username:
            QMessageBox.warning(self, "Ошибка", "Введите логин для атаки")
            return

        attack_type = 'brute' if self.brute_force_radio.isChecked() else 'dictionary'

        if attack_type == 'brute':
            try:
                length = int(self.attack_length_input.text())
                if length < 1 or length > 6:  # Увеличил максимальную длину для демонстрации
                    QMessageBox.warning(self, "Ошибка", "Длина пароля должна быть от 1 до 6 символов")
                    return
            except ValueError:
                QMessageBox.warning(self, "Ошибка", "Введите корректную длину пароля")
                return
        else:
            length = None

        self.attack_button.setEnabled(False)
        self.stop_attack_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Атака начата...")

        self.cracker_thread = PasswordCracker(self, attack_type, length)
        self.cracker_thread.update_signal.connect(self.update_attack_status)
        self.cracker_thread.result_signal.connect(self.show_attack_result)
        self.cracker_thread.finished_signal.connect(self.attack_finished)
        self.cracker_thread.start()

    def stop_attack(self):
        """Останавливает выполняющуюся атаку"""
        if self.cracker_thread:
            self.cracker_thread.stop()
            self.status_label.setText("Атака остановлена")

    def update_attack_status(self, password, current, total):
        """Обновляет статус выполнения атаки"""
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
        self.password_input.setText(password)
        self.status_label.setText(f"Проверка: {password}...")

    def show_attack_result(self, message):
        """Показывает результат атаки"""
        QMessageBox.information(self, "Результат", message)
        self.status_label.setText(message)

    def attack_finished(self):
        """Завершает процесс атаки"""
        self.attack_button.setEnabled(True)
        self.stop_attack_button.setEnabled(False)
        if self.cracker_thread:
            self.cracker_thread.quit()
            self.cracker_thread.wait()
            self.cracker_thread = None

class AdminPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.label = QLabel("Админ-панель")
        self.label.setAlignment(Qt.AlignCenter)

        self.current_password_label = QLabel("Текущий пароль:")
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)

        self.new_password_label = QLabel("Новый пароль:")
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)

        self.confirm_password_label = QLabel("Подтвердите новый пароль:")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)

        self.change_password_button = QPushButton("Изменить пароль")
        self.change_password_button.clicked.connect(self.handle_password_change)

        self.back_button = QPushButton("Назад")
        self.back_button.clicked.connect(self.go_back)

        layout.addWidget(self.label)
        layout.addWidget(self.current_password_label)
        layout.addWidget(self.current_password_input)
        layout.addWidget(self.new_password_label)
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.confirm_password_label)
        layout.addWidget(self.confirm_password_input)
        layout.addWidget(self.change_password_button)
        layout.addWidget(self.back_button)

        self.setLayout(layout)

    def hash_password(self, password):
        """Хеширует пароль с использованием SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def handle_password_change(self):
        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not current_password or not new_password or not confirm_password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Новые пароли не совпадают")
            return

        try:
            with open(USERS_FILE, "r") as f:
                users = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка чтения файла: {str(e)}")
            return

        username = self.parent.current_user
        if username not in users:
            QMessageBox.critical(self, "Ошибка", "Пользователь не найден")
            return

        # Проверяем текущий пароль
        hashed_current = self.hash_password(current_password)
        if users[username]["password"] != hashed_current:
            QMessageBox.warning(self, "Ошибка", "Неверный текущий пароль")
            return

        # Обновляем пароль
        users[username]["password"] = self.hash_password(new_password)

        try:
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения: {str(e)}")
            return

        QMessageBox.information(self, "Успех", "Пароль успешно изменен")

        # Очищаем поля
        self.current_password_input.clear()
        self.new_password_input.clear()
        self.confirm_password_input.clear()

    def go_back(self):
        self.parent.stacked_widget.setCurrentIndex(0)  # Возврат к окну входа
        self.parent.current_user = None
        self.parent.is_admin = False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.current_user = None
        self.is_admin = False

        self.setWindowTitle("Система входа")
        self.setGeometry(100, 100, 450, 450)

        # Создаем stacked widget для переключения между окнами
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        # Добавляем окна
        self.login_window = LoginWindow(self)
        self.admin_panel = AdminPanel(self)

        self.stacked_widget.addWidget(self.login_window)
        self.stacked_widget.addWidget(self.admin_panel)


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()