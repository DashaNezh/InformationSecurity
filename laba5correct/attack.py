import sys
import itertools
import string
import time
from PySide6.QtWidgets import QApplication
from laba3 import LoginWindow
from unittest.mock import patch

# Функции оценки стойкости
def calculate_combinations(password_length: int, alphabet_power: int) -> int:
    """Вычисляет количество возможных комбинаций пароля"""
    return alphabet_power ** password_length


def calculate_crack_time(password_length: int, alphabet_power: int, speed: float, max_attempts: int,
                         delay: int) -> tuple:
    """Рассчитывает время взлома с учетом задержки между попытками"""
    total_combinations = calculate_combinations(password_length, alphabet_power)
    time_without_delay = total_combinations / speed

    # Расчет времени с учетом задержки после max_attempts
    if total_combinations <= max_attempts:
        time_with_delay = 0
    else:
        if total_combinations % max_attempts == 0:
            time_with_delay = (total_combinations // max_attempts - 1) * delay
        else:
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
    """Определяет мощность алфавита на основе символов в пароле"""
    char_sets = {
        'russian_lower': "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
        'russian_upper': "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
        'digits': string.digits,
        'special': string.punctuation
    }

    power = 0
    for charset_name, charset in char_sets.items():
        if any(char in charset for char in password):
            power += len(charset)

    return power


def print_strength_results(password: str, speed: float, max_attempts: int, delay: int):
    """Выводит результаты оценки стойкости пароля"""
    password_length = len(password)
    alphabet_size = get_alphabet_power(password)

    total_time, total_combinations = calculate_crack_time(
        password_length, alphabet_size, speed, max_attempts, delay
    )

    print("\n[🔐] Оценка стойкости пароля:")
    print(f"Пароль: {password}")
    print(f"Длина пароля: {password_length}")
    print(f"Мощность алфавита: {alphabet_size}")
    print(f"Комбинаций: {total_combinations:,}".replace(",", " "))
    print(f"Ожидаемое время взлома: {format_time(int(total_time))}")


# Qt Init
app = QApplication(sys.argv)

# Цель
target_user = "DASHA"
login_win = LoginWindow()

# Русский алфавит
russian_lower = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
russian_upper = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
default_charset = russian_lower + russian_upper + string.digits

# Генератор полного перебора
def generate_passwords(charset, max_length):
    for length in range(1, max_length + 1):
        for password in itertools.product(charset, repeat=length):
            yield ''.join(password)

# Загрузка словаря из файла
def load_dictionary(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Файл {filename} не найден.")
        return []

# Выбор режима
mode = input("Выберите режим (dictionary/full): ").strip().lower()
if mode == "dictionary":
    passwords = load_dictionary("russian_words.txt")
elif mode == "full":
    max_length = int(input("Максимальная длина пароля: "))
    passwords = generate_passwords(default_charset, max_length)
else:
    print("[!] Неизвестный режим.")
    sys.exit(1)

# 🔐 Атака
found_password = None
print("[INFO] Начинаем перебор...")

start_time = time.time()
max_attempts = 10  # Параметры для оценки надежности
delay = 0  # Задержка в секундах

with patch("laba3.QMessageBox.information") as mock_info, \
     patch("laba3.QMessageBox.warning") as mock_warn:

    for idx, password in enumerate(passwords, 1):
        login_win.username_input.setText(target_user)
        login_win.password_input.setText(password)
        login_win.login()

        # Текущая скорость перебора
        elapsed = time.time() - start_time
        speed = idx / elapsed if elapsed > 0 else 0

        # Расчет скорости по надежности
        alphabet_size = len(set(password))  # Мощность алфавита текущего пароля
        password_length = len(password)
        crack_time, total_combinations = calculate_crack_time(password_length, alphabet_size, speed, max_attempts, delay)
        strength_speed = total_combinations / elapsed if elapsed > 0 else float('inf')
        formatted_time = format_time(int(crack_time))

        if mock_info.called:
            args = mock_info.call_args[0]
            if "Добро пожаловать" in args[2]:
                found_password = password
                print(f"\n[✅] Пароль найден: {password}")
                break

        mock_info.reset_mock()
        mock_warn.reset_mock()

# 🧾 Финальная статистика
elapsed = time.time() - start_time
speed = idx / elapsed if elapsed > 0 else 0
strength_speed = total_combinations / elapsed if elapsed > 0 else float('inf')
if not found_password:
    print("\n[-] Пароль не найден.")
print(f"\n[📊] Попыток: {idx} | Время: {elapsed:.2f} сек | Средняя скорость: {strength_speed:.2f} паролей/сек")

# 🔐 Оценка стойкости найденного пароля
if found_password:
    print_strength_results(found_password, speed, max_attempts=10, delay=0)

# Выход из приложения
sys.exit(app.exec())