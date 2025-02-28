import random
import string


def generate_password(length: int, alphabet_size: int) -> str:
    if alphabet_size == 10:
        alphabet = string.digits  # 0-9
    elif alphabet_size == 26:
        alphabet = string.ascii_lowercase  # a-z
    elif alphabet_size == 36:
        alphabet = string.ascii_lowercase + string.digits  # a-z, 0-9
    elif alphabet_size == 95:
        alphabet = string.printable  # все символы, доступные на клавиатуре
    else:
        raise ValueError("Unsupported alphabet size")

    return ''.join(random.choice(alphabet) for _ in range(length))


def calculate_combinations(password_length: int, alphabet_power: int) -> int:
    return alphabet_power ** password_length


def calculate_crack_time(password_length: int, alphabet_power: int, speed: float, max_attempts: int,
                         delay: int) -> tuple:
    total_combinations = calculate_combinations(password_length, alphabet_power)
    time_without_delay = total_combinations / speed

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


def print_results(password: str, alphabet_size: int, speed: float, max_attempts: int, delay: int):
    password_length = len(password)
    total_time, total_combinations = calculate_crack_time(password_length, alphabet_size, speed, max_attempts, delay)
    print(f"Пароль: {password}")
    print(f"Длина алфавита: {alphabet_size}")
    print(f"Длина пароля: {password_length}")
    print(f"Количество комбинаций: {int(total_combinations)}")
    print(f"Время перебора: {format_time(int(total_time))}\n")


def main():
    speed = 10
    max_attempts = 13
    delay = 10

    # Генерируем пароли для разных мощностей алфавита
    for alphabet_size in [10, 26, 36, 95]:
        password_length = random.randint(1, 1)  # Длина пароля случайным образом между 6 и 12 символами
        password = generate_password(password_length, alphabet_size)
        print_results(password, alphabet_size, speed, max_attempts, delay)


if __name__ == "__main__":
    main()
