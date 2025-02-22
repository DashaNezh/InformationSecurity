import json
import hashlib
import getpass

USERS_FILE = "users.json"


# Функция хэширования пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Загрузка пользователей из файла
def load_users():
    try:
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {"ADMIN": {"password": hash_password(""), "blocked": False, "restrictions": False}}


# Сохранение пользователей в файл
def save_users(users):
    with open(USERS_FILE, "w") as file:
        json.dump(users, file, indent=4)


# Проверка пароля
def check_password(stored_hash, entered_password):
    return stored_hash == hash_password(entered_password)


# Вход в систему
def login():
    users = load_users()
    while True:
        username = input("Введите имя пользователя: ")
        if username not in users:
            print("Пользователь не найден. Попробуйте снова.")
            continue

        if users[username]["blocked"]:
            print("Этот пользователь заблокирован. Вход невозможен.")
            continue

        for _ in range(3):  # 3 попытки ввода пароля
            password = getpass.getpass("Введите пароль: ")
            if check_password(users[username]["password"], password):
                print(f"Добро пожаловать, {username}!")
                return username
            else:
                print("Неверный пароль.")

        print("Слишком много неудачных попыток. Выход.")
        exit()


# Смена пароля
def change_password(username):
    users = load_users()
    while True:
        old_password = getpass.getpass("Введите старый пароль: ")
        if check_password(users[username]["password"], old_password):
            while True:
                new_password = getpass.getpass("Введите новый пароль: ")
                confirm_password = getpass.getpass("Повторите новый пароль: ")
                if new_password == confirm_password:
                    users[username]["password"] = hash_password(new_password)
                    save_users(users)
                    print("Пароль успешно изменён.")
                    return
                else:
                    print("Пароли не совпадают. Попробуйте снова.")
        else:
            print("Неверный старый пароль.")


# Добавление пользователя
def add_user():
    users = load_users()
    username = input("Введите имя нового пользователя: ")
    if username in users:
        print("Такой пользователь уже существует.")
        return

    users[username] = {"password": hash_password(""), "blocked": False, "restrictions": False}
    save_users(users)
    print(f"Пользователь {username} добавлен.")


# Просмотр пользователей
def view_users():
    users = load_users()
    print("--- Список пользователей ---")
    for user, data in users.items():
        status = "Заблокирован" if data["blocked"] else "Активен"
        restrictions = "Да" if data["restrictions"] else "Нет"
        print(f"{user}: {status}, Ограничения на пароль: {restrictions}")


# Блокировка пользователя
def block_user():
    users = load_users()
    username = input("Введите имя пользователя для блокировки: ")
    if username in users and username != "ADMIN":
        users[username]["blocked"] = True
        save_users(users)
        print(f"Пользователь {username} заблокирован.")
    else:
        print("Пользователь не найден или нельзя заблокировать администратора.")


# Установка ограничений на пароль
def set_password_restrictions():
    users = load_users()
    username = input("Введите имя пользователя для установки ограничений: ")
    if username in users:
        users[username]["restrictions"] = True
        save_users(users)
        print(f"Ограничения на пароли включены для {username}.")
    else:
        print("Пользователь не найден.")

# Снятие блокировки пользователя
def unblock_user():
    users = load_users()
    username = input("Введите имя пользователя для снятия блокировки: ")
    if username in users and username != "ADMIN":
        users[username]["blocked"] = False
        save_users(users)
        print(f"Блокировка пользователя {username} снята.")
    else:
        print("Пользователь не найден или нельзя снять блокировку с администратора.")


# Снятие ограничений на пароль
def remove_password_restrictions():
    users = load_users()
    username = input("Введите имя пользователя для снятия ограничений на пароль: ")
    if username in users:
        users[username]["restrictions"] = False
        save_users(users)
        print(f"Ограничения на пароли для пользователя {username} сняты.")
    else:
        print("Пользователь не найден.")


# Главное меню администратора
def admin_menu():
    while True:
        print("\n--- Меню администратора ---")
        print("1. Сменить пароль")
        print("2. Просмотр пользователей")
        print("3. Добавить пользователя")
        print("4. Блокировать пользователя")
        print("5. Установить ограничения на пароль")
        print("6. Снять блокировку с пользователя")
        print("7. Снять ограничения на пароль")
        print("8. Выйти")
        choice = input("Выберите действие: ")

        if choice == "1":
            change_password("ADMIN")
        elif choice == "2":
            view_users()
        elif choice == "3":
            add_user()
        elif choice == "4":
            block_user()
        elif choice == "5":
            set_password_restrictions()
        elif choice == "6":
            unblock_user()
        elif choice == "7":
            remove_password_restrictions()
        elif choice == "8":
            break
        else:
            print("Неверный ввод, попробуйте снова.")


# Главное меню пользователя
def user_menu(username):
    while True:
        print("\n--- Меню пользователя ---")
        print("1. Сменить пароль")
        print("2. Выйти")
        choice = input("Выберите действие: ")

        if choice == "1":
            change_password(username)
        elif choice == "2":
            break
        else:
            print("Неверный ввод, попробуйте снова.")


# Главная функция
def main():
    username = login()
    if username == "ADMIN":
        admin_menu()
    else:
        user_menu(username)


if __name__ == "__main__":
    main()
