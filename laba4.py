import random
import string
import matplotlib.pyplot as plt
import matplotlib.animation as animation


def generate_random_text(filename, length=2000):
    random_text = ''.join(random.choices(string.ascii_letters, k=length))
    with open(filename, "w", encoding="utf-8") as f:
        f.write(random_text)
    return filename


# Функция шифрования и дешифрования методом Цезаря
def caesar_cipher(text, shift, decrypt=False):
    result = ""
    if decrypt:
        shift = -shift  # Обратный сдвиг при дешифровании

    for char in text:
        if char.isalpha():  # Проверяем, является ли символ буквой
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)  # Смещение буквы в пределах алфавита
        else:
            result += char  # Оставляем символ без изменений

    return result


# Функция генерации квадрата Виженера
def generate_vigenere_square(orderly=True):
    alphabet = string.ascii_uppercase
    if not orderly:
        alphabet = ''.join(random.sample(alphabet, len(alphabet)))  # Перемешиваем алфавит, если нужно

    square = [[" "] + list(alphabet)]  # Заголовочная строка алфавита
    for i in range(26):
        square.append([alphabet[i]] + list(alphabet[i:] + alphabet[:i]))  # Заполняем таблицу сдвигами

    return square


# Функция шифрования и дешифрования методом Виженера
def vigenere_cipher(text, key, square, decrypt=False):
    key = key.upper()
    key_length = len(key)
    alphabet = square[0][1:]  # Получаем алфавит из первой строки квадрата
    result = ""

    for i, char in enumerate(text):
        if char.upper() in alphabet:
            row = alphabet.index(key[i % key_length]) + 1  # Определяем строку по ключу
            if decrypt:
                col = square[row][1:].index(char.upper()) + 1  # Определяем столбец по символу
                new_char = alphabet[col - 1]
            else:
                col = alphabet.index(char.upper()) + 1  # Определяем столбец по тексту
                new_char = square[row][col]
            result += new_char.lower() if char.islower() else new_char
        else:
            result += char  # Оставляем без изменений, если символ не буква

    return result


# Функция анимации квадрата Виженера с подсветкой процесса шифрования
def animate_vigenere_square_with_text(square, text, key):
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_title("Квадрат Виженера")

    # Строим таблицу квадрата Виженера
    table = ax.table(
        cellText=square,
        cellLoc='center',
        loc='center',
        cellColours=[["white"] * 27] + [["white"] + ["lightgray"] * 26 for _ in range(26)]
    )

    # Делаем заголовки строк и столбцов выделенными
    for i in range(27):
        for j in range(27):
            cell = table[i, j]
            cell.set_fontsize(12)
            if i == 0 or j == 0:
                cell.set_facecolor("lightblue")
                cell.set_fontsize(14)
                cell.set_text_props(weight="bold")

    # Функция обновления анимации
    def update(frame):
        i = frame
        if i < len(text):
            char = text[i]
            key_char = key[i % len(key)]  # Берем текущий символ ключа
            row = square[0].index(key_char)  # Определяем строку
            col = square[0].index(char.upper())  # Определяем столбец

            # Подсвечиваем строку и столбец
            for j in range(1, 27):
                table[j, col].set_facecolor("lightgray")
                table[row, j].set_facecolor("lightgray")

            # Подсвечиваем зашифрованный символ
            table[row, col].set_facecolor("red")

    # Запускаем анимацию
    ani = animation.FuncAnimation(fig, update, frames=len(text), interval=500, repeat=False)
    plt.show()


# Функция обработки файла с применением шифров
def process_file(filename, shift, key, orderly=True):
    with open(filename, "r", encoding="utf-8") as f:
        text = f.read()

    # Шифруем и дешифруем текст методом Цезаря
    caesar_encrypted = caesar_cipher(text, shift)
    with open(f"encC_{filename}", "w", encoding="utf-8") as f:
        f.write(caesar_encrypted)

    caesar_decrypted = caesar_cipher(caesar_encrypted, shift, decrypt=True)
    with open(f"decC_{filename}", "w", encoding="utf-8") as f:
        f.write(caesar_decrypted)

    # Генерация квадрата Виженера
    vigenere_square = generate_vigenere_square(orderly)

    # Запуск анимации шифрования Виженера
    animate_vigenere_square_with_text(vigenere_square, text, key)

    # Шифрование и дешифрование методом Виженера
    vigenere_encrypted = vigenere_cipher(text, key, vigenere_square)
    with open(f"encV_{filename}", "w", encoding="utf-8") as f:
        f.write(vigenere_encrypted)

    vigenere_decrypted = vigenere_cipher(vigenere_encrypted, key, vigenere_square, decrypt=True)
    with open(f"decV_{filename}", "w", encoding="utf-8") as f:
        f.write(vigenere_decrypted)

    # Вывод части данных для проверки
    print("Оригинальный текст:", text[:100])
    print("Шифр Цезаря (зашифрованный):", caesar_encrypted[:100])
    print("Шифр Цезаря (расшифрованный):", caesar_decrypted[:100])
    print("Шифр Виженера (зашифрованный):", vigenere_encrypted[:100])
    print("Шифр Виженера (расшифрованный):", vigenere_decrypted[:100])


filename = generate_random_text("example.txt", 2000)
process_file(filename, shift=3, key="AB", orderly=True)
