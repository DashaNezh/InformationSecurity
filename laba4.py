import random
import string
import matplotlib.pyplot as plt
import matplotlib.animation as animation


def generate_random_text(filename, length=2000):
    random_text = ''.join(random.choices(string.ascii_letters, k=length))
    with open(filename, "w", encoding="utf-8") as f:
        f.write(random_text)
    return filename


def caesar_cipher(text, shift, decrypt=False):
    result = ""
    if decrypt:
        shift = -shift

    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char

    return result


def generate_vigenere_square(orderly=True):
    alphabet = string.ascii_uppercase
    if not orderly:
        alphabet = ''.join(random.sample(alphabet, len(alphabet)))

    square = [[" "] + list(alphabet)]
    for i in range(26):
        square.append([alphabet[i]] + list(alphabet[i:] + alphabet[:i]))

    return square


def vigenere_cipher(text, key, square, decrypt=False):
    key = key.upper()
    key_length = len(key)
    alphabet = square[0][1:]  # Получаем алфавит из первой строки
    result = ""

    for i, char in enumerate(text):
        if char.upper() in alphabet:
            row = alphabet.index(key[i % key_length]) + 1
            if decrypt:
                col = square[row][1:].index(char.upper()) + 1
                new_char = alphabet[col - 1]
            else:
                col = alphabet.index(char.upper()) + 1
                new_char = square[row][col]
            result += new_char.lower() if char.islower() else new_char
        else:
            result += char

    return result


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

    # Делаем заголовки для строк и столбцов жирными и с другим цветом
    for i in range(27):
        for j in range(27):
            cell = table[i, j]
            cell.set_fontsize(12)
            if i == 0 or j == 0:
                cell.set_facecolor("lightblue")
                cell.set_fontsize(14)
                cell.set_text_props(weight="bold")

    # Делаем цикл по тексту, чтобы подсвечивать символы, которые шифруются
    def update(frame):
        i = frame
        if i < len(text):
            char = text[i]
            key_char = key[i % len(key)]  # Повторяем ключ по циклу
            row = square[0].index(key_char)  # Строка для ключа
            col = square[0].index(char.upper())  # Столбец для текущего символа текста

            # Подсвечиваем строку и столбец, где происходит шифрование
            for j in range(1, 27):
                if j <= 26:
                    table[j, col].set_facecolor("lightgray")  # Подсвечиваем столбец
                    table[row, j].set_facecolor("lightgray")  # Подсвечиваем строку

            # Подсвечиваем сам символ в таблице, который мы шифруем
            encrypted_char = square[row][col]
            table[row, col].set_facecolor("red")

    # Запускаем анимацию
    ani = animation.FuncAnimation(fig, update, frames=len(text), interval=500, repeat=False)
    plt.show()


def process_file(filename, shift, key, orderly=True):
    with open(filename, "r", encoding="utf-8") as f:
        text = f.read()

    caesar_encrypted = caesar_cipher(text, shift)
    with open(f"encC_{filename}", "w", encoding="utf-8") as f:
        f.write(caesar_encrypted)

    caesar_decrypted = caesar_cipher(caesar_encrypted, shift, decrypt=True)
    with open(f"decC_{filename}", "w", encoding="utf-8") as f:
        f.write(caesar_decrypted)

    # Генерация квадрата Виженера
    vigenere_square = generate_vigenere_square(orderly)

    # Запуск анимации с текстом и ключом
    animate_vigenere_square_with_text(vigenere_square, text, key)

    vigenere_encrypted = vigenere_cipher(text, key, vigenere_square)
    with open(f"encV_{filename}", "w", encoding="utf-8") as f:
        f.write(vigenere_encrypted)

    vigenere_decrypted = vigenere_cipher(vigenere_encrypted, key, vigenere_square, decrypt=True)
    with open(f"decV_{filename}", "w", encoding="utf-8") as f:
        f.write(vigenere_decrypted)

    print("Оригинальный текст:", text[:100])
    print("Шифр Цезаря (зашифрованный):", caesar_encrypted[:100])
    print("Шифр Цезаря (расшифрованный):", caesar_decrypted[:100])
    print("Шифр Виженера (зашифрованный):", vigenere_encrypted[:100])
    print("Шифр Виженера (расшифрованный):", vigenere_decrypted[:100])


# Генерация файла и его обработка
filename = generate_random_text("example.txt", 2000)
process_file(filename, shift=3, key="KEY", orderly=True)