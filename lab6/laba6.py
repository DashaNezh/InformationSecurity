import re
from math import gcd
from collections import defaultdict, Counter
import matplotlib.pyplot as plt

RUSSIAN_CHARS = "абвгдежзийклмнопрстуфхцчшщъыьэюя"
CHAR_COUNT = len(RUSSIAN_CHARS)  # 32 буквы

CAESAR_OFFSET = 3
VIGENERE_CODE = "рбн"


def load_text(file_path):
    """Загружает текст из файла в кодировке UTF-8."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def save_text(file_path, content):
    """Сохраняет текст в файл в кодировке UTF-8."""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def filter_text(content):
    """Очищает текст, оставляя только буквы русского алфавита."""
    content = content.lower().replace("ё", "е")
    return ''.join(c for c in content if c in RUSSIAN_CHARS)


def analyze_chars(text):
    """Считает частоту букв в тексте."""
    text = text.lower().replace("ё", "е")
    char_counts = Counter(c for c in text if c in RUSSIAN_CHARS)
    total_chars = sum(char_counts.values())
    char_freqs = {c: count / total_chars for c, count in char_counts.items()}
    return char_counts, char_freqs


def analyze_bigrams(text):
    """Считает частоту биграмм в тексте."""
    text = text.lower().replace("ё", "е")
    bigrams = [text[i:i + 2] for i in range(len(text) - 1) if text[i] in RUSSIAN_CHARS and text[i + 1] in RUSSIAN_CHARS]
    bigram_counts = Counter(bigrams)
    total_bigrams = sum(bigram_counts.values())
    bigram_freqs = {bg: count / total_bigrams for bg, count in bigram_counts.items()}
    return bigram_freqs


def detect_doubles(bigram_freqs):
    """Находит биграммы из одинаковых букв."""
    return {bg: freq for bg, freq in bigram_freqs.items() if bg[0] == bg[1]}


def display_freq_table(char_counts, char_freqs):
    """Выводит таблицу частот букв."""
    print("\nЧастота букв в тексте:")
    print(f"{'Символ':<6} | {'Вероятность':<12}")
    print("=" * 22)
    sorted_freqs = sorted(char_freqs.items(), key=lambda x: x[1], reverse=True)
    for char, freq in sorted_freqs:
        count = char_counts.get(char, 0)
        print(f"{char:<6} | {freq:.4f}")
    for char in RUSSIAN_CHARS:
        if char not in char_freqs:
            print(f"{char:<6} | {0:.4f}")
    return sorted_freqs


def draw_char_graph(char_freqs):
    """Строит график для топ-10 букв."""
    top_freqs = sorted(char_freqs.items(), key=lambda x: x[1], reverse=True)[:10]
    chars = [x[0] for x in top_freqs]
    freqs = [x[1] for x in top_freqs]

    plt.figure(figsize=(6, 4))
    plt.bar(chars, freqs, color='purple')
    plt.title("Топ-10 букв по частоте")
    plt.xlabel("Буквы")
    plt.ylabel("Частота")
    plt.show()


def draw_bigram_graph(bigram_freqs):
    """Строит график для топ-10 биграмм."""
    top_freqs = sorted(bigram_freqs.items(), key=lambda x: x[1], reverse=True)[:10]
    bigrams = [x[0] for x in top_freqs]
    freqs = [x[1] for x in top_freqs]

    plt.figure(figsize=(6, 4))
    plt.bar(bigrams, freqs, color='orange')
    plt.title("Топ-10 биграмм по частоте")
    plt.xlabel("Биграммы")
    plt.ylabel("Частота")
    plt.show()


def apply_caesar(text, offset):
    """Шифрует или дешифрует текст шифром Цезаря.

    Логика работы:
    Шифр Цезаря сдвигает каждую букву текста на фиксированное количество позиций в алфавите.
    Например, при сдвиге 3 буква 'а' становится 'г', 'б' — 'д' и т.д. Для дешифрования используется
    отрицательный сдвиг. Программа:
    1. Приводит каждую букву к нижнему регистру и заменяет 'ё' на 'е'.
    2. Если символ — буква алфавита, находит её индекс в RUSSIAN_CHARS.
    3. Вычисляет новый индекс: (текущий_индекс + сдвиг) % длина_алфавита.
    4. Получает новую букву по новому индексу, сохраняя регистр (верхний/нижний).
    5. Небуквенные символы остаются без изменений.
    6. Собирает результат в строку.

    Args:
        text (str): Входной текст для шифрования/дешифрования.
        offset (int): Сдвиг (положительный для шифрования, отрицательный для дешифрования).

    Returns:
        str: Зашифрованный или расшифрованный текст.
    """
    result = []
    for c in text:
        c_lower = c.lower().replace("ё", "е")
        if c_lower in RUSSIAN_CHARS:
            idx = RUSSIAN_CHARS.index(c_lower)
            new_idx = (idx + offset) % CHAR_COUNT
            new_char = RUSSIAN_CHARS[new_idx]
            result.append(new_char.upper() if c.isupper() else new_char)
        else:
            result.append(c)
    return ''.join(result)


def guess_caesar_offset(sorted_freqs, ref_freqs):
    """Определяет сдвиг шифра Цезаря через частотный анализ.

    Логика работы:
    Шифр Цезаря сохраняет частотность букв: если 'о' — самая частая буква в русском языке,
    то в зашифрованном тексте другая буква (например, 'р' при сдвиге 3) будет самой частой.
    Программа:
    1. Берёт 3 самые частые буквы зашифрованного текста (из sorted_freqs).
    2. Сравнивает их с 3 самыми частыми буквами эталонного текста (из ref_freqs).
    3. Для каждой пары (зашифрованная буква, эталонная буква) вычисляет сдвиг:
       сдвиг = (индекс_зашифрованной_буквы - индекс_эталонной_буквы) % длина_алфавита.
    4. Собирает все возможные сдвиги в список.
    5. Выбирает наиболее часто встречающийся сдвиг как наиболее вероятный.
    6. Если сдвигов нет, возвращает 0.

    Args:
        sorted_freqs (list): Частоты букв зашифрованного текста, отсортированные по убыванию.
        ref_freqs (dict): Эталонные частоты букв.

    Returns:
        int: Предполагаемый сдвиг шифра Цезаря.
    """
    top_chars = [c for c, _ in sorted_freqs[:3]]
    ref_top = sorted(ref_freqs.items(), key=lambda x: x[1], reverse=True)[:3]
    ref_top_chars = [c for c, _ in ref_top]

    offsets = []
    for enc_c in top_chars:
        enc_idx = RUSSIAN_CHARS.index(enc_c)
        for ref_c in ref_top_chars:
            ref_idx = RUSSIAN_CHARS.index(ref_c)
            offset = (enc_idx - ref_idx) % CHAR_COUNT
            offsets.append(offset)

    return Counter(offsets).most_common(1)[0][0] if offsets else 0


def apply_vigenere(text, key, decrypt=False, keep_non_alpha=False):
    """Шифрует или дешифрует текст шифром Виженера.

    Логика работы:
    Шифр Виженера использует ключ (слово), где каждая буква ключа задаёт сдвиг для
    соответствующей буквы текста, как в шифре Цезаря. Ключ повторяется, пока не покроет весь текст.
    Для дешифрования сдвиги берутся с обратным знаком. Программа:
    1. Очищает ключ, оставляя только буквы алфавита, и преобразует его в индексы букв.
    2. Для каждой буквы текста:
       - Если это буква алфавита, вычисляет сдвиг из ключа (ключ циклически повторяется).
       - Для шифрования: новый_индекс = (индекс_буквы + индекс_буквы_ключа) % длина_алфавита.
       - Для дешифрования: новый_индекс = (индекс_буквы - индекс_буквы_ключа) % длина_алфавита.
       - Сохраняет регистр (верхний/нижний).
    3. Если keep_non_alpha=True, небуквенные символы (пробелы, знаки) сохраняются.
    4. Собирает результат в строку.

    Args:
        text (str): Входной текст.
        key (str): Ключ для шифрования/дешифрования.
        decrypt (bool): Если True, выполняется дешифрование.
        keep_non_alpha (bool): Если True, сохраняются небуквенные символы.

    Returns:
        str: Зашифрованный или расшифрованный текст.
    """
    result = []
    key_clean = ''.join(c for c in key.lower().replace("ё", "е") if c in RUSSIAN_CHARS)
    key_indices = [RUSSIAN_CHARS.index(c) for c in key_clean]
    key_pos = 0

    for c in text:
        c_lower = c.lower().replace("ё", "е")
        if c_lower in RUSSIAN_CHARS:
            shift = (-key_indices[key_pos % len(key_indices)] if decrypt else key_indices[key_pos % len(key_indices)])
            new_char = RUSSIAN_CHARS[(RUSSIAN_CHARS.index(c_lower) + shift) % CHAR_COUNT]
            result.append(new_char.upper() if c.isupper() else new_char)
            key_pos += 1
        elif keep_non_alpha:
            result.append(c)
    return ''.join(result)


def estimate_key_length(cipher_text, max_key_len=20):
    """Определяет длину ключа шифра Виженера методом Фридмана.

    Логика работы:
    Шифр Виженера разбивает текст на группы, где каждая группа шифруется одной буквой ключа.
    Если длина ключа правильная, буквы в каждой группе имеют частотность, близкую к русскому языку
    (индекс совпадения ~0.055). Программа:
    1. Очищает текст, оставляя только буквы алфавита.
    2. Для каждой предполагаемой длины ключа (от 2 до max_key_len):
       - Разбивает текст на группы: 1-я буква ключа шифрует символы 1, 1+key_len, 1+2*key_len и т.д.
       - Для каждой группы вычисляет индекс совпадения (IC):
         IC = Σ(n*(n-1))/(N*(N-1)), где n — частота буквы, N — длина группы.
       - Усредняет IC по всем группам.
    3. Сравнивает средний IC с ожидаемым для русского языка (0.055).
    4. Если разница меньше порога (0.01), добавляет длину ключа в кандидаты.
    5. Выбирает наименьшую длину ключа с минимальной разницей IC.

    Args:
        cipher_text (str): Зашифрованный текст.
        max_key_len (int): Максимальная длина ключа для проверки.

    Returns:
        int: Наиболее вероятная длина ключа.
    """
    clean_text = filter_text(cipher_text)

    def calc_ic(text):
        freqs = Counter(text)
        n = len(text)
        if n < 2:
            return 0
        return sum(v * (v - 1) for v in freqs.values()) / (n * (n - 1))

    target_ic = 0.055
    ic_tolerance = 0.01
    key_len_candidates = []

    for key_len in range(2, max_key_len + 1):
        ic_total = 0
        for i in range(key_len):
            group = clean_text[i::key_len]
            if len(group) > 1:
                ic_total += calc_ic(group)
        avg_ic = ic_total / key_len if key_len > 0 else 0
        ic_diff = abs(avg_ic - target_ic)
        if ic_diff < ic_tolerance:
            key_len_candidates.append((key_len, ic_diff))

    key_len_candidates.sort(key=lambda x: (x[0], x[1]))
    print(f"Вероятная длина ключа: {key_len_candidates[0][0]}")
    return key_len_candidates[0][0]


def estimate_vigenere_key(cipher_text, key_len, ref_freqs):
    """Подбирает ключ шифра Виженера через частотный анализ.

    Логика работы:
    Каждая буква ключа шифрует свою группу букв текста (1-я буква — 1, 1+key_len, ...; 2-я — 2, 2+key_len, ...).
    Если сдвинуть группу на правильное значение, частоты букв станут похожи на эталонные (русский язык).
    Программа:
    1. Очищает зашифрованный текст, оставляя только буквы.
    2. Для каждой позиции ключа (от 0 до key_len-1):
       - Берёт группу букв, шифрованных этой буквой ключа.
       - Пробует все возможные сдвиги (0..31) для группы.
       - Для каждого сдвига:
         - Дешифрует группу (сдвиг назад).
         - Считает частоты букв в дешифрованной группе.
         - Сравнивает частоты с эталонными (ref_freqs), вычисляя сумму абсолютных разностей.
       - Выбирает сдвиг с минимальной разностью (наиболее похожий на русский язык).
       - Преобразует сдвиг в букву ключа (индекс_сдвига → буква из RUSSIAN_CHARS).
    3. Собирает буквы в ключ.

    Args:
        cipher_text (str): Зашифрованный текст.
        key_len (int): Длина ключа.
        ref_freqs (dict): Эталонные частоты букв.

    Returns:
        str: Предполагаемый ключ.
    """
    clean_cipher = filter_text(cipher_text)
    key_chars = []

    for i in range(key_len):
        group = clean_cipher[i::key_len]
        best_offset = 0
        min_diff = float('inf')

        for offset in range(CHAR_COUNT):
            shifted = [RUSSIAN_CHARS[(RUSSIAN_CHARS.index(c) - offset) % CHAR_COUNT] for c in group]
            freqs = Counter(shifted)
            total = sum(freqs.values())
            diff = sum(abs((freqs.get(c, 0) / total) - ref_freqs.get(c, 0)) for c in RUSSIAN_CHARS)

            if diff < min_diff:
                min_diff = diff
                best_offset = offset

        key_chars.append(RUSSIAN_CHARS[best_offset])
    return ''.join(key_chars)


if __name__ == "__main__":
    # Загружаем эталонный текст
    try:
        base_text = load_text("text.txt")
    except FileNotFoundError:
        print("Файл text.txt не найден!")
        exit(1)

    # Анализ эталонного текста
    _, base_freqs = analyze_chars(base_text)
    char_counts, char_freqs = analyze_chars(base_text)
    sorted_freqs = display_freq_table(char_counts, char_freqs)

    print("\nСамые частые буквы (топ-10):")
    for c, f in sorted_freqs[:10]:
        print(f"{c}: {f:.4f}")

    bigram_freqs = analyze_bigrams(base_text)
    print("\nСамые частые биграммы (топ-10):")
    for bg, f in sorted(bigram_freqs.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{bg}: {f:.4f}")

    double_bigrams = detect_doubles(bigram_freqs)
    print("\nСамые частые удвоения (топ-10):")
    for bg, f in sorted(double_bigrams.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{bg}: {f:.4f}")

    draw_char_graph(char_freqs)
    draw_bigram_graph(bigram_freqs)

    # Обработка шифрованных текстов
    files_to_process = ["text_Caesar.txt", "text_Vigenere.txt"]
    for file in files_to_process:
        print(f"\nАнализ файла: {file}")
        try:
            content = load_text(file)
        except FileNotFoundError:
            print(f"Файл {file} не найден!")
            continue

        if "Caesar" in file:
            encrypted = apply_caesar(content, CAESAR_OFFSET)
            out_file = f"caesar_enc_{file.split('.')[0]}.txt"
        else:
            encrypted = apply_vigenere(content, VIGENERE_CODE, decrypt=False, keep_non_alpha=True)
            out_file = f"vigenere_enc_{file.split('.')[0]}.txt"

        save_text(out_file, encrypted)

        print("\nПервые 150 символов:")
        print(f"Исходный: {content[:150]}")
        print(f"Зашифрованный: {encrypted[:150]}")

        # Частотный анализ зашифрованного текста
        enc_counts, enc_freqs = analyze_chars(encrypted)
        enc_sorted_freqs = display_freq_table(enc_counts, enc_freqs)

        # Криптоанализ
        if "Caesar" in file:
            print("\nАнализ шифра Цезаря:")
            offset = guess_caesar_offset(enc_sorted_freqs, base_freqs)
            print(f"Сдвиг: {offset}")
            decrypted = apply_caesar(encrypted, -offset)
            print(f"Расшифровано: {decrypted[:150]}")
        else:
            print("\nАнализ шифра Виженера:")
            key_len = estimate_key_length(encrypted)
            key = estimate_vigenere_key(encrypted, key_len, base_freqs)
            print(f"Ключ: {key}")
            decrypted = apply_vigenere(encrypted, key, decrypt=True, keep_non_alpha=True)
            print(f"Расшифровано: {decrypted[:150]}")