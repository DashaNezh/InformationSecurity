import base64
import os
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import qrcode
from PyPDF2 import PdfReader, PdfWriter
import random


# Упрощённая реализация RSA
class SimpleRSA:
    def __init__(self, key_size=512):
        # Генерация простых чисел
        p = self._generate_prime(key_size)
        q = self._generate_prime(key_size)

        self.n = p * q
        phi = (p - 1) * (q - 1)

        self.e = 65537
        self.d = self._modinv(self.e, phi)  # Вычисление обратного элемента

        self.public_key = (self.e, self.n)
        self.private_key = (self.d, self.n)

    def _generate_prime(self, bits):
        """Генерация простого числа"""
        while True:
            num = random.getrandbits(bits)
            if num > 1 and self._is_prime(num):
                return num

    def _is_prime(self, n, k=5):
        """Проверка на простоту (тест Миллера-Рабина)"""
        if n <= 1:
            return False
        elif n <= 3:
            return True

        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _modinv(self, a, m):
        """Поиск обратного элемента по модулю"""
        g, x, y = self._extended_gcd(a, m)
        if g != 1:
            raise ValueError('Обратный элемент не существует')
        return x % m

    def _extended_gcd(self, a, b):
        """Расширенный алгоритм Евклида"""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self._extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def encrypt(self, text):
        """Шифрование с обработкой больших чисел"""
        encrypted = []
        for c in text:
            m = ord(c)
            if m >= self.n:  # Проверка, что число меньше модуля
                raise ValueError("Символ вне диапазона RSA")
            encrypted.append(str(pow(m, self.e, self.n)))
        return ' '.join(encrypted)

    def decrypt(self, encrypted_text):
        """Дешифрование с обработкой больших чисел"""
        decrypted = []
        for num in encrypted_text.split():
            try:
                m = pow(int(num), self.d, self.n)
                decrypted.append(chr(m))
            except ValueError:
                decrypted.append('�')  # Символ замены при ошибке
        return ''.join(decrypted)

class PDFSteganographer:
    def __init__(self, password=None, rsa_key_size=64):
        self.password = password
        self.rsa = SimpleRSA(rsa_key_size)

    def _int_to_b64(self, number: int) -> str:
        """Конвертирует большое число в Base64 строку"""
        bytes_data = number.to_bytes((number.bit_length() + 7) // 8, 'big')
        return base64.b64encode(bytes_data).decode('utf-8')

    def _b64_to_int(self, b64_str: str) -> int:
        """Конвертирует Base64 строку обратно в число"""
        bytes_data = base64.b64decode(b64_str.encode('utf-8'))
        return int.from_bytes(bytes_data, 'big')

    def hide_data(self, input_pdf, output_pdf, secret_message):
        """Скрытие данных в PDF с паролем"""
        try:
            encrypted_msg = self.rsa.encrypt(secret_message)

            # Читаем PDF
            reader = PdfReader(input_pdf)
            writer = PdfWriter()

            # Копируем страницы
            for page in reader.pages:
                writer.add_page(page)

            # Добавляем метаданные
            writer.add_metadata({
                '/HiddenData': encrypted_msg,
                '/RSA_n': self._int_to_b64(self.rsa.n),  # n в Base64
                '/RSA_e': str(self.rsa.e),  # e маленькое, можно как строку
                '/RSA_d': self._int_to_b64(self.rsa.d)  #
            })
            """d в Base64 (но это небезопасно, но из-за ошибки "Python int too large to convert to C int" пришлось 
            сделать через base64)"""

            # Защищаем PDF паролем (если задан)
            with open(output_pdf, 'wb') as f:
                if self.password:
                    writer.encrypt(self.password)
                writer.write(f)

            return True
        except Exception as e:
            print(f"Ошибка при скрытии данных: {str(e)}")
            return False

    def extract_data(self, secret_pdf):
        try:
            reader = PdfReader(secret_pdf)
            if reader.is_encrypted:
                if not self.password:
                    return "❌ Файл защищён паролем"
                reader.decrypt(self.password)

            if hasattr(reader, 'metadata'):
                encrypted_msg = reader.metadata.get('/HiddenData', '')
                if encrypted_msg:
                    # Восстанавливаем ключи из Base64
                    n = self._b64_to_int(reader.metadata['/RSA_n'])
                    e = int(reader.metadata['/RSA_e'])
                    d = self._b64_to_int(reader.metadata['/RSA_d'])  # Теперь d читается без ошибок

                    temp_rsa = SimpleRSA()
                    temp_rsa.n = n
                    temp_rsa.e = e
                    temp_rsa.d = d

                    return temp_rsa.decrypt(encrypted_msg)
        except Exception as e:
            return f"❌ Ошибка: {str(e)}"

    def _generate_qrcode(self):
        """Генерация QR-кода с приватным ключом"""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(f"RSA Private Key (d,n): {self.rsa.d},{self.rsa.n}")
            qr.make(fit=True)

            temp_dir = tempfile.gettempdir()
            qr_path = os.path.join(temp_dir, f"pdf_steg_qr_{os.getpid()}.png")

            img = qr.make_image(fill_color="black", back_color="white")
            img.save(qr_path)
            return qr_path
        except Exception as e:
            print(f"[Ошибка генерации QR] {type(e).__name__}: {str(e)}")
            return None


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Steganography (RSA)")
        self.root.geometry("700x600")

        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=("Arial", 10))
        self.style.configure("TLabel", font=("Arial", 11))

        self.input_pdf_var = tk.StringVar()
        self.output_pdf_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.message_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        # Фрейм для ввода
        input_frame = ttk.LabelFrame(self.root, text="Параметры", padding=10)
        input_frame.pack(pady=10, padx=10, fill="x")

        # Поля ввода
        ttk.Label(input_frame, text="Исходный PDF:").grid(row=0, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.input_pdf_var, width=40).grid(row=0, column=1)
        ttk.Button(input_frame, text="Обзор", command=self.browse_input).grid(row=0, column=2)

        ttk.Label(input_frame, text="Выходной PDF:").grid(row=1, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.output_pdf_var, width=40).grid(row=1, column=1)
        ttk.Button(input_frame, text="Обзор", command=self.browse_output).grid(row=1, column=2)

        ttk.Label(input_frame, text="Пароль PDF:").grid(row=2, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.password_var, show="*", width=40).grid(row=2, column=1)

        ttk.Label(input_frame, text="Сообщение:").grid(row=3, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.message_var, width=40).grid(row=3, column=1)

        # Кнопки действий
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Спрятать данные", command=self.hide_data).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Извлечь данные", command=self.extract_data).grid(row=0, column=1, padx=5)

        # Область для QR-кода
        self.qr_frame = ttk.LabelFrame(self.root, text="Приватный ключ (RSA)", padding=10)
        self.qr_frame.pack(pady=10, fill="both", expand=True)

        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        ttk.Label(self.root, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", padx=10, pady=5)

    def browse_input(self):
        filename = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if filename:
            self.input_pdf_var.set(filename)

    def browse_output(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if filename:
            self.output_pdf_var.set(filename)

    def hide_data(self):
        if not all([self.input_pdf_var.get(), self.output_pdf_var.get(), self.message_var.get()]):
            messagebox.showerror("Ошибка", "Заполните все обязательные поля!")
            return

        try:
            stego = PDFSteganographer(self.password_var.get() or None)
            if stego.hide_data(self.input_pdf_var.get(),
                               self.output_pdf_var.get(),
                               self.message_var.get()):
                self.status_var.set("✅ Данные успешно скрыты!")

                # Показываем QR-код с приватным ключом
                qr_path = stego._generate_qrcode()
                if qr_path:
                    self.current_qr_path = qr_path
                    self.show_qrcode(qr_path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось скрыть данные: {str(e)}")

    def extract_data(self):
        if not self.input_pdf_var.get():
            messagebox.showerror("Ошибка", "Укажите PDF файл!")
            return

        try:
            # Передаём пароль из интерфейса
            stego = PDFSteganographer(self.password_var.get() or None)
            result = stego.extract_data(self.input_pdf_var.get())

            if result.startswith("❌"):
                messagebox.showerror("Ошибка", result)
            else:
                messagebox.showinfo("Результат", f"Извлеченные данные:\n\n{result}")
                self.status_var.set("🔍 Данные извлечены!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось извлечь данные: {str(e)}")

    def show_qrcode(self, path):
        """Отображение QR-кода"""
        try:
            for widget in self.qr_frame.winfo_children():
                widget.destroy()

            img = Image.open(path)
            img.thumbnail((300, 300), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)

            label = ttk.Label(self.qr_frame, image=photo)
            label.image = photo
            label.pack(pady=5)

            ttk.Label(self.qr_frame, text="Приватный ключ RSA").pack()

            ttk.Button(
                self.qr_frame,
                text="Сохранить QR-код",
                command=lambda: self.save_qrcode_image(path)
            ).pack(pady=5)
        except Exception as e:
            ttk.Label(self.qr_frame, text=f"Ошибка: {str(e)}", foreground="red").pack()

    def save_qrcode_image(self, path):
        """Сохранение QR-кода"""
        try:
            dest_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )
            if dest_path:
                import shutil
                shutil.copy(path, dest_path)
                messagebox.showinfo("Успех", f"QR-код сохранён в:\n{dest_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()