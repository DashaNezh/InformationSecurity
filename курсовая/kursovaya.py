import base64
import os
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import qrcode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from PyPDF2 import PdfReader, PdfWriter
import binascii

# Конфигурация
SALT = b'salt_123'
ITERATIONS = 100_000


class PDFSteganographer:
    def __init__(self, password):
        self.password = password
        self.key = self._generate_key(password)

    def _generate_key(self, password):
        """Генерация ключа на основе пароля."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def hide_data(self, input_pdf, output_pdf, secret_message):
        """Упрощенная функция скрытия данных в метаданных."""
        try:
            # Шифруем сообщение
            encrypted_msg = self.key.encrypt(secret_message.eЫncode())

            # Читаем PDF
            reader = PdfReader(input_pdf)
            writer = PdfWriter()

            # Копируем все страницы
            for page in reader.pages:
                writer.add_page(page)

            # Добавляем зашифрованные данные в метаданные
            writer.add_metadata({
                '/Creator': 'PDF Steganography',
                '/HiddenData': binascii.hexlify(encrypted_msg).decode()
            })

            # Сохраняем PDF с паролем
            with open(output_pdf, 'wb') as f:
                writer.encrypt(self.password, use_128bit=True)
                writer.write(f)

            return True
        except Exception as e:
            print(f"Ошибка при скрытии данных: {str(e)}")
            return False

    def extract_data(self, secret_pdf):
        """Извлечение данных с обработкой Base64 ключа."""
        try:
            reader = PdfReader(secret_pdf)
            if reader.is_encrypted:
                reader.decrypt(self.password)

            # Проверяем метаданные
            if hasattr(reader, 'metadata') and reader.metadata:
                encrypted_hex = reader.metadata.get('/HiddenData', '')
                if encrypted_hex:
                    encrypted_msg = binascii.unhexlify(encrypted_hex)

                    # Декодируем Base64 ключ при извлечении
                    if hasattr(self.key, '_signing_key'):
                        key_b64 = base64.b64encode(self.key._signing_key).decode('ascii')
                        return f"Ключ: {key_b64}\nСообщение: {self.key.decrypt(encrypted_msg).decode()}"

                    return self.key.decrypt(encrypted_msg).decode()

            return "❌ Скрытые данные не найдены"
        except Exception as e:
            return f"❌ Ошибка при извлечении: {str(e)}"

    def _generate_qrcode(self):
        """Генерация QR-кода с ключом в Base64."""
        try:
            # Получаем бинарные данные ключа
            key_bytes = self.key._signing_key

            # Кодируем в Base64 для безопасного представления
            key_b64 = base64.b64encode(key_bytes).decode('ascii')

            # Создаем QR-код
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(key_b64)
            qr.make(fit=True)

            # Создаем временный файл
            temp_dir = tempfile.gettempdir()
            qr_path = os.path.join(temp_dir, f"pdf_steg_qr_{os.getpid()}.png")

            # Сохраняем изображение
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(qr_path)

            return qr_path

        except Exception as e:
            print(f"[Ошибка генерации QR] {type(e).__name__}: {str(e)}")
            return None

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Steganography Pro")
        self.root.geometry("700x600")

        # Стиль
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=("Arial", 10))
        self.style.configure("TLabel", font=("Arial", 11))

        # Переменные
        self.input_pdf_var = tk.StringVar()
        self.output_pdf_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.message_var = tk.StringVar()

        # GUI элементы
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

        ttk.Label(input_frame, text="Пароль:").grid(row=2, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.password_var, show="*", width=40).grid(row=2, column=1)

        ttk.Label(input_frame, text="Сообщение:").grid(row=3, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.message_var, width=40).grid(row=3, column=1)

        # Кнопки действий
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Спрятать данные", command=self.hide_data).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Извлечь данные", command=self.extract_data).grid(row=0, column=1, padx=5)

        # Область для QR-кода
        self.qr_frame = ttk.LabelFrame(self.root, text="Ключ для расшифровки", padding=10)
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
        if not all([self.input_pdf_var.get(), self.output_pdf_var.get(),
                    self.password_var.get(), self.message_var.get()]):
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        try:
            stego = PDFSteganographer(self.password_var.get())
            if stego.hide_data(self.input_pdf_var.get(),
                               self.output_pdf_var.get(),
                               self.message_var.get()):
                self.status_var.set("✅ Данные успешно скрыты!")

                # Генерируем и показываем QR-код
                qr_path = stego._generate_qrcode()
                if qr_path:
                    # Сохраняем путь к QR-коду как атрибут класса
                    self.current_qr_path = qr_path
                    self.show_qrcode(qr_path)
                else:
                    messagebox.showwarning("Внимание", "QR-код не был создан")
            else:
                messagebox.showerror("Ошибка", "Не удалось скрыть данные")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось спрятать данные: {str(e)}")

    def extract_data(self):
        if not all([self.input_pdf_var.get(), self.password_var.get()]):
            messagebox.showerror("Ошибка", "Укажите PDF и пароль!")
            return

        try:
            stego = PDFSteganographer(self.password_var.get())
            result = stego.extract_data(self.input_pdf_var.get())

            if result.startswith("❌"):
                messagebox.showerror("Ошибка", result)
            else:
                messagebox.showinfo("Результат", f"Извлеченные данные:\n\n{result}")
                self.status_var.set("🔍 Данные извлечены!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось извлечь данные: {str(e)}")

    def show_qrcode(self, path):
        """Улучшенное отображение QR-кода с сохранением файла."""
        try:
            # Очищаем предыдущий QR-код
            for widget in self.qr_frame.winfo_children():
                widget.destroy()

            # Проверяем существование файла
            if not os.path.exists(path):
                raise FileNotFoundError(f"Файл {path} не найден")

            # Загружаем изображение
            img = Image.open(path)
            if not img:
                raise ValueError("Не удалось загрузить изображение")

            # Масштабируем
            max_size = (300, 300)
            img.thumbnail(max_size, Image.LANCZOS)

            # Конвертируем для Tkinter
            photo = ImageTk.PhotoImage(img)

            # Создаем элементы интерфейса
            label = ttk.Label(self.qr_frame, image=photo)
            label.image = photo  # сохраняем ссылку
            label.pack(pady=5)

            # Добавляем текст-описание
            ttk.Label(
                self.qr_frame,
                text="Сохраните этот QR-код для расшифровки",
                font=('Arial', 9)
            ).pack()

            # Кнопка сохранения
            ttk.Button(
                self.qr_frame,
                text="Сохранить QR-код",
                command=lambda: self.save_qrcode_image(path)
            ).pack(pady=5)

        except Exception as e:
            error_msg = f"Ошибка отображения QR-кода: {str(e)}"
            ttk.Label(
                self.qr_frame,
                text=error_msg,
                foreground='red'
            ).pack()
            print(error_msg)

    def save_qrcode_image(self, source_path):
        """Сохранение QR-кода с проверкой существования файла."""
        try:
            if not os.path.exists(source_path):
                raise FileNotFoundError("Исходный файл QR-кода не найден")

            dest_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
                title="Сохранить QR-код как..."
            )

            if dest_path:
                import shutil
                shutil.copy(source_path, dest_path)
                messagebox.showinfo("Успех", f"QR-код сохранен в:\n{dest_path}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить QR-код: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()