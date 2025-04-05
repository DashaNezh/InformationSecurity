import os
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import qrcode
from PyPDF2 import PdfReader, PdfWriter


class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift

    def encrypt(self, text, shift=None):
        """Шифрование текста с поддержкой русского и английского алфавитов"""
        shift = self.shift if shift is None else shift
        result = []
        for char in text:
            if 'А' <= char <= 'Я':
                base = ord('А')
                result.append(chr((ord(char) - base + shift) % 32 + base))
            elif 'а' <= char <= 'я':
                base = ord('а')
                result.append(chr((ord(char) - base + shift) % 32 + base))
            elif 'A' <= char <= 'Z':
                base = ord('A')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            elif 'a' <= char <= 'z':
                base = ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)

    def decrypt(self, text):
        """Дешифрование текста (используем отрицательный сдвиг)"""
        return self.encrypt(text, -self.shift)

class PDFSteganographer:
    def __init__(self, shift=3):
        self.shift = shift
        self.cipher = CaesarCipher(shift)

    def hide_data(self, input_pdf, output_pdf, secret_message):
        """Скрытие данных в метаданных PDF"""
        try:
            encrypted_msg = self.cipher.encrypt(secret_message)

            reader = PdfReader(input_pdf)
            writer = PdfWriter()

            for page in reader.pages:
                writer.add_page(page)

            writer.add_metadata({
                '/Creator': 'PDF Steganography',
                '/HiddenData': encrypted_msg,
                '/ShiftKey': str(self.shift)
            })

            with open(output_pdf, 'wb') as f:
                writer.write(f)

            return True
        except Exception as e:
            print(f"Ошибка при скрытии данных: {str(e)}")
            return False

    def extract_data(self, secret_pdf):
        """Извлечение данных из PDF"""
        try:
            reader = PdfReader(secret_pdf)

            if hasattr(reader, 'metadata') and reader.metadata:
                encrypted_msg = reader.metadata.get('/HiddenData', '')
                shift = int(reader.metadata.get('/ShiftKey', '3'))

                if encrypted_msg:
                    cipher = CaesarCipher(shift)
                    return cipher.decrypt(encrypted_msg)  # Используем decrypt вместо encrypt с отрицательным сдвигом

            return "❌ Скрытые данные не найдены"
        except Exception as e:
            return f"❌ Ошибка при извлечении: {str(e)}"

    def _generate_qrcode(self):
        """Генерация QR-кода с ключом"""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(f"Ключ Цезаря: {self.shift}")
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
        self.root.title("PDF Steganography (Caesar Cipher)")
        self.root.geometry("700x600")

        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=("Arial", 10))
        self.style.configure("TLabel", font=("Arial", 11))

        self.input_pdf_var = tk.StringVar()
        self.output_pdf_var = tk.StringVar()
        self.shift_var = tk.IntVar(value=3)
        self.message_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        input_frame = ttk.LabelFrame(self.root, text="Параметры", padding=10)
        input_frame.pack(pady=10, padx=10, fill="x")

        ttk.Label(input_frame, text="Исходный PDF:").grid(row=0, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.input_pdf_var, width=40).grid(row=0, column=1)
        ttk.Button(input_frame, text="Обзор", command=self.browse_input).grid(row=0, column=2)

        ttk.Label(input_frame, text="Выходной PDF:").grid(row=1, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.output_pdf_var, width=40).grid(row=1, column=1)
        ttk.Button(input_frame, text="Обзор", command=self.browse_output).grid(row=1, column=2)

        ttk.Label(input_frame, text="Сдвиг (ключ):").grid(row=2, column=0, sticky="w")
        ttk.Spinbox(input_frame, from_=1, to=31, textvariable=self.shift_var, width=5).grid(row=2, column=1, sticky="w")

        ttk.Label(input_frame, text="Сообщение:").grid(row=3, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.message_var, width=40).grid(row=3, column=1)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Спрятать данные", command=self.hide_data).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Извлечь данные", command=self.extract_data).grid(row=0, column=1, padx=5)

        self.qr_frame = ttk.LabelFrame(self.root, text="Ключ для расшифровки", padding=10)
        self.qr_frame.pack(pady=10, fill="both", expand=True)

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
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        try:
            stego = PDFSteganographer(self.shift_var.get())
            if stego.hide_data(self.input_pdf_var.get(), self.output_pdf_var.get(), self.message_var.get()):
                self.status_var.set("✅ Данные успешно скрыты!")
                qr_path = stego._generate_qrcode()
                if qr_path:
                    self.current_qr_path = qr_path
                    self.show_qrcode(qr_path)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось спрятать данные: {str(e)}")

    def extract_data(self):
        if not self.input_pdf_var.get():
            messagebox.showerror("Ошибка", "Укажите PDF файл!")
            return

        try:
            stego = PDFSteganographer(self.shift_var.get())
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

            ttk.Label(self.qr_frame, text="Сохраните этот QR-код").pack()

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