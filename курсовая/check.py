import tkinter as tk
from tkinter import filedialog, messagebox
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import NameObject, DecodedStreamObject
import re


class PdfSteganoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Стеганография")

        self.input_pdf_path = tk.StringVar()
        self.output_pdf_path = tk.StringVar()
        self.message_text = tk.StringVar()
        self.mode = tk.IntVar(value=1)

        self.create_widgets()

    def create_widgets(self):
        mode_frame = tk.LabelFrame(self.root, text="Режим работы", padx=5, pady=5)
        mode_frame.pack(padx=10, pady=5, fill="x")

        tk.Radiobutton(mode_frame, text="Зашифровать сообщение", variable=self.mode, value=1,
                       command=self.toggle_mode).pack(anchor="w")
        tk.Radiobutton(mode_frame, text="Расшифровать сообщение", variable=self.mode, value=2,
                       command=self.toggle_mode).pack(anchor="w")

        input_frame = tk.LabelFrame(self.root, text="Исходный PDF", padx=5, pady=5)
        input_frame.pack(padx=10, pady=5, fill="x")

        tk.Entry(input_frame, textvariable=self.input_pdf_path, width=50).pack(side="left", padx=5)
        tk.Button(input_frame, text="Обзор", command=self.browse_input_pdf).pack(side="left")

        self.message_frame = tk.LabelFrame(self.root, text="Сообщение", padx=5, pady=5)
        self.message_frame.pack(padx=10, pady=5, fill="x")

        tk.Entry(self.message_frame, textvariable=self.message_text, width=50).pack(side="left", padx=5)

        self.output_frame = tk.LabelFrame(self.root, text="Куда сохранить PDF", padx=5, pady=5)
        self.output_frame.pack(padx=10, pady=5, fill="x")

        tk.Entry(self.output_frame, textvariable=self.output_pdf_path, width=50).pack(side="left", padx=5)
        tk.Button(self.output_frame, text="Обзор", command=self.browse_output_pdf).pack(side="left")

        self.execute_button = tk.Button(self.root, text="Выполнить", command=self.execute)
        self.execute_button.pack(pady=10)

        self.toggle_mode()

    def toggle_mode(self):
        if self.mode.get() == 1:
            self.message_frame.pack()
            self.output_frame.pack()
            self.execute_button.config(text="Зашифровать и сохранить")
        else:
            self.message_frame.pack_forget()
            self.output_frame.pack_forget()
            self.execute_button.config(text="Расшифровать сообщение")

    def browse_input_pdf(self):
        filename = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if filename:
            self.input_pdf_path.set(filename)

    def browse_output_pdf(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if filename:
            self.output_pdf_path.set(filename)

    def execute(self):
        if self.mode.get() == 1:
            self.encode_message()
        else:
            self.decode_message()

    def encode_message(self):
        input_pdf = self.input_pdf_path.get()
        output_pdf = self.output_pdf_path.get()
        message = self.message_text.get()

        if not all([input_pdf, output_pdf, message]):
            messagebox.showerror("Ошибка", "Заполните все поля!")
            return

        try:
            binary_msg = ''.join(format(ord(c), '08b') for c in message) + '00000000'
            print(f"[DEBUG] Бинарное сообщение: {binary_msg}")
            reader = PdfReader(input_pdf)
            writer = PdfWriter()
            bit_index = 0

            for page in reader.pages:
                if '/Contents' in page:
                    contents = page['/Contents']
                    content_obj = contents.get_object()
                    content_data = self._safe_decode(content_obj.get_data())
                    print("[DEBUG] Содержимое страницы:\n", content_data[:1000])

                    def insert_color(match):
                        nonlocal bit_index
                        if bit_index < len(binary_msg):
                            bit = binary_msg[bit_index]
                            bit_index += 1
                            color = '0 0 0 rg\n' if bit == '0' else '1 0 0 rg\n'
                            print(f"[DEBUG] Вставка цвета для бита {bit}: {color.strip()}")
                            return color + match.group(0)
                        return match.group(0)

                    modified_data = re.sub(
                        r'(\[(?:\([^\)]*\)|<[^>]*>)[^\]]*\]\s*TJ|\([^\)]*\)\s*Tj)',
                        insert_color,
                        content_data
                    )
                    print(f"[DEBUG] Всего вставлено бит: {bit_index}")

                    new_stream = DecodedStreamObject()
                    new_stream.set_data(modified_data.encode('latin-1'))
                    page[NameObject('/Contents')] = new_stream

                writer.add_page(page)

            with open(output_pdf, 'wb') as f:
                writer.write(f)

            print(f"[DEBUG] Всего вставлено бит: {bit_index}")
            messagebox.showinfo("Успех", "Сообщение зашифровано в цвет текста!")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")

    def decode_message(self):
        input_pdf = self.input_pdf_path.get()

        if not input_pdf:
            messagebox.showerror("Ошибка", "Выберите PDF файл!")
            return

        try:
            binary_msg = []
            reader = PdfReader(input_pdf)

            for page_num, page in enumerate(reader.pages):
                if '/Contents' in page:
                    contents = page['/Contents']
                    content_bytes = self._get_content_bytes(contents)
                    content_str = self._safe_decode(content_bytes)

                    print(f"[DEBUG] Страница {page_num + 1}: поиск цветовых команд...")
                    for match in re.finditer(r'(\d+(?:\.\d+)? \d+(?:\.\d+)? \d+(?:\.\d+)?) rg', content_str):
                        color_str = match.group(1)
                        print(f"[DEBUG] Найден цвет: {color_str}")
                        try:
                            r, g, b = map(float, color_str.split())
                            if r == 0.0 and g == 0.0 and b == 0.0:
                                binary_msg.append('0')
                            elif r == 1.0 and g == 0.0 and b == 0.0:
                                binary_msg.append('1')
                        except ValueError as e:
                            print(f"[DEBUG] Ошибка преобразования цвета: {color_str}, {e}")

            # Восстановление сообщения из бинарных данных
            message = []
            for i in range(0, len(binary_msg), 8):
                byte = binary_msg[i:i + 8]
                if len(byte) == 8:
                    char = chr(int(''.join(byte), 2))
                    if char == '\x00':
                        break
                    message.append(char)

            result = ''.join(message)
            print(f"[DEBUG] Декодированное сообщение: {result}")
            messagebox.showinfo("Результат", f"Сообщение: {result}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при расшифровке: {str(e)}")

    def _get_content_bytes(self, contents):
        if isinstance(contents, list):
            return b''.join([self._get_single_content(x) for x in contents])
        return self._get_single_content(contents)

    def _get_single_content(self, content):
        if hasattr(content, 'get_data'):
            return content.get_data()
        elif isinstance(content, (bytes, bytearray)):
            return content
        elif isinstance(content, str):
            return content.encode('latin-1', errors='replace')
        return bytes(content)

    def _safe_decode(self, content_bytes):
        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
        for encoding in encodings:
            try:
                return content_bytes.decode(encoding)
            except UnicodeDecodeError:
                continue
        return content_bytes.decode('latin-1', errors='replace')


if __name__ == "__main__":
    root = tk.Tk()
    app = PdfSteganoApp(root)
    root.mainloop()