from tkinter import *
from tkinter import Tk, messagebox, filedialog
import tkinter as tk
import tkinter.font as tkFont
import sqlite3
import re
import bcrypt

def create_user_table():
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    connection.commit()
    connection.close()
def validate_data(data):
    return re.match("^[a-zA-Z0-9]+$", data) is not None

def is_valid_length(data):
    return len(data) > 4

def is_field_empty(data):
    if not data:
        return True
    return False
def check_existing_username(username):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    connection.close()
    return result is not None
def register_user(window_login):
    def process_registration():
        username = entry_username.get()
        password = entry_password.get()
        confirm_password = entry_confirm_password.get()

        if is_field_empty(username) or is_field_empty(password):
            messagebox.showerror("Ошибка", "Необходимо заполнить все поля")
            return

        if not validate_data(username) or not validate_data(password):
            messagebox.showerror("Ошибка", "Используйте только английские буквы и цифры без пробелов.")
            return

        if not is_valid_length(username) or not is_valid_length(password):
            messagebox.showerror("Ошибка", "Логин и пароль должны быть длиннее 4 символов.")
            return

        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают. Попробуйте еще раз.")
            return

        if check_existing_username(username):
            messagebox.showerror("Ошибка", "Пользователь с таким логином уже существует.")
            return

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        connection = sqlite3.connect("users.db")
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users VALUES (?, ?)", (username, hashed_password))
        connection.commit()
        connection.close()
        messagebox.showinfo("Регистрация", "Регистрация прошла успешно!")
        registration_window.destroy()

    registration_window = tk.Toplevel(window_login)
    registration_window.resizable(False, False)
    registration_window.title("Регистрация")
    width1 = 300
    height1 = 200
    screen_width1 = registration_window.winfo_screenwidth()
    screen_height1 = registration_window.winfo_screenheight()
    x_coord1 = (screen_width1 / 2) - (width1 / 2)
    y_coord1 = (screen_height1 / 2) - (height1 / 2)
    registration_window.geometry('%dx%d+%d+%d' % (width1, height1, x_coord1, y_coord1))

    tk.Label(registration_window, text="Имя пользователя:").pack()
    entry_username = tk.Entry(registration_window)
    entry_username.pack()

    tk.Label(registration_window, text="Пароль:").pack()
    entry_password = tk.Entry(registration_window, show="*")
    entry_password.pack()

    tk.Label(registration_window, text="Подтвердите пароль:").pack()
    entry_confirm_password = tk.Entry(registration_window, show="*")
    entry_confirm_password.pack()

    tk.Button(registration_window, text="Зарегистрироваться", command=process_registration).pack()
def login_user():
    username = entry_username.get()
    password = entry_password.get()
    if is_field_empty(username) or is_field_empty(password):
        lbl_status.config(text="Необходимо заполнить все поля")
        return

    if not validate_data(username) or not validate_data(password):
        lbl_status.config(text="Используйте только английские буквы и цифры\nбез пробелов.")
        return

    if not is_valid_length(username) or not is_valid_length(password):
        lbl_status.config(text="Логин и пароль должны быть\n длиннее 4 символов.")
        return

    if not check_existing_username(username):
        lbl_status.config(text="Пользователя с таким логином не существует.")
        return
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user is not None and bcrypt.checkpw(password.encode(), user[1]):
        lbl_status.config(text="Вход выполнен успешно")
        shifr()
    else:
        lbl_status.config(text="Введены неверные данные")
    connection.close()

def vigenere_cipher(text, keyword, decrypt=False):
    alphabet = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
    key_length = len(keyword.replace(' ', ''))
    key_int = [alphabet.index(letter.lower()) for letter in keyword.replace(' ', '').lower()]
    result = ''
    space_indices = [i for i in range(len(text)) if text[i] == ' ']
    j = 0
    for i in range(len(text)):
        if text[i] in alphabet or text[i].lower() in alphabet:
            is_upper = text[i].isupper()
            letter = text[i].lower()
            if decrypt:
                letter_index = (alphabet.index(letter) - key_int[j % key_length]) % len(alphabet)
                result += alphabet[letter_index].upper() if is_upper else alphabet[letter_index]
                j += 1
            else:
                letter_index = (alphabet.index(letter) + key_int[j % key_length]) % len(alphabet)
                result += alphabet[letter_index].upper() if is_upper else alphabet[letter_index]
                j += 1
        else:
            result += text[i]
            if text[i] == ' ' and i + 1 < len(text) and text[i + 1] in alphabet:
                result += ' '  # Добавляем пробел только если следующий символ - буква
    return result
def shifr():
    def is_valid_input(text):
        valid_characters = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя.,;:!\? '
        for char in text:
            if char.lower() not in valid_characters:
                return False
        return True

    def encrypt_text():
        keyword = keyword_entry.get()
        input_text = input_textbox.get(1.0, tk.END).strip()
        if is_field_empty(input_text) or is_field_empty(keyword):
            messagebox.showerror("Ошибка", "Необходимо заполнить все поля")
            return
        if not is_valid_input(input_text) or not is_valid_input(keyword):
            messagebox.showerror("Ошибка", "Вводите только русские буквы")
            return
        result = vigenere_cipher(input_text, keyword)
        output_textbox.configure(state=tk.NORMAL)
        output_textbox.delete(1.0, tk.END)
        output_textbox.insert(1.0, result)
        output_textbox.configure(state=tk.DISABLED)

    def decrypt_text():
        keyword = keyword_entry.get()
        input_text = input_textbox.get(1.0, tk.END).strip()
        if is_field_empty(input_text) or is_field_empty(keyword):
            messagebox.showerror("Ошибка", "Необходимо заполнить все поля")
            return
        if not is_valid_input(input_text) or not is_valid_input(keyword):
            messagebox.showerror("Ошибка", "Вводите только русские буквы")
            return
        result = vigenere_cipher(input_text, keyword, decrypt=True)
        output_textbox.configure(state=tk.NORMAL)
        output_textbox.delete(1.0, tk.END)
        output_textbox.insert(1.0, result)
        output_textbox.configure(state=tk.DISABLED)

    def save_to_file_dialog(text):
        if is_field_empty(text.strip()):
            messagebox.showerror("Ошибка", "Поле с результатом шифрования пусто")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(text)

    def clear_output_textbox():
        output_textbox.configure(state=tk.NORMAL)
        output_textbox.delete(1.0, tk.END)
        output_textbox.configure(state=tk.DISABLED)

    window_login.destroy()
    vigenere = tk.Tk()
    vigenere.resizable(False, False)
    vigenere.title("Шифр Виженера")
    vigenere.configure(bg="#F0FFFF")
    font_style2 = tkFont.Font(family="Calibri", size=16, weight="bold")
    font_style3 = tkFont.Font(family="David", size=14)
    screen_width1 = vigenere.winfo_screenwidth()
    screen_height1 = vigenere.winfo_screenheight()
    window_width = 530
    window_height = 400
    x_coord = (screen_width1 / 2) - (window_width / 2)
    y_coord = (screen_height1 / 2) - (window_height / 2)
    vigenere.geometry("%dx%d+%d+%d" % (window_width, window_height, x_coord, y_coord))
    input_label = tk.Label(vigenere, text="Исходный текст:", font=font_style2, bg="#F0FFFF")
    input_textbox = tk.Text(vigenere, height=5, width=29, font=font_style3, state=tk.NORMAL)
    keyword_label = tk.Label(vigenere, text="Ключ:", font=font_style2, bg="#F0FFFF")
    keyword_entry = tk.Entry(vigenere, font=font_style3)
    keyword_entry.configure(width=29)
    encrypt_button = tk.Button(vigenere, text="Зашифровать", command=encrypt_text, font=font_style3)
    encrypt_button.configure(height=1, width=13)
    output_label = tk.Label(vigenere, text="Результат:", font=font_style2, bg="#F0FFFF")
    output_textbox = tk.Text(vigenere, height=5, width=29, state=tk.NORMAL, font=font_style3)
    decrypt_button = tk.Button(vigenere, text="Расшифровать", command=decrypt_text, font=font_style3)
    decrypt_button.configure(height=1, width=13)
    input_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
    input_textbox.grid(row=0, column=1, padx=5, pady=5, columnspan=2, sticky="w")
    keyword_label.grid(row=1, column=0, padx=55, pady=5, sticky="w")
    keyword_entry.grid(row=1, column=1, padx=5, pady=5, columnspan=2, sticky="w")
    encrypt_button.grid(row=2, column=1, padx=5, pady=5, sticky="e")
    decrypt_button.grid(row=2, column=2, padx=5, pady=5, sticky="w")
    output_label.grid(row=3, column=0, padx=40, pady=5, sticky="w")
    output_textbox.grid(row=3, column=1, padx=5, pady=5, columnspan=2, sticky="w")
    btn_save = tk.Button(vigenere, text="Сохранить в файл",
                      command=lambda: save_to_file_dialog(output_textbox.get(1.0, tk.END)), font=font_style3)
    btn_save.configure(height=1, width=15)
    btn_save.grid(row=4, column=1, padx=5, pady=5, columnspan=2, sticky="w")

    clear_button = tk.Button(vigenere, text="Очистить", command=clear_output_textbox, font=font_style3)
    clear_button.configure(height=1, width=13)
    clear_button.grid(row=4, column=2, padx=20, pady=5, sticky="w")

    vigenere.mainloop()


if __name__ == "__main__":
    create_user_table()
    window_login = Tk()
    window_login.resizable(False, False)
    window_login.title("Регистрация и авторизация")
    font_style = tkFont.Font(family="Arial", size=14, weight= "bold")
    font_style1 = tkFont.Font(family="Arial", size=11, weight= "bold")
    window_login.configure(bg= '#79CDCD')
    bg_color = '#79CDCD'
    button_color = '#3D59AB'
    label_color = '#292421'
    width = 400
    height = 340
    screen_width = window_login.winfo_screenwidth()
    screen_height = window_login.winfo_screenheight()
    x_coord = (screen_width/2) - (width/2)
    y_coord= (screen_height/2) - (height/2)
    window_login.geometry('%dx%d+%d+%d' % (width, height, x_coord, y_coord))
    lbl_username = Label(window_login, text="Имя пользователя:", bg=bg_color, fg=label_color, font=font_style)
    lbl_username.pack(padx=20, pady=10)
    entry_username = Entry(window_login, font=font_style)
    entry_username.pack(padx=20, pady=5)
    lbl_password = Label(window_login, text="Пароль:", bg=bg_color, fg=label_color, font=font_style)
    lbl_password.pack(padx=20, pady=10)
    entry_password = Entry(window_login, show="*", font=font_style)
    entry_password.pack(padx=20, pady=5)
    btn_register = Button(window_login, text="Зарегистрироваться", command=lambda: register_user(window_login),
                              bg=button_color,
                              font=font_style, fg='white')
    btn_register.pack(padx=20, pady=10)
    btn_login = Button(window_login, text="Войти", command=login_user, bg=button_color, font=font_style, fg='white')
    btn_login.pack(padx=20, pady=5)
    lbl_status = Label(window_login, text="", bg=bg_color, fg=label_color, font=font_style1)
    lbl_status.pack(padx=20, pady=10)
    window_login.mainloop()