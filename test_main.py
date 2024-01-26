import unittest
from unittest.mock import patch
from tkinter import Tk
from main import create_user_table, validate_data, is_valid_length, is_field_empty, check_existing_username, register_user, login_user, shifr, vigenere_cipher

class TestValidateData(unittest.TestCase):
    def test_valid_data(self):
        self.assertTrue(validate_data("username123"))

    def test_invalid_data(self):
        self.assertFalse(validate_data("user name"))
        self.assertFalse(validate_data("user@name"))

class TestIsValidLength(unittest.TestCase):
    def test_valid_length(self):
        self.assertTrue(is_valid_length("abcde"))

    def test_invalid_length(self):
        self.assertFalse(is_valid_length("abc"))
        self.assertFalse(is_valid_length("12"))

class TestCheckExistingUsername(unittest.TestCase):
    def test_existing_username(self):
        self.assertFalse(check_existing_username("existing_user"))

    def test_non_existing_username(self):
        self.assertFalse(check_existing_username("non_existing_user"))

class TestRegistrationFunctions(unittest.TestCase):

    def test_check_existing_username(self):
        window_login = Tk()
        window_login.title("Авторизация")
        window_login.resizable(False, False)

        create_user_table()
        self.assertFalse(check_existing_username("NonExistingUser"))
        register_user(window_login)
        self.assertFalse(check_existing_username("ValidUser"))

        window_login.destroy()

class TestVigenereCipher(unittest.TestCase):

    def test_vigenere_cipher_encryption(self):
        text = "привет,мир!"
        keyword = "ключ"
        encrypted_text = vigenere_cipher(text, keyword)
        decrypted_text = vigenere_cipher(encrypted_text, keyword, decrypt=True)
        self.assertEqual(encrypted_text, "ъьжщпю,каы!")
        self.assertEqual(decrypted_text, text)

if __name__ == '__main__':
    unittest.main()

