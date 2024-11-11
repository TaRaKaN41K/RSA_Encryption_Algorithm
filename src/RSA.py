import time

from constants import STANDARD_PUBLIC_EXHIBITOR, BLOCK_SIZE
from helpers import *


class RSA:
    def __init__(self):
        self.p: int = generate_prime_number()
        self.q: int = generate_prime_number()
        self.e: int = STANDARD_PUBLIC_EXHIBITOR

    # Генерация ключей
    def generate_keypair(self) -> tuple[tuple[int, int], tuple[int, int]]:
        p = self.p
        q = self.q

        while p == q:  # Убедимся, что p и q разные
            q = generate_prime_number()

        n: int = p * q
        phi: int = (p - 1) * (q - 1)
        d: int = multiplicative_inverse(number=self.e, module=phi)

        public_key: tuple[int, int] = (self.e, n)
        private_key: tuple[int, int] = (d, n)

        return public_key, private_key

    @staticmethod
    def pkcs7_padding(plaintext: bytes, block_size: int) -> bytes:
        padding_len = block_size - (len(plaintext) % block_size)
        padding = bytes([padding_len] * padding_len)
        return plaintext + padding

    @staticmethod
    def remove_pkcs7_padding(padded_message: bytes) -> bytes:
        padding_len = padded_message[-1]
        return padded_message[:-padding_len]

    # Шифрование
    def encrypt(self, public_key: tuple[int, int], plaintext: str, manual: bool = False, padding: bool = False) -> tuple[list[int], float]:
        e, n = public_key

        # Применяем padding к исходному сообщению
        plaintext = self.pkcs7_padding(plaintext.encode(), BLOCK_SIZE) if padding else plaintext.encode()

        # Шифруем каждый байт plaintext
        start_time: float = time.time()
        if manual:
            encrypted_message = [manual_exponentiation(byte, e, n) for byte in plaintext]
        else:
            encrypted_message = [fast_exponentiation(byte, e, n) for byte in plaintext]
        end_time: float = time.time()

        return encrypted_message, end_time - start_time

    # Расшифровка
    def decrypt(self, private_key: tuple[int, int], ciphertext: list[int], crt: bool = False, padding: bool = False) -> tuple[str, float]:
        d, n = private_key
        decrypted_bytes = []

        start_time: float = time.time()

        if crt:
            p, q = self.p, self.q
            for char in ciphertext:
                cp, cq = char % p, char % q
                m_p, m_q = pow(cp, d, p), pow(cq, d, q)
                q_inv = multiplicative_inverse(number=q, module=p)
                h = (q_inv * (m_p - m_q)) % p
                m = m_q + h * q
                decrypted_bytes.append(m % n)
        else:
            decrypted_bytes = [pow(char, d, n) for char in ciphertext]

        end_time: float = time.time()

        # Преобразуем результат в байты и удаляем padding
        decrypted_message_bytes = bytes(decrypted_bytes)
        plaintext_bytes = self.remove_pkcs7_padding(decrypted_message_bytes) if padding else decrypted_message_bytes
        plaintext = plaintext_bytes.decode()

        return plaintext, end_time - start_time
