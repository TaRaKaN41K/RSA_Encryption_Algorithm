from RSA import RSA


if __name__ == '__main__':

    rsa = RSA()

    # Пример использования
    public_key, private_key = rsa.generate_keypair()
    print(
        f"\nОткрытый ключ:                                   {public_key}",
        f"\nЗакрытый ключ:                                   {private_key}"
    )

    message = "Привет, Я Калашов Феодор Олегович N33481"

    print("\n\nБЕЗ ДОПОЛНЕНИЯ\n")

    # Шифруем сообщение
    encrypted_msg, encrypted_time = rsa.encrypt(public_key=public_key, plaintext=message)

    print(
        f"\nЗашифрованное сообщение:                         {''.join([hex(num)[2:] for num in encrypted_msg])}"
        f"\nВремя выполнения encrypt:                        {encrypted_time}"
    )

    encrypted_msg, encrypted_time = rsa.encrypt(public_key=public_key, plaintext=message, manual=True)

    print(
        f"\nЗашифрованное сообщение:                         {''.join([hex(num)[2:] for num in encrypted_msg])}"
        f"\nВремя выполнения encrypt manual:                 {encrypted_time}"
    )

    # Расшифровываем сообщение
    decrypted_msg, decrypted_time = rsa.decrypt(private_key=private_key, ciphertext=encrypted_msg)
    print(
        f"\nРасшифрованное сообщение:                        {''.join(decrypted_msg)}"
        f"\nВремя выполнения decrypt:                        {decrypted_time}"
    )

    decrypted_msg, decrypted_time = rsa.decrypt(private_key=private_key, ciphertext=encrypted_msg, crt=True)
    print(
        f"\nРасшифрованное сообщение (с использованием CRT): {''.join(decrypted_msg)}"
        f"\nВремя выполнения decrypt (с использованием CRT): {decrypted_time}"
    )

    print("\n\nС ДОПОЛНЕНИЕМ\n")

    # Шифруем сообщение с дополнением
    encrypted_msg, encrypted_time = rsa.encrypt(public_key=public_key, plaintext=message, padding=True)

    print(
        f"\nЗашифрованное сообщение:                         {''.join([hex(num)[2:] for num in encrypted_msg])}"
        f"\nВремя выполнения encrypt:                        {encrypted_time}"
    )

    encrypted_msg, encrypted_time = rsa.encrypt(public_key=public_key, plaintext=message, manual=True, padding=True)

    print(
        f"\nЗашифрованное сообщение:                         {''.join([hex(num)[2:] for num in encrypted_msg])}"
        f"\nВремя выполнения encrypt manual:                 {encrypted_time}"
    )

    # Расшифровываем сообщение с дополнением
    decrypted_msg, decrypted_time = rsa.decrypt(private_key=private_key, ciphertext=encrypted_msg, padding=True)
    print(
        f"\nРасшифрованное сообщение:                        {''.join(decrypted_msg)}"
        f"\nВремя выполнения decrypt:                        {decrypted_time}"
    )

    decrypted_msg, decrypted_time = rsa.decrypt(private_key=private_key, ciphertext=encrypted_msg, crt=True, padding=True)
    print(
        f"\nРасшифрованное сообщение (с использованием CRT): {''.join(decrypted_msg)}"
        f"\nВремя выполнения decrypt (с использованием CRT): {decrypted_time}"
    )
