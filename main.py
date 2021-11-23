from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import hashes
import os
import json
import argparse


def key_selection() -> int:
    print("Выберите длину ключа:")
    print("1. 128 бит")
    print("2. 192 бит")
    print("3. 256 бит")
    print("Ваш выбор:")
    choice = input()
    while int(choice) != 1 and int(choice) != 2 and int(choice) != 3:
        os.system('cls')
        print("Выберите длину ключа:")
        print("1. 128 бит")
        print("2. 192 бит")
        print("3. 256 бит")
        print("Ваш выбор:", end=" ")
        choice = input()
    if int(choice) == 1:
        return 128
    if int(choice) == 2:
        return 192
    if int(choice) == 3:
        return 256


def key_generator(symmetric_key_path: str, public_key_path: str, secret_key_path: str):
    symmetric_key = algorithms.Camellia(os.urandom(int(key_selection() / 8)))
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    with open(public_key_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(secret_key_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))


'''parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
args = parser.parse_args()
if args.generation is not None:
# генерируем ключи
else if args.encryption is not None:
# шифруем
else:
# дешифруем'''
with open('settings.json') as json_file:
    json_data = json.load(json_file)
key_generator(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'])
