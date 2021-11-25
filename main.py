from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
import os
import json
import argparse
import pickle


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
    encrypted_symmetric_key = public_key.encrypt(symmetric_key.key,
                                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))
    with open(symmetric_key_path, 'wb') as key_file:
        key_file.write(encrypted_symmetric_key)


def encrypt_data(text_file: str, secret_key_path: str, encrypted_symmetric_key_path: str,
                 encrypted_text_file_path: str):
    with open(encrypted_symmetric_key_path, "rb") as file:
        encrypted_symmetric_key = file.read()
    with open(secret_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    with open(text_file, "r") as file:
        data = file.read()
    pad = padding2.ANSIX923(32).padder()
    text = bytes(data, 'UTF-8')
    padded_text = pad.update(text) + pad.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.Camellia(decrypted_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)
    encrypted_data = {"encrypted_text": c_text, "iv": iv}
    with open(encrypted_text_file_path, "wb") as file:
        pickle.dump(encrypted_data, file)


def decrypt_data(encrypted_text_file_path: str, secret_key_path: str, encrypted_symmetric_key_path: str,
                 decrypted_text_file_path: str):
    with open(encrypted_symmetric_key_path, "rb") as file:
        encrypted_symmetric_key = file.read()
    with open(secret_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    with open(encrypted_text_file_path, 'rb') as file:
        encrypted_text = pickle.load(file)
    text = encrypted_text['encrypted_text']
    iv = encrypted_text['iv']
    cipher = Cipher(algorithms.SM4(decrypted_symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(8).unpadder()
    unpadded_dc_data = unpadder.update(decrypted_text)
    final_text = unpadded_dc_data.decode('UTF-8')
    with open(decrypted_text_file_path, 'w') as file:
        file.write(final_text)


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')
args = parser.parse_args()
if args.generation is not None:
    with open('settings.json') as json_file:
        json_data = json.load(json_file)
    key_generator(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'])
if args.encryption is not None:
    with open('settings.json') as json_file:
        json_data = json.load(json_file)
    encrypt_data(json_data['initial_file'], json_data['secret_key'], json_data['symmetric_key'],
                 json_data['encrypted_file'])
if args.decryption is not None:
    with open('settings.json') as json_file:
        json_data = json.load(json_file)
    decrypt_data(json_data['encrypted_file'], json_data['secret_key'], json_data['symmetric_key'],
                 json_data['decrypted_file'])
