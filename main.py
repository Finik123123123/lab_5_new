

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import socket
import os


#Создадим функции для генерации ключей и обмена ими:


def generate_dh_params(size):
    params = dh.generate_parameters(generator=2, key_size=size, backend=default_backend())
    return params

def generate_dh_key_pair(params):
    private_key = params.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def exchange_keys(client_public_key, server_private_key):
    shared_key = server_private_key.exchange(client_public_key)
    return shared_key

def derive_key(shared_key, salt, info, length=32):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    key = kdf.derive(shared_key)
    return key


#Теперь создадим сервер и клиент:

#Сервер:


def server():
    size = 2048
    server_params = generate_dh_params(size)
    server_private_key, server_public_key = generate_dh_key_pair(server_params)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Server is listening...")
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr}")

    client_public_key_pem = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(
        client_public_key_pem,
        backend=default_backend()
    )

    shared_key = exchange_keys(client_public_key, server_private_key)
    salt = os.urandom(16)
    info = b"handshake info"
    key = derive_key(shared_key, salt, info)

    # Используем ключ для шифрования и дешифрования сообщений
    # ...

    client_socket.close()
    server_socket.close()

if __name__ == "main":
    server()


#Клиент:


def client():
    size = 2048
    client_params = generate_dh_params(size)
    client_private_key, client_public_key = generate_dh_key_pair(client_params)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(client_public_key_pem)

    server_public_key_pem = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem,
        backend=default_backend()
    )

    shared_key = exchange_keys(server_public_key, client_private_key)
    salt = os.urandom(16)
    info = b"handshake info"
    key = derive_key(shared_key, salt, info)

    # Используем ключ для шифрования и дешифрования сообщений
    # ...

    client_socket.close()

if __name__ == "main":
    client()