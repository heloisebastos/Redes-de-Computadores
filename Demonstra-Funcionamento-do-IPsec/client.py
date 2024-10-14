import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Função para criptografar dados
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext  # Retorna o IV junto com o texto criptografado

# Função para descriptografar dados
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Configurações do cliente
key = b'0123456789abcdef0123456789abcdef'  # Chave de 256 bits (32 bytes)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))  # Conectar ao servidor

# Enviar mensagem criptografada
message = "Olá servidor!"
encrypted_message = encrypt_message(key, message)
print(f"Mensagem criptografada (cliente): {encrypted_message}")

client_socket.sendall(encrypted_message)

# Receber resposta do servidor
data = client_socket.recv(1024)

# Imprimir a resposta criptografada
print(f"Resposta criptografada (servidor): {data}")

# Descriptografar a resposta do servidor
decrypted_response = decrypt_message(key, data)
print(f"Resposta do servidor (descriptografada): {decrypted_response.decode()}")

client_socket.close()
