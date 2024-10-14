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

# Configurações do servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))  # Bind na porta 65432
server_socket.listen(1)
print("Servidor ouvindo na porta 65432...")

# Chave secreta (deve ser a mesma que o cliente)
key = b'0123456789abcdef0123456789abcdef'  # Chave de 256 bits (32 bytes)

while True:
    conn, addr = server_socket.accept()  # Aceitar conexão do cliente
    print(f"Conexão estabelecida com: {addr}")
    
    # Receber mensagem do cliente
    data = conn.recv(1024)
    print(f"Recebido do cliente: {data}")
    
    # Descriptografar a mensagem recebida
    decrypted_message = decrypt_message(key, data)
    print(f"Mensagem descriptografada: {decrypted_message.decode()}")
    
    # Enviar resposta criptografada
    response = "Olá cliente, sua conexão é segura!".encode()
    encrypted_response = encrypt_message(key, response.decode())
    conn.sendall(encrypted_response)

    # Fechar a conexão após processar a mensagem
    conn.close()
    print("Conexão encerrada.")
