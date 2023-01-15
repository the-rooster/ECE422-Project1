from Crypto.Cipher import PKCS1_v1_5
import socket

from Utils.cryptomanager import CryptoManager

def send_all(conn : socket.socket ,data):
    #prepend length of data to message.
    data = bytes(str(len(data)) + "|",encoding="UTF-8") + data

    conn.sendall(data)

def send_all_encrypted(conn : socket.socket ,crypto : CryptoManager,data):
    #encrypt data
    data = crypto.encrypt(bytes(data,encoding="UTF-8"))

    send_all(conn,data)

def recv_all_unencrypted(conn : socket.socket):

    buffer = bytearray()

    part = conn.recv(4096)

    split_at = part.index(b'|')
    msg_length = int(part[:split_at].decode("UTF-8"))
    part = part[split_at + 1:]

    while part:
        buffer.extend(part)

        if len(buffer) >= msg_length:
            break
        part = conn.recv(4096)
    
    return buffer

def recv_all_encrypted(conn : socket.socket, crypto : CryptoManager):
    return crypto.decrypt(recv_all_unencrypted(conn))


