from Crypto.Cipher import PKCS1_v1_5
import socket

from Utils.symmanager import SymmetricCryptoManager

def send_all(conn : socket.socket ,data):
    #prepend length of data to message.
    data = bytes(str(len(data)) + "|",encoding="UTF-8") + data

    conn.sendall(data)

def send_all_encrypted(conn : socket.socket ,crypto : SymmetricCryptoManager,data : str):
    #encrypt data
    to_send = crypto.encrypt(data.encode("UTF-8"))
    send_all(conn,to_send)

def recv_all_unencrypted(conn : socket.socket):

    buffer = bytearray()

    part = conn.recv(4096)


    if not b'|' in part:
        return b'{}'

    split_at = part.index(b'|')
    msg_length = int(part[:split_at].decode("UTF-8"))
    part = part[split_at + 1:]

    while part:
        buffer.extend(part)

        if len(buffer) >= msg_length:
            break
        part = conn.recv(4096)
    
    return buffer

def recv_all_encrypted(conn : socket.socket, crypto : SymmetricCryptoManager):
    encrypted = recv_all_unencrypted(conn)
    unencrypted = crypto.decrypt(encrypted)
    return unencrypted


