from Crypto.Cipher import PKCS1_v1_5
import socket

from Utils.cryptomanager import CryptoManager

def send_all(conn : socket.socket ,data):
    #prepend length of data to message.
    data = bytes(str(len(data)) + "|",encoding="UTF-8") + data

    conn.sendall(data)

def send_all_encrypted(conn : socket.socket ,crypto : CryptoManager,data):
    #encrypt data
    to_send = bytearray()

    for i in range(0,len(data),100):
        chunk = data[i:min(i + 100,len(data))]
        to_send.extend(b'|CHUNK|')
        to_send.extend(crypto.encrypt(bytes(chunk,encoding="UTF-8")))

    send_all(conn,to_send)

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
    encrypted = recv_all_unencrypted(conn)
    unencrypted = bytearray()
    for chunk in encrypted.split(b'|CHUNK|'):
        if chunk:
            unencrypted.extend(crypto.decrypt(chunk))

    return unencrypted


