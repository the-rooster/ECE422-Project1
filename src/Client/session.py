import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

#to load utils package
import sys
sys.path.append('../')

from Utils.asymmanager import AsymmetricCryptoManager
from Utils.symmanager import SymmetricCryptoManager
from Utils.messages import *

class Session():


    def __init__(self,conn : socket.socket):

        self.conn_crypto = AsymmetricCryptoManager("key.pem")
        self.conn = conn
        self.other_pub_key = None
        self.other_cipher = None


        if not self.key_exchange():
            print("SERVER SENT BAD PUBLIC KEY")

        self.handle()


        
    def key_exchange(self):
        print("BEGINNING KEY EXCHANGE")
        
        print("SENDING PUBLIC KEY")
        send_all(self.conn,self.conn_crypto.get_public_key())

        symmetric_key = recv_all_unencrypted(self.conn)
        symmetric_key = self.conn_crypto.decrypt(symmetric_key)
        print("SYMMETRIC KEY RECEIVED:\n", symmetric_key)

        self.symmetric_cipher = SymmetricCryptoManager(key=symmetric_key)
        
        print("BEGINNING ENCRYPTED COMMUNICATION")
        return True


    def handle(self):

        #begin message sharing with encryption
        while self.conn:

            inp = input(f"> ")
            send_all_encrypted(self.conn,self.symmetric_cipher,inp)
            #poc to check key exchange is working
            data = recv_all_encrypted(self.conn,self.symmetric_cipher).decode("UTF-8")
            print(data)
            


