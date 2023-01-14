import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

#to load utils package
import sys
sys.path.append('../')

from Utils.cryptomanager import CryptoManager
from Utils.messages import *

class Session():


    def __init__(self,conn : socket.socket):

        self.conn_crypto = CryptoManager("key.pem")
        self.conn = conn
        self.other_pub_key = None
        self.other_cipher = None

        self.user = "no-user"
        self.pwd = ""


        if not self.key_exchange():
            print("SERVER SENT BAD PUBLIC KEY")

        self.handle()


        
    def key_exchange(self):
        
        print("BEGINNING KEY EXCHANGE!")
        #receive server public key for communication
        public_key = recv_all_unencrypted(self.conn).decode("UTF-8")

        print("PUBLIC KEY RECEIVED: ")
        print(public_key)

        self.other_pub_key = RSA.import_key(public_key)

        if not self.other_pub_key.can_encrypt():
            return False

        self.other_cipher = PKCS1_v1_5.new(self.other_pub_key)

        print("SENDING PUBLIC KEY")
        send_all(self.conn,self.conn_crypto.get_public_key())
        
        print("BEGINNING ENCRYPTED COMMUNICATION")
        return True



    def handle(self):

        #begin message sharing with encryption
        while self.conn:

            inp = input(f"[{self.user}]@[{self.pwd}]> ")

            send_all_encrypted(self.conn,self.other_cipher,inp)
            #poc to check key exchange is working
            data = recv_all_encrypted(self.conn,self.conn_crypto)
            print(data)
            


