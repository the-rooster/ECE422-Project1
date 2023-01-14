from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import socket
import base64

#to load utils package
import sys
sys.path.append('../')

from Utils.cryptomanager import CryptoManager
from Utils.messages import *
from authenticator import Authenticator


class SecureFileSystemServer():

    def __init__(self):
        
        #master key for file encryption
        self.file_crypto = CryptoManager("master_key.pem")

        #key for communication
        self.conn_crypto = CryptoManager()

        #user authentication
        self.authenticator = Authenticator()
    

    def handle_conn(self,conn : socket.socket):

        
        print("SENDING PUBLIC KEY!: ")
        print(self.conn_crypto.get_public_key())

        #send public key first
        send_all(conn,self.conn_crypto.get_public_key())

        print("PUBLIC KEY SENT")

        #receive client public key
        public_key_client = recv_all_unencrypted(conn).decode("UTF-8")

        print("PUBLIC KEY RECEIVED: ")
        print(public_key_client)

        
        #verify key integrity and make cipher object
        pub_key = RSA.import_key(public_key_client)

        if not pub_key.can_encrypt():
            conn.sendall("Public Key Invalid\n")
            conn.close()
            return
        
        cipher = PKCS1_v1_5.new(RSA.import_key(public_key_client))

        print("BEGINNING ENCRYPTED COMMUNICATION!")
        #begin message sharing with encryption
        while conn:

            #poc to check key exchange is working
            data = recv_all_encrypted(conn,self.conn_crypto).decode("UTF-8")
            print("CLIENT SENT:\n")
            print(data)
            print()

            send_all_encrypted(conn,cipher,data)





    

        

    
        