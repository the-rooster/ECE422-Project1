from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

class CryptoManager():

    def __init__(self,filename : str = None,key : str = None):

        #if filename is specified (premade key stored in file), or create new key if it can't be found
        if filename:
            #import keys, or create keys if they aren't provided
            if os.path.exists(filename):
                with open(filename,"rb") as f:
                    self.private_key = RSA.import_key(f.read())
            else:
                self.private_key = RSA.generate(2048)
                with open(filename,"wb") as f:
                    f.write(self.private_key.export_key('PEM'))
        elif key:
            self.private_key = RSA.import_key(key)
        else:
            #if filename is not specified, just create keys within this object and don't save them
            self.private_key = RSA.generate(4096)

                    
        self.public_key = self.private_key.public_key()

        self.master_cipher = PKCS1_OAEP.new(self.private_key)


    def encrypt(self,contents : bytes):
        return self.master_cipher.encrypt(contents)

    def decrypt(self,contents : bytearray):
        return self.master_cipher.decrypt(contents)

    def get_public_key(self):
        return self.public_key.export_key("PEM")

