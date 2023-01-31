from cryptography.fernet import Fernet
from secrets import token_bytes
import os
import base64

class FernetCryptoManager():

    def __init__(self,filename : str = None):
        if not filename:
            self.key = base64.encodebytes(token_bytes(32))
        else:
            if os.path.exists(filename):
                with open(filename,"rb") as f:
                    self.key = f.read()
            else:
                self.key = base64.encodebytes(token_bytes(32))
                with open(filename,"wb") as f:
                    f.write(self.key)

        self.cipher = Fernet(self.key)

    def encrypt(self,contents : bytearray) -> bytes:
        return self.cipher.encrypt(contents)

    def decrypt(self,contents : bytes) -> bytes:
        return self.cipher.decrypt(contents)

    def get_key(self):
        return self.key
