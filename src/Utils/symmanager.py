from Crypto.Cipher import AES
from secrets import token_bytes
import base64
import json
import os

class SymmetricCryptoManager():

    def __init__(self,filename : str = None,key : str = None, num_bits : int = 2048):
        if not filename:
            self.key = key if key else token_bytes(32)
        else:

            if os.path.exists(filename):
                with open(filename,"rb") as f:
                    self.key = f.read()
            else:
                self.key = token_bytes(32)
                with open(filename,"wb") as f:
                    f.write(self.key)

    def encrypt(self,contents : bytearray) -> bytes:
        aes = AES.new(self.key,AES.MODE_EAX)
        nonce = aes.nonce
        ciphertext, tag = aes.encrypt_and_digest(contents)
        
        data = json.dumps({
            "nonce" : base64.encodebytes(nonce).decode("UTF-8"),
            "ciphertext" : base64.encodebytes(ciphertext).decode("UTF-8"),
            "tag" : base64.encodebytes(tag).decode("UTF-8")
        })

        return data.encode("UTF-8")

    def decrypt(self,contents : bytearray) -> bytes:
        data = json.loads(contents)
        data = {k : base64.decodebytes(v.encode("UTF-8")) for k,v in data.items()}

        aes = AES.new(self.key,AES.MODE_EAX,nonce=data["nonce"])

        return aes.decrypt_and_verify(data["ciphertext"],data["tag"])

    def get_key(self):
        return self.key
