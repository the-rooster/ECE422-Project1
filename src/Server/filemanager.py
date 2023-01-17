import os
import json
import base64
from threading import Lock
from Crypto.Hash import SHA256

from Utils.cryptomanager import CryptoManager
from session import UserSession

"""
files.json:

{
    "user dir 1": {
        "permissions": "000",       # 0, 1 or 2 (none, read, read and write),
        "owner": "user 1",
        "type": "directory"/"file",
        "hash": <file hash>         #if file, hash of filename + contents, if directory hash of dirname
        "files": {                  # only if directory
            "dir 1": {...}
        }
    },
    "user dir 2": {...},
    ...
}
"""
class FileManager():


    def __init__(self, get_user_info):

        #master key for file encryption
        self.file_crypto = CryptoManager("master_key.pem")

        self.name_crypto = CryptoManager("dir_name.pem",num_bits=1024)

        if os.path.exists("files.json"):

            with open("files.json","r") as f:
                self.files = json.loads(f.read())
        else:
            self.files = {}

        #lock for updating files.json / directories / files
        self.write_lock = Lock()

        self.base_path = "./sfs/"

        self.get_user_info = get_user_info

    def new_user_dir(self,username : str):

        
        self.write_lock.acquire()

        dir_name = self.encode_filename(username)

        os.mkdir(self.base_path + dir_name)
        self.files[dir_name] = {
            "permissions" : "200",
            "owner" : username,
            "type" : "directory",
            "hash" : "",
            "files" : {}
        }

        self.save()

        self.write_lock.release()

    def encode_filename(self,filename : str):
        filename = self.name_crypto.encrypt(filename.encode("UTF-8"))
        filename = base64.encodebytes(filename).decode("UTF-8")
        filename = filename.replace("\n","")
        filename = filename.replace("=","^")
        filename = filename.replace("+","_")
        filename = filename.replace("/","-")
        return filename
    
    def decode_filename(self,filename : str):
        filename = filename.replace("^","=")
        filename = filename.replace("_","+")
        filename = filename.replace("-","/")
        filename = base64.decodebytes(filename)
        filename = self.name_crypto.decrypt(filename)
        return filename
    
    def save(self):
        with open("files.json","w") as f:
            f.write(json.dumps(self.files))

    def cd(self,path,session : UserSession):
        
        path : str = os.path.normpath(session.get_cwd() + "/" + path)

        #case for when path[0] == ~
        if path[0] == "~/":
            path = path.replace("~/",session.get_username() + "/")
        
        #encrypt each piece of the path
        encrypted_path = '/'.join([self.encode_filename(x.encode("UTF-8")) for x in path.split("/")])

        if not os.path.exists(self.base_path + encrypted_path + "/"):
            return False
            
        return path + "/"
    
    def mkdir(self, args, session):

        return