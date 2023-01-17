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
    "user dir 1 <HASHED W/ SHA256>": {
        "permissions": "000",       # 0, 1 or 2 (none, read, read and write),
        "owner": "user 1",
        "type": "directory"/"file",
        "name" : <file name : user dir 1>,
        "hash": <file hash>         #if file, hash of filename + contents. if directory, leave empty
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

        dir_name = self.encode_filename(username.encode("UTF-8"))

        os.mkdir(self.base_path + dir_name)
        self.files[dir_name] = {
            "permissions" : "200",
            "owner" : username,
            "type" : "directory",
            "hash" : "",
            "name" : username,
            "files" : {}
        }

        self.save()

        self.write_lock.release()

    def encode_filename(self,filename : bytes):
        b64 = base64.encodebytes(SHA256.new(filename).digest()).decode("UTF-8").strip()
        b64 = b64.replace("/","-")
        b64 = b64.replace("+","_")
        b64 = b64.replace("=","^")
        return b64
    
    def decode_filename(self,filepath : str):
        #must use absolute filepath. no relative filepaths (including ~)
        parts = filepath.split("/")

        current = self.files[parts[0]]

        for p in parts[1:]:
            current = current[p]
        
        return current["name"]

        
        
    
    def save(self):
        with open("files.json","w") as f:
            f.write(json.dumps(self.files))

    def cd(self,path,session : UserSession):
        
        if path[0] == "/":
            print("ABSOLUTE")
            path = os.path.normpath(path)
            path = path.replace("..","")
            path = os.path.normpath(path)

        elif path[0] == "~/":
            print("HOME")
            #case for when path[0] == ~, a shortcut to the home directory
            path = path.replace("~", session.get_username()+ "/")
        else :
            #case for when path begins with "." or "" (relative traversal)
            print("RELATIVE")
            path : str = os.path.normpath(session.get_cwd() + "/" + path)
            print("HERE1",path)
            path = path.replace("..","")
            path : str = os.path.normpath(path)


        
        #remove random /'s and /./'s and extract path components
        path = [p for p in path.split("/") if p and p != "."]

        
        print(path)

        #encrypt each piece of the path
        encrypted_path = '/'.join([self.encode_filename(x.encode("UTF-8")) for x in path]) if path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path + "/")

        if not os.path.exists(total_path):
            return False

        path = "/".join(path)
            
        return path + "/"
    
    def mkdir(self, args, session):

        return