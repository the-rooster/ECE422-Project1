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
        self.home_path = self.encode_filename("home".encode("UTF-8"))


        if os.path.exists("files.json"):
            with open("files.json","r") as f:
                self.files = json.loads(f.read())
        else:
            self.files = { 
                self.home_path: {
                    "permissions" : "211",
                    "owner" : "admin",
                    "type" : "directory",
                    "hash" : "",
                    "name" : "home",
                    "files" : {}
                }
        }
        
        if not os.path.exists("./sfs"):
            os.makedirs(f"./sfs/{self.home_path}/")

        #lock for updating files.json / directories / files
        self.write_lock = Lock()

        self.base_path = "./sfs/"

        self.get_user_info = get_user_info



    
        
    def new_user_dir(self,username : str):

        
        self.write_lock.acquire()

        dir_name = self.encode_filename(username.encode("UTF-8"))

        os.mkdir(self.base_path + "/" + self.home_path + "/" + dir_name)
        self.files[self.home_path]["files"][dir_name] = {
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

    def has_permission(self,file : dict, session : UserSession):
        #return string 'read', 'write' if user has permission
        #otherwise, return None

        perms = file["permissions"]
        owner = file["owner"]
        user_group = self.get_user_info(file["owner"])["group"]
        
        #check owner bits if user is owner
        if session.get_username() == owner:

            if perms[0] == "2":
                return 'write'
            elif perms[0] == "1":
                return 'read'

            return None
        
        #check group bits if user in same group

        if self.get_user_info(session.get_username()) == user_group:

            if perms[1] == "2":
                return 'write'
            elif perms[1] == "1":
                return 'read'
            
            return None

        #otherwise, check other bits
        
        if perms[2] == "2":
            return 'write'
        elif perms[2] == "1":
            return 'read'
            
        return None
        
    
    def save(self):
        with open("files.json","w") as f:
            f.write(json.dumps(self.files))

    def fix_path(self,path,session):
        if not path:
            path = session.get_cwd()
        
        elif path[0] == "/":
            print("ABSOLUTE")
            path = os.path.normpath(path)
            path = path.replace("..","")
            path = os.path.normpath(path)
        else :
            #case for when path begins with "." or "" (relative traversal)
            print("RELATIVE")
            path : str = os.path.normpath(session.get_cwd() + "/" + path)
            print("HERE1",path)
            path = path.replace("..","")
            path : str = os.path.normpath(path)


        
        #remove random /'s and /./'s and extract path components
        path = [p for p in path.split("/") if p and p != "."]

        return path
    
    def save(self):
        with open("files.json","w") as f:
            f.write(json.dumps(self.files))

    def cd(self,path,session : UserSession):
        
        path = self.fix_path(path,session)

        #encrypt each piece of the path
        encrypted_path = '/'.join([self.encode_filename(x.encode("UTF-8")) for x in path]) if path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path + "/")

        print("CD TOTAL PATH: ",total_path)
        if not os.path.exists(total_path):
            return False

        path = "/".join(path)
            
        return path + "/"

    def ls(self,path,session):

        result = "Directory Listing:\n"

        path = self.fix_path(path,session)
        print("BEFORE ENCRYPT:",path)
        path = [self.encode_filename(x.encode("UTF-8")) for x in path]
        file_obj = {}
        if path:
            print("PATH:",path)
            file_obj = self.files[path[0]]

            if len(path) > 1:
                for p in path[1:]:

                    try:
                        file_obj = file_obj["files"][p]
                    except KeyError:
                        return False

                    if file_obj["type"] != "directory":
                        print("found object on ls path that isnt a directory")
                        return False

        #if they requested a listing of the root directory
        if not file_obj:
            for (k,v) in self.files.items():
                result += v["name"] + "\n"
        else:
            #listing of directory returned. only return filename if user has permission 
            for (k,v) in file_obj["files"].items():
                type = v["type"]
                if type == "directory" or (type == "file" and self.has_permission(v,session)) :
                    result += v["name"] + f" | {type}\n"
                else:
                    #if user lacks permissions, show encrypted name
                    result += k + f" | {type}\n"
        return result            
    
    def mkdir(self, name, session : UserSession):
        
        self.write_lock.acquire()

        path = self.fix_path(f"./{name}",session)
        encrypted_path = '/'.join([self.encode_filename(x.encode("UTF-8")) for x in path]) if path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path + "/")


        if not path:
            print("can't create directory in root")
            self.write_lock.release()
            return False
        


        if len(path) < 2 or path[0] != 'home' or path[1] != session.get_username():
            self.write_lock.release()
            return False


        print ("PATHS:")
        print (encrypted_path)
        print (total_path)
        print (path)


        file_obj = self.files[self.encode_filename(path[0].encode("UTF-8"))]["files"][self.encode_filename(path[1].encode("UTF-8"))]
        if len([path]) > 2:
            for dir in path[1:]:

                
                encrypted_dir = self.encode_filename(dir.encode("UTF-8"))
                if encrypted_dir not in file_obj["files"]:
                    file_obj["files"][encrypted_dir] = {
                        "permissions" : "200",
                        "owner" : session.get_username(),
                        "type" : "directory",
                        "hash" : "",
                        "name" : dir,
                        "files" : {}
                    }

                try:
                    file_obj = file_obj["files"][encrypted_dir]
                except KeyError as e:
                    print("key error", e)
                    self.write_lock.release()
                    return False

                if file_obj["type"] != "directory":
                    print("found object on mkdir path that isnt a directory")
                    self.write_lock.release()
                    return False

        if not os.path.exists(total_path):
            print("total path: ", total_path)
            os.makedirs(total_path)
        else:
            print("HERE!")
            self.write_lock.release()
            return False
            
        self.save()

        self.write_lock.release()

        return True