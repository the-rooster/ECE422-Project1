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
        self.home_path = self.encode_filename("home")


        if os.path.exists("files.json"):
            with open("files.json","r") as f:
                self.files = json.loads(f.read())
        else:
            self.files = { 
                "files": {
                    self.home_path: {
                        "permissions" : "200",
                        "owner" : "admin",
                        "type" : "directory",
                        "name" : "home",
                        "files" : {}
                    }
                }
            }
        
        if not os.path.exists("./sfs"):
            os.makedirs(f"./sfs/{self.home_path}/")

        #lock for updating files.json / directories / files
        self.write_lock = Lock()

        self.base_path = "./sfs/"

        self.get_user_info = get_user_info


    def new_user_dir(self, username : str):
        

        encoded_user_dir = self.encode_filename(username)
        os.mkdir(self.base_path + "/" + self.home_path + "/" + encoded_user_dir)
        self.files["files"][self.home_path]["files"][encoded_user_dir] = {
            "permissions" : "200",
            "owner" : username,
            "type" : "directory",
            "name" : username,
            "files" : {}
        }
        self.save()

        


    def encode_filename(self, filename : str):
        filename = filename.encode("UTF-8")
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
        print("SAVING")
        print(self.files)
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
    

    def cd(self,path,session : UserSession):
        
        path = self.fix_path(path,session)

        #encrypt each piece of the path
        hashed_path = '/'.join([self.encode_filename(x) for x in path]) if path else ""
        total_path = os.path.normpath(self.base_path + hashed_path + "/")

        print("CD TOTAL PATH: ",total_path)
        if not os.path.exists(total_path) or os.path.isfile(total_path):
            return False

        path = "/".join(path)
            
        return path + "/"


    def ls(self,path,session):

        result = ""

        path = self.fix_path(path,session)
        print("BEFORE ENCRYPT:",path)
        path = [self.encode_filename(x) for x in path]

        file_obj = self.files

        for dir in path:
            try:
                file_obj = file_obj["files"][dir]
            except KeyError:
                return False

            if file_obj["type"] != "directory":
                print("found object on ls path that isnt a directory")
                return False

        #if they requested a listing of the root directory
        if not file_obj:
            for (k,v) in self.files["files"].items():
                result += v["name"] + "\n"
        else:
            #listing of directory returned. only return filename if user has permission 
            for (k,v) in file_obj["files"].items():
                type = v["type"]
                perms = v["permissions"]
                owner = v["owner"]
                if type == "directory" or (type == "file" and self.has_permission(v,session)) :
                    result += v["name"] + f" | {owner} | {type} | {perms}\n"
                else:
                    #if user lacks permissions, show encrypted name
                    result += k + f" | {type} | {perms}\n"
        return result            
    
    
    def mkdir(self, name, session: UserSession):
        
        path = self.fix_path(f"./{name}",session)
        encrypted_path = '/'.join([self.encode_filename(x) for x in path]) if path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path + "/")

        if not path or len(path) < 2 or path[0] != 'home' or path[1] != session.get_username():
            return False

        file_obj = self.files

        for dir in path:
            encrypted_dir = self.encode_filename(dir)
            if encrypted_dir not in file_obj["files"]:
                file_obj["files"][encrypted_dir] = {
                    "permissions" : "200",
                    "owner" : session.get_username(),
                    "type" : "directory",
                    "name" : dir,
                    "files" : {}
                }

            file_obj = file_obj["files"][encrypted_dir]

            if file_obj["type"] != "directory":
                print("found object on mkdir path that isnt a directory")
                return False

        if not os.path.exists(total_path):
            print("total path: ", total_path)
            os.makedirs(total_path)
            
        self.save()
        return True


    def write(self, path, overwrite_flag, content : str, session : UserSession):

        #get path to create file in
        path = self.fix_path(path,session)
        hashed_path_dirs = '/'.join([self.encode_filename(x) for x in path[:-1]]) if path else ""
        total_path_dirs = os.path.normpath(self.base_path + hashed_path_dirs + "/")

        #hash all parts of the path
        hashed_path = [self.encode_filename(x) for x in path]
        hashed_path_str = '/'.join(hashed_path) if path else ""
        total_path = os.path.normpath(self.base_path + hashed_path_str)

        #ensure user has rights to make a file in this directory. also ensure user is creating a .txt file!
        if not path or not path[-1].endswith(".txt"):
            print("here1")
            return False

        #if file doesn't exist yet, ensure they are creating it within their home directory
        if not os.path.exists(total_path) and ( len(path) < 2 or path[0] != 'home' or path[1] != session.get_username()):
            print("here2")
            return False

        
        file_obj = self.files

        for dir in path[:-1]:
            encrypted_dir = self.encode_filename(dir)
            if encrypted_dir not in file_obj["files"]:
                file_obj["files"][encrypted_dir] = {
                    "permissions" : "200",
                    "owner" : session.get_username(),
                    "type" : "directory",
                    "name" : dir,
                    "files" : {}
                }

            file_obj = file_obj["files"][encrypted_dir]

            if file_obj["type"] != "directory":
                print("found object on mkdir path that isnt a directory")
                return False


        #ensure user has write permissions on this file

        if not self.has_permission(file_obj,session):
            #user lacks permissions
            print("USER LACKS PERMISSIONS")
            return False

        encrypted_filename = self.encode_filename(path[-1])
        if overwrite_flag == "o":
            file_obj["files"][encrypted_filename] = {
                "permissions" : "200",
                "owner" : session.get_username(),
                "type" : "file",
                "hash" : base64.encodebytes(SHA256.new(content.encode("UTF-8")).digest()).decode("UTF-8"),
                "name" : path[-1],
            }
        
        if not os.path.exists(total_path_dirs):
            print("total path: ", total_path_dirs)
            os.makedirs(total_path_dirs)

        #do all the writing stuff here
        flags = ("w" if overwrite_flag == "o" else "a") + "b"

        print("OPEN FLAGS: ",flags)
        with open(total_path,flags) as f:
            
            #encrypt contents and place them in file
            encrypted_content = bytearray()

            for i in range(0,len(content),100):
                chunk = content[i:min(i + 100,len(content))]
                encrypted_content.extend(b'|CHUNK|')
                encrypted_content.extend(self.file_crypto.encrypt(bytes(chunk,encoding="UTF-8")))

            f.write(encrypted_content)


        self.save()
        return True
        

    def read(self, path, session : UserSession):

        #get path to create file in
        path = self.fix_path(path,session)
        hashed_path_dirs = '/'.join([self.encode_filename(x) for x in path[:-1]]) if path else ""
        total_path_dirs = os.path.normpath(self.base_path + hashed_path_dirs + "/")

        #hash all parts of the path
        hashed_path = [self.encode_filename(x) for x in path]
        hashed_path_str = '/'.join(hashed_path) if path else ""
        total_path = os.path.normpath(self.base_path + hashed_path_str)
        

        if not os.path.isfile(total_path):
            print("trying to read a directory. cringe.")
            return "Failed"
        
        
        file_obj = self.files

        for dir in path[:-1]:
            encrypted_dir = self.encode_filename(dir)

            file_obj = file_obj["files"][encrypted_dir]

            if file_obj["type"] != "directory":
                print("found object on read path that isnt a directory")
                return "Failed"


        #ensure user has write permissions on this file
        if not self.has_permission(file_obj,session):
            #user lacks permissions
            print("USER LACKS PERMISSIONS")
            return "Failed"



        unencrypted = bytearray()
        with open(total_path,"rb") as f:
            
            #encrypt contents and place them in file
            encrypted = f.read()

            for chunk in encrypted.split(b'|CHUNK|'):
                if chunk:
                    unencrypted.extend(self.file_crypto.decrypt(chunk))

        return unencrypted.decode("UTF-8")
        
        
        
        

        