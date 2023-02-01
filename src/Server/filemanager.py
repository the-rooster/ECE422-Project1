import os
import json
import base64
from threading import Lock
from Crypto.Hash import SHA256

from Utils.symmanager import SymmetricCryptoManager
from Utils.fernetmanager import FernetCryptoManager
from session import UserSession

"""
files.json:

{
    "user dir 1 <encrypted with fernet": {
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
        self.file_crypto = SymmetricCryptoManager(filename="aes_key.key")

        self.filename_crypto = FernetCryptoManager(filename="fern_key.key")




        if os.path.exists("files.json"):
            with open("files.json","r") as f:
                self.files = json.loads(f.read())
                self.home_path = list(self.files["files"].keys())[0]
        else:
            print("TEST1")
            self.home_path = self.encode_filename("home")
            print("TEST2")
            self.files = { 
                "type" : "directory",
                "files": {
                    self.home_path: {
                        "permissions" : "200",
                        "owner" : "admin",
                        "type" : "directory",
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
            "files" : {}
        }
        self.save()


    def encode_filename(self, filename : str) -> str:
        return self.filename_crypto.encrypt(filename.encode("UTF-8")).decode("UTF-8")
    

    def decode_filename(self,filename : str) -> str:
        return self.filename_crypto.decrypt(filename.encode("UTF-8")).decode("UTF-8")


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


    def find_encrypted_filename(self, filename : str, file_obj) -> str:
        for encrypted_filename in file_obj["files"]:
            if self.decode_filename(encrypted_filename) == filename:
                return encrypted_filename

        return ""


    def get_file_list(self, file_obj, session : UserSession) -> str:
        result = ""
        
        for (k,v) in file_obj["files"].items():
            type = v["type"]
            perms = v["permissions"]
            owner = v["owner"]
            if type == "directory" or (type == "file" and self.has_permission(v, session)) :
                result += self.decode_filename(k) + f" | {owner} | {type} | {perms}\n"
            else:
                result += k + f" | {type} | {perms}\n"

        return result


    def make_os_directories(self, path) -> None:
        encrypted_path = '/'.join([self.encode_filename(x) for x in path]) if path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path + "/")

        if not os.path.exists(total_path):
            print("total path: ", total_path)
            os.makedirs(total_path)
    

    def cd(self, path, session : UserSession):
        path = self.fix_path(path,session)
        file_obj = self.files

        for dir_name in path:
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                return False

            file_obj = file_obj["files"][encrypted_filename]
            if file_obj["type"] != "directory":
                return False
            
        return "/".join(path) + "/"


    def ls(self, path, session : UserSession):
        path = self.fix_path(path,session)
        file_obj = self.files

        for dir_name in path:
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                return "ls failed"

            file_obj = file_obj["files"][encrypted_filename]
            if file_obj["type"] != "directory":
                return "ls failed"

        return self.get_file_list(file_obj, session)
    

    def mkdir(self, name, session: UserSession):
        path = self.fix_path(f"./{name}", session)
        file_obj = self.files

        for dir_name in path:
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                encrypted_filename = self.encode_filename(dir_name)
                file_obj["files"][encrypted_filename] = {
                    "permissions" : "200",
                    "owner" : session.get_username(),
                    "type" : "directory",
                    "files" : {}
                }

            file_obj = file_obj["files"][encrypted_filename]
            if file_obj["type"] != "directory":
                return False

        self.make_os_directories(path)
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
                    "files" : {}
                }

            file_obj = file_obj["files"][encrypted_dir]

            if file_obj["type"] != "directory":
                print("found object on mkdir path that isnt a directory")
                return False


        #ensure user has write permissions on this file

        if not self.has_permission(file_obj,session) == "write":
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
            }
        
        if not os.path.exists(total_path_dirs):
            print("total path: ", total_path_dirs)
            os.makedirs(total_path_dirs)

        #do all the writing stuff here
        flags = ("w" if overwrite_flag == "o" else "a") + "b"

        encrypted_content = self.encrypt_file_contents(content)

        print("OPEN FLAGS: ",flags)
        with open(total_path,flags) as f:
            f.write(encrypted_content)

        self.save()
        return True

    def __getfile(self,path,session : UserSession):
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
            return False, False
        
        file_obj = self.files

        for dir in path:
            encrypted_dir = self.encode_filename(dir)

            file_obj = file_obj["files"][encrypted_dir]

        
        return total_path, file_obj
        

    def read(self, path, session : UserSession):

        total_path, file_obj = self.__getfile(path,session)

        #ensure user has write permissions on this file
        if not self.has_permission(file_obj,session) == "write":
            #user lacks permissions
            print("USER LACKS PERMISSIONS")
            return "Failed"

        encrypted_contents = bytearray()
        with open(total_path, "rb") as f:
            encrypted_contents = f.read()

        return self.decrypt_file_contents(encrypted_contents).decode('utf-8')

    def chmod(self,perms : str,path : str,session : UserSession):

        total_path, file_obj = self.__getfile(path,session)
        
        #assure file exists in files.json
        if not file_obj:
            print("path does not exist")
            return False

        if len(perms) != 3:
            print("perm string not long enough")
            return False

        #ensure user has write permissions on this file
        if not self.has_permission(file_obj,session) == "write":
            #user lacks permissions
            print("USER LACKS PERMISSIONS")
            return False
        
        file_obj["permissions"] = perms
        print(file_obj)
        return True

    def verify_integrity(self, username : str):
        path = ['home', username] # the unencrypted path in an array
        encrypted_path = '/'.join([self.encode_filename(x) for x in path]) if path else "" # the encrypted path in a string
        total_path = os.path.normpath(self.base_path + encrypted_path + "/") # the encrypted path in a string starting with sfs/

        file_obj = self.files
        try:
            file_obj = file_obj['files'][self.encode_filename(path[0])]['files'][self.encode_filename(path[1])] # file_obj at home/<username>
        except:
            return ["Error: user directory not found"]

        return self.verify_integrity_dfs(file_obj, total_path)


    def verify_integrity_dfs(self, file_obj, total_path):
        messages = []

        for file in file_obj['files']:
            new_path = total_path + '/' + file
            new_file_obj = file_obj['files'][file]

            if new_file_obj['type'] == 'directory' and os.path.isdir(new_path):
                messages.extend(self.verify_integrity_dfs(new_file_obj, new_path))
            elif new_file_obj['type'] == 'file' and os.path.isfile(new_path):
                messages.extend(self.verify_integrity_hash(new_file_obj, new_path))
            else:
                messages.append(f"Error: path not found {new_path}")
        
        return messages


    def verify_integrity_hash(self, file_obj, path):
        encrypted_contents = bytearray()
        with open(path, "rb") as f:
            encrypted_contents = f.read()

        decrypted_contents = self.decrypt_file_contents(encrypted_contents)
        constructed_hash = base64.encodebytes(SHA256.new(decrypted_contents).digest()).decode("UTF-8")
        existing_hash = file_obj['hash']

        if constructed_hash != existing_hash:
            return [f"Error: hash mismatch {path}"]
        return []

    
    def encrypt_file_contents(self, decrypted_contents : str) -> bytearray:
        encrypted_content = bytearray()

        for i in range(0, len(decrypted_contents), 100):
            chunk = decrypted_contents[i:min(i + 100, len(decrypted_contents))]
            encrypted_content.extend(b'|CHUNK|')
            encrypted_content.extend(self.file_crypto.encrypt(bytes(chunk, encoding="UTF-8")))

        return encrypted_content

    
    def decrypt_file_contents(self, encrypted_contents : bytes) -> bytearray:
        decrypted_contents = bytearray()

        for chunk in encrypted_contents.split(b'|CHUNK|'):
            if chunk:
                decrypted_contents.extend(self.file_crypto.decrypt(chunk))

        return decrypted_contents
    