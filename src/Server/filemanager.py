import os
import json
import base64
import copy
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
            self.home_path = self.encode_filename("home")

            self.files = { 
                "type" : "directory",
                "permissions" : "211",
                "owner" : "admin",
                "files": {
                    self.home_path: {
                        "permissions" : "211",
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
            "permissions" : "220",
            "owner" : username,
            "type" : "directory",
            "files" : {}
        }
        self.save()

    
    def remove_user_dir(self, username : str):
        file_obj = self.files["files"][self.home_path]
        del file_obj["files"][self.find_encrypted_filename(username,file_obj)]
        self.save()


    def encode_filename(self, filename : str) -> str:
        return self.filename_crypto.encrypt(filename.encode("UTF-8")).decode("UTF-8")
    

    def decode_filename(self,filename : str) -> str:
        return self.filename_crypto.decrypt(filename.encode("UTF-8")).decode("UTF-8")


    def has_permission(self,file : dict, session : UserSession):
        #return string 'read', 'write' if user has permission
        #otherwise, return None

        print('testtesttesttest')
        perms = file["permissions"]
        owner = file["owner"]

        print("GETTING GROUPS OF USER")
        user_groups = self.get_user_info(file["owner"])
        print("GOT USER GROUPS")
        user_groups = user_groups["groups"]
        print(perms)
        
        #check owner bits if user is owner
        if session.get_username() == owner:

            if perms[0] == "2":
                return 'write'
            elif perms[0] == "1":
                return 'read'

            return None
        
        print("FILE OWNER GROUPS: ",user_groups)
        print("REQUESTER GROUPS: ", self.get_user_info(session.get_username())["groups"])
        is_in_group = False
        for group in user_groups:
            if group in self.get_user_info(session.get_username())["groups"]:
                is_in_group = True
        
        print(is_in_group)
        #check group bits if user in same group
        if is_in_group:
            
            print(perms)
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
                print('aaaaaaaa')
                return encrypted_filename

        print("ooeoeeeeeee")
        return ""


    def get_file_list(self, file_obj, session : UserSession) -> str:
        result = ""
        
        for (k,v) in file_obj["files"].items():
            type = v["type"]
            perms = v["permissions"]
            owner = v["owner"]
            if self.has_permission(v, session):
                result += self.decode_filename(k) + f" | {owner} | {type} | {perms}\n"
            else:
                result += k + f" | {type} | {perms}\n"

        return result
            

    def make_os_directories(self, encrypted_path) -> None:
        encrypted_path_string = '/'.join(encrypted_path) if encrypted_path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path_string + "/")

        if not os.path.exists(total_path):
            print("total path: ", total_path)
            os.makedirs(total_path)
            return True
        return False


    def write_os_file(self, encrypted_path, content : str) -> None:
        encrypted_path_string = '/'.join(encrypted_path) if encrypted_path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path_string)
        encrypted_content = self.file_crypto.encrypt(content.encode("UTF-8"))

        with open(total_path, "wb") as f:
            f.write(encrypted_content)

    
    def read_os_file(self, encrypted_path) -> bytes:
        encrypted_path_string = '/'.join(encrypted_path) if encrypted_path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path_string)

        encrypted_contents = bytearray()
        with open(total_path, "rb") as f:
            encrypted_contents = f.read()

        return encrypted_contents


    def delete_os_file(self, encrypted_path) -> bool:
        encrypted_path_string = '/'.join(encrypted_path) if encrypted_path else ""
        total_path = os.path.normpath(self.base_path + encrypted_path_string)

        if os.path.isfile(total_path):
            os.remove(total_path)
            return not os.path.exists(total_path)

        print('here124124')
        return False


    def rename_os_file(self,encrypted_path,new_name) -> bool:
        encrypted_path_string = '/'.join(encrypted_path) if encrypted_path else ""
        dest_path_string = '/'.join(encrypted_path[:-1]) + "/" + new_name
        total_path = os.path.normpath(self.base_path + encrypted_path_string)
        total_dest_path = os.path.normpath(self.base_path + dest_path_string)

        os.rename(total_path,total_dest_path)
        return os.path.exists(total_dest_path) and not os.path.exists(total_path)
 

    def cd(self, path, session : UserSession):
        path = self.fix_path(path,session)
        file_obj = self.files

        print("oooaaaaoooaaaoaooaoaaoooaoaoa")
        print(path)
        for dir_name in path:
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            print(encrypted_filename)
            if encrypted_filename == "":
                print("test2")
                return False

            file_obj = file_obj["files"][encrypted_filename]

            print('test3')

            if not self.has_permission(file_obj,session):
                print("perms failed")
                return False
            
            if file_obj["type"] != "directory":
                print("test")
                return False

        print("AASODAOSDOSADOSA")
            
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

            if not self.has_permission(file_obj,session):
                return "ls failed"

        return self.get_file_list(file_obj, session)
    

    def mkdir(self, name, session: UserSession):
        path = self.fix_path(f"./{name}", session)
        encrypted_path = []
        file_obj = self.files

        for dir_name in path:
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                if not self.has_permission(file_obj,session) == "write":
                    return False
                encrypted_filename = self.encode_filename(dir_name)
                file_obj["files"][encrypted_filename] = {
                    "permissions" : "220",
                    "owner" : session.get_username(),
                    "type" : "directory",
                    "files" : {}
                }

            encrypted_path.append(encrypted_filename)
            file_obj = file_obj["files"][encrypted_filename]
            if file_obj["type"] != "directory":
                return False

        if not self.make_os_directories(encrypted_path):
            print("failed to make directories. path already exists.")
            return False

        self.save()
        return True


    def write(self, path, overwrite_flag, content : str, session : UserSession):
        path = self.fix_path(path, session)
        encrypted_path = []
        file_obj = self.files

        if not path or not path[-1].endswith(".txt"):
            print("here1")
            return False
        
        for dir_name in path[:-1]:
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                return False

            encrypted_path.append(encrypted_filename)
            file_obj = file_obj["files"][encrypted_filename]
            if file_obj["type"] != "directory":
                return False

        encrypted_filename = self.find_encrypted_filename(path[-1], file_obj)

        if not encrypted_filename:
            encrypted_filename = self.encode_filename(path[-1])

        if not self.has_permission(file_obj, session) == "write" and encrypted_filename in file_obj["files"]:
            print("USER LACKS PERMISSIONS", self.has_permission(file_obj, session))
            return False
        elif not encrypted_filename in file_obj["files"].keys() and not session.get_username() == file_obj["owner"]:
            print("Creating new file in directory that they do not own!")
            return False

        
        encrypted_write_path = encrypted_path + [encrypted_filename]

        if overwrite_flag == "o":
            file_obj["files"][encrypted_filename] = {
                "permissions" : "200",
                "owner" : session.get_username(),
                "type" : "file",
                "hash" : base64.encodebytes(SHA256.new(content.encode("UTF-8")).digest()).decode("UTF-8"),
            }
        elif overwrite_flag == "a":
            
            if encrypted_filename not in file_obj["files"].keys():
                print("appending to a file that does not exist")
                return False

            #recalculate hash here:

            encrypted_path_string = '/'.join(encrypted_write_path) if encrypted_path else ""
            total_path = os.path.normpath(self.base_path + encrypted_path_string)

            try:
                with open(total_path,"rb") as f:

                    content = self.file_crypto.decrypt(f.read()).decode("UTF-8") + content

            except Exception as e:
                return False

            file_obj["files"][encrypted_filename]["hash"] = base64.encodebytes(SHA256.new(content.encode("UTF-8")).digest()).decode("UTF-8")
        else:
            return False


        self.make_os_directories(encrypted_path)
        self.write_os_file(encrypted_write_path, content)
        self.save()
        return True


    def read(self, path, session : UserSession):
        path = self.fix_path(path,session)
        encrypted_path = []
        file_obj = self.files

        for dir_name in path:
            if file_obj["type"] != "directory":
                return "read failed"
                
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                return "read failed"

            encrypted_path.append(encrypted_filename)
            file_obj = file_obj["files"][encrypted_filename]

        if not self.has_permission(file_obj, session):
            print("USER LACKS PERMISSIONS")
            return "Failed"

        if file_obj["type"] == "directory":
            return "read failed"
            
        encrypted_contents = self.read_os_file(encrypted_path)

        
        try:
            decrypted = self.decrypt_file_contents(encrypted_contents).decode('utf-8')
        except Exception as e:
            return "Failed to decrypt! File likely tampered with"
            
        return decrypted


    def chmod(self,perms : str,path : str,session : UserSession):

        path = self.fix_path(path,session)
        file_obj = self.files

        for dir_name in path:

                
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                return False

            file_obj = file_obj["files"][encrypted_filename]
        
        #assure file exists in files.json
        if not file_obj:
            print("path does not exist")
            return False

        if len(perms) != 3:
            print("perm string not long enough")
            return False

        #ensure user has write permissions on this file
        if not file_obj["owner"] == session.get_username():
            #user lacks permissions
            print("USER LACKS PERMISSIONS")
            return False
        
        file_obj["permissions"] = perms
        print(file_obj)

        self.save()
        return True


    def delete(self,path,session : UserSession) -> bool:
        path = self.fix_path(path,session)
        encrypted_path = []
        file_obj = self.files

        for dir_name in path[:-1]:
            if file_obj["type"] != "directory":
                return False
                
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                print('delete1')
                return False

            encrypted_path.append(encrypted_filename)
            file_obj = file_obj["files"][encrypted_filename]

        if not self.has_permission(file_obj, session) == "write":
            print("USER LACKS PERMISSIONS")
            return False

        old_name = self.find_encrypted_filename(path[-1],file_obj)
        del file_obj["files"][old_name]

        encrypted_path.append(old_name)
        
        return self.delete_os_file(encrypted_path)
        

    def rename(self,path,new_name,session : UserSession):
        path = self.fix_path(path,session)
        encrypted_path = []
        file_obj = self.files

        if "/" in new_name:
            print("tried to move file in rename")
            return False

        for dir_name in path[:-1]:
            if file_obj["type"] != "directory":
                return False
                
            encrypted_filename = self.find_encrypted_filename(dir_name, file_obj)
            if encrypted_filename == "":
                return False

            encrypted_path.append(encrypted_filename)
            file_obj = file_obj["files"][encrypted_filename]



        enc_new_name = self.encode_filename(new_name)
        old_name = self.find_encrypted_filename(path[-1],file_obj)

        if not self.has_permission(file_obj["files"][old_name], session) == "write":
            print("USER LACKS PERMISSIONS")
            return False
        encrypted_path.append(old_name)

        if file_obj["files"][old_name]["type"] == "file" and not new_name.endswith(".txt"):
            print("tried to rename file to not txt")
            return False

        temp = copy.deepcopy(file_obj["files"][old_name])
        del file_obj["files"][old_name]
        file_obj["files"][enc_new_name] = temp

        return self.rename_os_file(encrypted_path, enc_new_name)


    def create(self,path,session : UserSession):
        return self.write(path,"o","",session)


    def verify_integrity(self, username : str):
        path = ['home', username] # the unencrypted path in an array

        file_obj = self.files
        try:
            
            file_obj = file_obj['files'][self.home_path]
            encrypted_user_dir = self.find_encrypted_filename(path[1],file_obj)
            file_obj = file_obj['files'][self.find_encrypted_filename(path[1],file_obj)] # file_obj at home/<username>
        except Exception as e:
            print(e)
            return ["Error: user directory not found"]

        encrypted_path = f'/{self.home_path}/{encrypted_user_dir}' if path else "" # the encrypted path in a string
        total_path = os.path.normpath(self.base_path + encrypted_path + "/") # the encrypted path in a string starting with sfs/

        return self.verify_integrity_dfs(file_obj, total_path, path)


    def verify_integrity_dfs(self, file_obj, total_path, path):
        messages = []

        for file in file_obj['files']:
            new_path = total_path + '/' + file
            new_file_obj = file_obj['files'][file]

            new_piece = self.filename_crypto.decrypt(file.encode("UTF-8")).decode("UTF-8")

            temp = path + [new_piece]
            if new_file_obj['type'] == 'directory' and os.path.isdir(new_path):
                messages.extend(self.verify_integrity_dfs(new_file_obj, new_path, temp))
            elif new_file_obj['type'] == 'file' and os.path.isfile(new_path):
                messages.extend(self.verify_integrity_hash(new_file_obj, new_path, temp))
            else:
                disp_path = "/".join(path)
                messages.append(f"Error: path not found {disp_path}")
        
        return messages


    def verify_integrity_hash(self, file_obj, total_path, path):
        encrypted_contents = bytearray()

        path = "/".join(path)
        
        with open(total_path, "rb") as f:
            encrypted_contents = f.read()

        try:
            decrypted_contents = self.decrypt_file_contents(encrypted_contents)
            constructed_hash = base64.encodebytes(SHA256.new(decrypted_contents).digest()).decode("UTF-8")
            existing_hash = file_obj['hash']
        except Exception as e:
            
            return [f"Error: File tampered with {path}"]

        print(constructed_hash,existing_hash)

        if constructed_hash != existing_hash:
            return [f"Error: hash mismatch {path}"]
        return []

    
    def encrypt_file_contents(self, plain_contents : str) -> bytearray:
        return self.file_crypto.encrypt(plain_contents.encode("UTF-8"))

    
    def decrypt_file_contents(self, encrypted_contents : bytes) -> bytearray:
        return self.file_crypto.decrypt(encrypted_contents)
    