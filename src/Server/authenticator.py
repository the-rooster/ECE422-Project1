import os
import json
from Crypto.Hash import SHA256
from threading import Lock
import copy

"""
This class manages all user authentication. holds usernames and hashed passwords.
Saves all data to users.json.
"""
class Authenticator():

    def __init__(self):
        
        if os.path.exists("users.json"):
            with open("users.json","r") as f:
                self.users = json.loads(f.read())
        else:
            self.users = {}

        self.write_lock = Lock()

    #must be write locked so that the file can't be corrupted
    def save(self):
        with open("users.json","w") as f:
            f.write(json.dumps(self.users))

    def new_user(self,username : str,password : str):
        #must wrap in lock since every client has a seperate thread, and creating a new user will call this method
        self.write_lock.acquire()

        if username in self.users.keys():
            self.write_lock.release()
            return False
        
        self.users[username] = {
            "password":SHA256.new(password.encode("UTF-8")).hexdigest(),
            "group":"",
        }

        self.save()

        self.write_lock.release()
        return True

    def authenticate_user(self,username : str,password : str):
        self.write_lock.acquire()
        if username in self.users:
            valid = self.users[username]["password"] == SHA256.new(password.encode("UTF-8")).hexdigest()
        else:
            valid = False
        self.write_lock.release()
        return valid

    def get_user(self,username : str):
        self.write_lock.acquire()
        ret = copy.copy(self.users[username])
        self.write_lock.release()
        return ret
