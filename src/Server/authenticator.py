import os
import json
from Crypto.Hash import SHA256
from threading import Lock
import copy
from session import UserSession

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

        if os.path.exists("groups.json"):
            with open("groups.json","r") as f:
                self.groups = json.loads(f.read())
        else:
            self.groups = {"groups" : []}


    def user_save(self):
        with open("users.json","w") as f:
            f.write(json.dumps(self.users))
    
    
    def group_save(self):
        with open("groups.json","w") as f:
            f.write(json.dumps(self.groups))


    def new_user(self,username : str,password : str):
        if username in self.users.keys():
            return False
        
        self.users[username] = {
            "password": SHA256.new(password.encode("UTF-8")).hexdigest(),
            "groups": [],
        }

        self.user_save()
        return True


    def authenticate_user(self,username : str,password : str):
        if username in self.users:
            valid = self.users[username]["password"] == SHA256.new(password.encode("UTF-8")).hexdigest()
        else:
            valid = False
        return valid


    def get_user(self,username : str):
        ret = copy.copy(self.users[username])
        return ret


    def group_create(self,group_name,session : UserSession):
        if group_name in self.groups["groups"]:
            return False

        if not group_name:
            return False
        
        self.groups["groups"].append(group_name)

        self.users[session.get_username()]["groups"].append(group_name)

        self.user_save()
        self.group_save()
        return True


    def group_add(self,group_name,new_user,session : UserSession):
        if not group_name in self.users[session.get_username()]["groups"]:
            return False

        if not new_user in self.users.keys():
            return False
        
        if group_name in self.users[new_user]["groups"]:
            return False
        
        self.users[new_user]["groups"].append(group_name)

        self.user_save()
        self.group_save()
        return True


    def group_remove(self,group_name,user,session : UserSession):
        if not group_name in self.users[session.get_username()]["groups"]:
            return False

        if not user in self.users.keys():
            return False
        
        if not group_name in self.users[user]["groups"]:
            return False
        
        group_list : list = self.users[user]["groups"]
        group_list.remove(group_name)
        self.users[user]["groups"] = group_list

        self.user_save()
        self.group_save()
        return True

    
    def group_list(self, session : UserSession):
        return " ".join(self.users[session.get_username()]["groups"])
    