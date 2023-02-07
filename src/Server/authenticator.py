import os
import json
from Crypto.Hash import SHA256
from threading import Lock
import copy
from session import UserSession



"""
groups.json structure
{
    "groups": {

        "group1": {
            "join_reqs" : ["user1","user2"]
        }
    }
}

users.json structure
{
    "name" : {
        "password" : SHA256HASH,
        "groups": [],
        "active": boolean
    }
}
"""
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
            self.groups = {}

        self.admin_name = "admin"



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
            "active" : False
        }

        if username == self.admin_name:

            self.users[username]["active"] = True

        self.user_save()
        return True

    def delete_user(self,username : str, session : UserSession):

        if not username in self.users.keys() or username == self.admin_name:
            return False

        if not session.get_username() == self.admin_name:
            return False

        del self.users[username]

        self.user_save()

        return True


    def user_list_requests(self, session : UserSession):

        if not session.get_username() == self.admin_name:
            return False

        res = []
        for i in self.users:
            if not self.users[i]["active"]:
                res.append(i)

        return " ".join(res)


    def activate_user(self,username : str, session : UserSession):

        if not session.get_username() == self.admin_name:
            return False

        if username not in self.users.keys():
            return False

        if self.users[username]["active"]:
            return False
        
        self.users[username]["active"] = True

        print('asdiasida')
        self.user_save()

        return True

    def authenticate_user(self,username : str,password : str):

        
        if username in self.users:
            valid = self.users[username]["password"] == SHA256.new(password.encode("UTF-8")).hexdigest()

            if not self.users[username]["active"]:
                return False
        else:
            valid = False

        return valid


    def get_user(self,username : str):
        ret = copy.copy(self.users[username])
        return ret


    def group_create(self,group_name,session : UserSession):
        
        #only the server admin can create groups
        if not session.get_username() == self.admin_name:
            return False

        if group_name in self.groups.keys():
            return False

        if not group_name:
            return False
        
        self.groups[group_name] = {"join_reqs" : []}

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
        
        if not new_user in self.groups[group_name]["join_reqs"]:
            return False

        self.groups[group_name]["join_reqs"].remove(new_user)

        self.users[new_user]["groups"].append(group_name)

        self.user_save()
        self.group_save()
        return True


    def group_remove(self,group_name,user,session : UserSession):
        if not group_name in self.users[session.get_username()]["groups"].keys():
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

    def group_join(self, group_name, session : UserSession):
        
        if not group_name in self.groups.keys():
            return False

        self.groups[group_name]["join_reqs"].append(session.get_username())

        self.group_save()
        return True
    
    def group_list_requests(self,group_name, session : UserSession):
        #list all join requests for a given group

        if (not group_name in self.users[session.get_username()]["groups"]) or (group_name not in self.groups.keys()):
            return ""
        

        return " ".join(self.groups[group_name]["join_reqs"])
    