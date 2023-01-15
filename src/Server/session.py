import socket
from uuid import uuid4
from Utils.cryptomanager import CryptoManager
from Utils.messages import *
class UserSession():


    def __init__(self,conn : socket.socket, keys : CryptoManager):
        self.conn = conn
        self.pwd = "/"
        self.username = ""
        self.keys = keys

    def get_cwd(self):
        return self.pwd

    
    def set_cwd(self,path):
        self.pwd = path

    def get_username(self):
        return self.username

    def set_username(self,name):
        self.username = name
    
    def get_keys(self):
        return self.keys
    
    def get_conn(self):
        return self.conn
    