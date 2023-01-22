from Crypto.PublicKey import RSA
import socket
import base64

#to load utils package
import sys
sys.path.append('../')

from Utils.cryptomanager import CryptoManager
from Utils.messages import *
from authenticator import Authenticator
from session import UserSession
from menu import menu
from filemanager import FileManager

class SecureFileSystemServer():

    def __init__(self):
        


        #key for communication
        self.conn_crypto = CryptoManager()

        #user authentication
        self.authenticator = Authenticator()

        #encrypted file services
        self.filemanager = FileManager(self.authenticator.get_user)

    def handle_user_create(self,args : list, session : UserSession):
        if len(args) != 3:
            self.send(session, "Length of user_create command must be 3\n")
            return

        if self.authenticator.new_user(args[1],args[2]):
            session.set_username(args[1])
            #create new user directory in file system
            self.filemanager.new_user_dir(args[1])
            #set working directory to new home
            session.set_cwd("/home/" + args[1] + "/")
            self.send(session, f"Successfully created user: {args[1]}\n")
        else:
            self.send(session, "Failed to create user\n")

    def handle_whoami(self,session : UserSession):
        self.send(session, session.get_username())
        
    def handle_login(self,args : list,session : UserSession):
        if len(args) != 3:
            self.send(session, "Length of login command must be 3\n")
            return

        if self.authenticator.authenticate_user(args[1],args[2]):
            session.set_username(args[1])
            self.send(session, f"Succesfully logged in as {args[1]}\n")
        else:
            self.send(session, "Failed to login\n")

    def handle_logout(self,session: UserSession):
        session.set_username("")
        self.send(session, "Succesfully logged out\n")

    def handle_menu(self, session : UserSession):
        self.send(session, menu)

    def handle_pwd(self,session : UserSession):
        self.send(session,session.get_cwd())

    def handle_cd(self, args, session: UserSession):
        if len(args) != 2:
            self.send(session, "Length of cd command must be 2\n")
            return

        try:
            new_path = self.filemanager.cd(args[1], session)
        except Exception as e:
            print(e)
            new_path = False
        
        if new_path:
            session.set_cwd(new_path)
            self.send(session, f"{session.get_cwd()}\n")
        else:
            self.send(session, "Invalid path\n")

    def handle_ls(self, args, session: UserSession):
        if len(args) != 1 and len(args) != 2:
            self.send(session, "Length of ls command must be 1 or 2\n")
            return

        if len(args) == 2:
            self.send(session,self.filemanager.ls(args[1], session))
        else:
            self.send(session,self.filemanager.ls("", session))

    def handle_mkdir(self, args, session: UserSession):
        if len(args) != 2:
            self.send(session, "Length of mkdir command must be 2\n")
            return

        if self.filemanager.mkdir(args[1], session):
            self.send(session, "Directory creation succesful\n")
        else:
            self.send(session, "Directory creation failed\n")


    def send(self, session : UserSession, message: str):
        send_all_encrypted(session.get_conn(), session.get_keys(), message)

    def handle_command(self, message, session : UserSession):

        args = message.split(" ")
        args = [str(x) for x in args]

        cmd = args[0]

        if cmd == "user_create":
            self.handle_user_create(args, session)
        elif cmd == "whoami":
            self.handle_whoami(session)
        elif cmd == "login":
            self.handle_login(args, session)
        elif session.get_username():
            if cmd == "logout":
                self.handle_logout(session)
            elif cmd == "menu":
                self.handle_menu(session)
            elif cmd == "group_create":
                self.handle_group_create(args, session)
            elif cmd == "group_add":
                self.handle_group_add(args, session)
            elif cmd == "group_remove":
                self.handle_group_remove(args, session)
            elif cmd == "group_list":
                self.handle_group_list(args, session)
            elif cmd == "create":
                self.handle_create(args, session)
            elif cmd == "delete":
                self.handle_delete(args, session)
            elif cmd == "read":
                self.handle_read(args, session)
            elif cmd == "write":
                self.handle_write(args, session)
            elif cmd == "rename":
                self.handle_rename(args, session)
            elif cmd == "chmod":
                self.handle_chmod(args, session)
            elif cmd == "cd":
                self.handle_cd(args, session)
            elif cmd == "mkdir":
                self.handle_mkdir(args, session)
            elif cmd == "ls":
                self.handle_ls(args, session)
            elif cmd == "pwd":
                self.handle_pwd(session)
            else:
                self.send(session, "Invalid command\n")
        else:
            self.send(session ,"Invalid command\n")
    
    

    def handle_conn(self,conn : socket.socket):

        
        print("SENDING PUBLIC KEY!: ")
        print(self.conn_crypto.get_public_key())

        #send public key first
        send_all(conn,self.conn_crypto.get_public_key())

        print("PUBLIC KEY SENT")

        #receive client public key
        public_key_client = recv_all_unencrypted(conn).decode("UTF-8")

        print("PUBLIC KEY RECEIVED: ")
        print(public_key_client)
        
        cipher = CryptoManager(key=public_key_client)

        print("BEGINNING ENCRYPTED COMMUNICATION!")

        #user session object for working directory + session token
        sess = UserSession(conn,cipher)

        #begin message sharing with encryption
        while conn:

            #poc to check key exchange is working
            data = recv_all_encrypted(conn,self.conn_crypto).decode("UTF-8")
            print("CLIENT SENT:\n")
            print(data)
            print()

            #validate session token sent with message is legit

            
            self.handle_command(data,sess)

            #send_all_encrypted(conn,cipher,data)





    

        

    
        