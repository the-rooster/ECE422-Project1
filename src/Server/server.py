from Crypto.PublicKey import RSA
import socket
import base64

#to load utils package
import sys
sys.path.append('../')

from Utils.asymmanager import AsymmetricCryptoManager
from Utils.symmanager import SymmetricCryptoManager
from Utils.messages import *
from authenticator import Authenticator
from session import UserSession
from menu import menu
from filemanager import FileManager

class SecureFileSystemServer():

    def __init__(self):


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
            print('verify_integrity', self.filemanager.verify_integrity(args[1]))
            session.set_username(args[1])
            self.send(session, f"Succesfully logged in as {args[1]}\n")
            session.set_cwd("/home/" + args[1] + "/")
        else:
            self.send(session, "Failed to login\n")


    def handle_logout(self,session: UserSession):
        session.logout()
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
            res = self.filemanager.ls(args[1], session)
            self.send(session,res)
        else:
            res = self.filemanager.ls("", session)
            self.send(session,res)

        print(res)


    def handle_mkdir(self, args, session: UserSession):
        if len(args) != 2:
            self.send(session, "Length of mkdir command must be 2\n")
            return

        if self.filemanager.mkdir(args[1], session):
            self.send(session, "Directory creation succesful\n")
        else:
            self.send(session, "Directory creation failed\n")


    def handle_write(self, message : str, session: UserSession):
        args = message.split(" ",3)

        if len(args) != 4:
            self.send(session, "Length of write command must be 4\n")
            return

        if self.filemanager.write(args[1], args[2], args[3], session):
            self.send(session, "Write succesful\n")
        else:
            self.send(session, "Write failed\n")


    def handle_read(self, args, session: UserSession):
        if len(args) != 2:
            self.send(session, "Length of read command must be 2\n")
            return

        self.send(session, self.filemanager.read(args[1], session))

    def handle_chmod(self,args,session: UserSession):
        if len(args) != 3:
            self.send(session,"Length of chmod command must be 3\n")
            return

        if self.filemanager.chmod(args[1],args[2],session):
            self.send(session,"chmod succesful\n")
        else:
            self.send(session,"chmod failed\n")


    def handle_group_create(self, args, session):
        if len(args) != 2:
            self.send(session,"Length of group_create command must be 2\n")
            return

        if self.authenticator.group_create(args[1], session):
            self.send(session,"group_create succesful\n")
        else:
            self.send(session,"group_create failed\n")


    def handle_group_add(self, args, session):
        if len(args) != 3:
            self.send(session,"Length of group_add command must be 3\n")
            return

        if self.authenticator.group_add(args[1], args[2], session):
            self.send(session,"group_add succesful\n")
        else:
            self.send(session,"group_add failed\n")
            

    def handle_group_remove(self, args, session : UserSession):
        if len(args) != 3:
            self.send(session, "Length of group_remove command must be 3\n")
            return
            
        if self.authenticator.group_remove(args[1], args[2], session):
            self.send(session,"group_remove succeeded\n")
        else:
            self.send(session,"group_remove failed\n")


    def handle_group_list(self, args, session):

        if len(args) != 1:
            self.send(session,"Length of group_list command must be 1\n")
            return
        
        self.send(session,self.authenticator.group_list(session))

    def handle_group_join(self,args,session : UserSession):

        if len(args) != 2:
            self.send(session,"Length of group_join command must be 2\n")
            return
        
        if self.authenticator.group_join(args[1],session):
            self.send(session,"join group request sent\n")
            return
        
        self.send(session,"group_join failed")

    def handle_group_list_requests(self,args,session : UserSession):

        if len(args) != 2:
            self.send(session,"Length of group_list_requests command must be 2\n")
            return

        self.send(session,self.authenticator.group_list_requests(args[1],session))


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
            elif cmd == "group_join":
                self.handle_group_join(args,session)
            elif cmd == "group_list_requests":
                self.handle_group_list_requests(args,session)
            elif cmd == "create":
                self.handle_create(args, session)
            elif cmd == "delete":
                self.handle_delete(args, session)
            elif cmd == "read":
                self.handle_read(args, session)
            elif cmd == "write":
                self.handle_write(message, session)
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
        print("BEGINNING KEY EXCHANGE")

        public_key_client = recv_all_unencrypted(conn).decode("UTF-8")
        print("PUBLIC KEY RECEIVED:\n", public_key_client)
        
        rsa_cipher = AsymmetricCryptoManager(key=public_key_client)
        conn_cipher = SymmetricCryptoManager()

        print("SENDING SYMMETRIC KEY:\n", conn_cipher.get_key())
        send_all(conn,rsa_cipher.encrypt(conn_cipher.get_key()))

        print("BEGINNING ENCRYPTED COMMUNICATION")


        #user session object for working directory + session token
        sess = UserSession(conn,conn_cipher)

        #begin message sharing with encryption
        while conn:

            #poc to check key exchange is working
            data = recv_all_encrypted(conn,conn_cipher).decode("UTF-8")
            print("CLIENT SENT:\n")
            print(data)
            print()

            #validate session token sent with message is legit

            
            self.handle_command(data,sess)

            #send_all_encrypted(conn,cipher,data)
