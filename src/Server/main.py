import socket
from threading import Thread
from server import SecureFileSystemServer
import sys

sfs = SecureFileSystemServer()


def main():

    if len(sys.argv) != 3:
        print("Syntax is: python main.py <port> <4 or 6>")
        return
    

    port = int(sys.argv[1])

    ip_family = socket.AF_INET6
    interfaces = "::"

    if sys.argv[2] == "4":
        ip_family = socket.AF_INET
        interfaces = "0.0.0.0"

    #start tcp server. bind to all network interfaces
    server = socket.socket(ip_family,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind((interfaces,port))
    server.listen()

    if "admin" not in sfs.authenticator.users.keys():
        print("MUST REGISTER SYS ADMIN. Username is admin, choose password:\n")
        password = input("Admin Password: ")

        sfs.authenticator.new_user("admin",password)
        sfs.filemanager.new_user_dir("admin")

    else:
        print("ADMIN USER FOUND!")
    
    print(f"Starting server on all interfaces. Port is {port} and using ipv{sys.argv[2]}")
    while True:
        
        connection,address = server.accept()

        thread = Thread(target=sfs.handle_conn,args=(connection,),daemon=True)

        thread.start()

    return

if __name__ == "__main__":
    main()