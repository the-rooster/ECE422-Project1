import socket
from threading import Thread
from server import SecureFileSystemServer

sfs = SecureFileSystemServer()


def main():
    #start tcp server. bind to all network interfaces
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    server.bind(("0.0.0.0",8080))
    server.listen()

    print("LISTENING ON PORT 8080")

    
    while True:
        
        connection,address = server.accept()

        thread = Thread(target=sfs.handle_conn,args=(connection,),daemon=True)

        thread.start()

    return

if __name__ == "__main__":
    main()