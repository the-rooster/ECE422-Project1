import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import sys

from session import Session





def main():


    if len(sys.argv) != 4:
        print("Syntax is: python main.py <ipv6> <port> <4 or 6>")
        return


    ip = sys.argv[1]
    port = sys.argv[2]

    ip_family = socket.AF_INET6

    if sys.argv[3] == "4":
        ip_family = socket.AF_INET


    conn = socket.socket(ip_family,socket.SOCK_STREAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    conn.connect((ip,int(port)))

    print("Connected")


    #create encrypted communication session. creating this class creates the communication loop
    sess = Session(conn)


if __name__ == "__main__":
    main()

