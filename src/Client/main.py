import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


from session import Session





def main():

    conn = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    conn.connect(("2605:fd00:4:1001:f816:3eff:fe61:7eb6",8080))

    print("Connected")


    #create encrypted communication session. creating this class creates the communication loop
    sess = Session(conn)


if __name__ == "__main__":
    main()

