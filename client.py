"""
Created by: Ryan Stanbury
"""

import binascii
import getpass
import os
import socket
import sys
import time

import pyDHE
import rsa
from rsa import common

import main
import shared


def login(connection, server_pub_key, priv_key):
    """
    Login to the server
    :param connection: Connection to the server
    :param server_pub_key: Server's public key
    :param priv_key: Client's public key
    """

    # Try until the user can login
    while True:

        # Get the username and password from the client
        username = input('Username: ')
        password = getpass.getpass('Password: ')

        # Send the username and password to the server
        connection.sendall(rsa.encrypt(username.encode(), server_pub_key))
        connection.sendall(rsa.encrypt(password.encode(), server_pub_key))

        # Get the login results from the server
        result = rsa.decrypt(connection.recv(1024), priv_key).decode()

        # Successful login
        if result == 'SUCCESS':
            return

        # Login failure
        elif result == 'FAILURE':
            print('Failed to login, please try again', file=sys.stderr)

        # Server connection lost
        elif not result:
            print('Server closed connection')
            sys.exit(0)


def upload(connection, server_pub_key, priv_key, max_message_size):
    """
    Upload a file to the server
    :param connection: Connection to the server
    :param server_pub_key: Server's public key
    :param priv_key: Client's private key
    :param max_message_size: Maximum bytes that can be encrypted
    """

    while True:
        # Get file name from user
        file_path = input('Which file would you like to send to the server?: ')

        # Verify file exists
        if os.path.isfile(file_path) is True:
            break

        # File doesn't exist
        else:
            print('Could not find specified file, please try again', file=sys.stderr)

    try:
        # Tell server file is being sent
        connection.sendall(rsa.encrypt(b'UPLOAD', server_pub_key))
        time.sleep(1)
        connection.sendall(rsa.encrypt(str.encode(file_path), server_pub_key))
        time.sleep(1)

        # Tell the server the file size of the file attempting to be uploaded
        connection.sendall(rsa.encrypt(str(os.path.getsize(file_path)).encode(), server_pub_key))
        time.sleep(1)

        # Get requirement from server
        data = rsa.decrypt(connection.recv(1024), priv_key)
        if data == b'PERMISSION CHECK':
            security_level = input('What security level should the file have?: ')
            connection.sendall(rsa.encrypt(security_level.encode(), server_pub_key))

        elif data == b'TRAVERSAL':
            print('Failed attempting to upload file outside of scope', file=sys.stderr)
            return

        elif data == b'SIZE EXCEEDED':
            print('Maximum storage exceeded', file=sys.stderr)
            return

        else:
            print('Unexpected response from server', file=sys.stderr)
            return

        # Attempt to upload file to the server
        status = rsa.decrypt(connection.recv(1024), priv_key)
        if status == b'CONTINUE':

            # Send the file to the server
            shared.send_file(connection, server_pub_key, file_path, max_message_size)

            # Get the result from the server
            result = rsa.decrypt(connection.recv(1024), priv_key)

            # If success
            if result == b'SUCCESS':
                print('Successfully added file to the storage system')

            # If failure
            elif result == b'FAILURE':
                print('Failed to add file to the storage system')

        # Attempt to overwrite file on the server
        elif status == b'OVERWRITE':

            # Ask the user if they would like to overwrite the file on the server
            while True:
                overwrite = input('Would you like to overwrite the file on the server with the same name?\n'
                                  '1 - Yes\n'
                                  '2 - No\n'
                                  'Choice: ')

                # Overwrite file
                if overwrite == '1':
                    connection.sendall(rsa.encrypt(b'YES', server_pub_key))
                    break

                # Don't overwrite file
                elif overwrite == '2':
                    connection.sendall((rsa.encrypt(b'NO', server_pub_key)))
                    return

                # Invalid input
                else:
                    print('Invalid input, please select an available option', file=sys.stderr)

            # Send the file to the server
            shared.send_file(connection, server_pub_key, file_path, max_message_size)

            # Get the result from the server
            result = rsa.decrypt(connection.recv(1024), priv_key)

            # If success
            if result == b'SUCCESS':
                print('Successfully added file to the storage system')

            # If failure
            elif result == b'FAILURE':
                print('Failed to add file to the storage system')

        else:
            print('Failed to upload file to the server with desired security level', file=sys.stderr)

    # Catch file not found
    except FileNotFoundError:
        print(''.join(['\nCould not find the file ', file_path]), file=sys.stderr)
        connection.sendall(rsa.encrypt(b'MISSING', server_pub_key))


def download(connection, priv_key, server_pub_key):
    """
    Download a file from the server
    :param connection: Connection to the server
    :param priv_key: Client's private key
    :param server_pub_key: Server's public key
    """

    # Get the filename from the user
    file_name = input('What file would you like to download from the server?: ')

    # Tell the server to prepare to download a file
    connection.sendall(rsa.encrypt(b'DOWNLOAD', server_pub_key))

    # Send the file name to the server
    connection.sendall(rsa.encrypt(file_name.encode(), server_pub_key))

    # Attempt to download the file
    try:
        shared.download_file(connection, priv_key, file_name)

    # If the server can't find the file that is asked for
    except ValueError:
        print(''.join(['\nThe file does not exist']), file=sys.stderr)


def talk_to_server(connection, server_pub_key, max_message_size, priv_key):
    """
    Handle communication to server
    :param connection: Connection to server
    :param server_pub_key: Server's public key
    :param max_message_size: Maximum bytes allowed to encrypt
    :param priv_key: Client's private key
    """

    # Attempt to login to the server
    login(connection, server_pub_key, priv_key)

    # Menu to interact with the server
    while True:
        message = input('\nWhat would you like to do?\n'
                        '1 - Upload a file\n'
                        '2 - Download a file\n'
                        '3 - Send a message\n'
                        '4 - Quit\n'
                        'Enter Choice: ')

        # Detect invalid input
        if not message == '1' and not message == '2' and not message == '3' and not message == '4':
            print('Please select a valid option', file=sys.stderr)
            continue

        # Send file to server
        elif message == '1':
            upload(connection, server_pub_key, priv_key, max_message_size)

        # Download a file form the server
        elif message == '2':
            download(connection, priv_key, server_pub_key)

        # Send message to server
        elif message == '3':
            send_echo(connection, max_message_size, server_pub_key, priv_key)

        # Exit program
        elif message == '4':
            print('Quitting program', file=sys.stderr)
            raise SystemExit


def send_echo(connection, max_message_size, server_pub_key, priv_key):
    """
    Send echo message to server
    :param connection: Connection to server
    :param max_message_size: Maximum bytes allowed to encrypt
    :param server_pub_key: Server's public key
    :param priv_key: Client's private key
    """

    # Get the message to send from the user
    while True:
        message = input('What would you like to send to the server?: ')
        message = str.encode(message)

        # Make sure the user enters something to send
        if message != b'':
            break
        else:
            print('Please enter a valid message', file=sys.stderr)

    # Break message into sections to allow for padding
    part = b''
    for cnt, section in enumerate(message):

        # Add current character to string
        part += bytes([section])

        # Send data if at max size or last character
        if len(part) == max_message_size or cnt == len(message) - 1:
            print('Sending', part.decode('utf-8'))
            connection.sendall(rsa.encrypt(part, server_pub_key))
            part = b''

    # Add delay with END token to make sure this is the only thing sent in the packet
    time.sleep(1)
    connection.sendall(rsa.encrypt(b'ENDED', server_pub_key))

    # Receive response parts from server
    response = b''
    while True:

        # Receive next part
        data = connection.recv(1024)
        try:
            data = rsa.decrypt(data, priv_key)

        # Catch if an invalid packet was sent
        except ValueError:
            raise ConnectionResetError

        # If the server terminated the session
        if not data:
            print('Disconnected from server')
            raise BrokenPipeError

        # If the packet contains more data in the message
        elif not data == b'ENDED':
            response = response + data

        # If the packet was the final packet in the message
        else:
            break

    # Display what was received from the client
    print(''.join(['Received \"', response.decode('utf-8'), '\" from server']))


def exchange_key(connection, pub_key):
    """
    Get RSA key from server
    :param connection: Connection to server
    :param pub_key: Client's public key
    :return: server_pub_key, server_pub_key_bytes, max_message_size
    """

    if main.diffe_key_exchange is False:
        # Get the server's public key
        server_pub_key_bytes = connection.recv(1024)

        # Send public key
        connection.sendall(rsa.PublicKey.save_pkcs1(pub_key))

    else:
        # Rounds of bit-shifting and XOR
        rounds = 64

        while True:

            # Generate 4096-bit keys (RFC 3526 Group 16)
            client_diffe_key = pyDHE.new(16)
            shared_secret = client_diffe_key.negotiate(connection)

            # Encrypt
            encrypted = int(binascii.hexlify(rsa.PublicKey.save_pkcs1(pub_key)).decode(), 16)
            for x in range(0, rounds):
                encrypted = encrypted ^ (shared_secret ** rounds)
                encrypted = encrypted << rounds
            encrypted = int(str(encrypted)[::-1])

            # Decrypt
            decrypted = encrypted
            decrypted = int(str(decrypted)[::-1])
            for x in range(rounds, 0, -1):
                decrypted = decrypted >> rounds
                decrypted = decrypted ^ (shared_secret ** rounds)

            # Check if able to decrypt
            try:
                binascii.unhexlify(hex(decrypted)[2:]).decode()
                client_success = True

            # Generate new keys upon failure and try again
            except UnicodeDecodeError:
                client_success = False
                pass
            except binascii.Error:
                client_success = False
                pass

            # Notify client about encryption status
            server_success = connection.recv(1024)
            if client_success is False:
                connection.send(b'DHE')
            else:
                connection.send(b'CONTINUE')

            # Get encryption status from client
            if client_success is False or server_success == b'DHE':
                pass
            elif server_success == b'CONTINUE':
                break

        # Hold encrypted server key
        server_encrypted = b''

        # Receive encrypted key from the server
        while True:
            data = connection.recv(8192)
            if data == b'ENDED':
                break
            elif data[-5:] == b'ENDED':
                server_encrypted += data[:-5]
                break
            server_encrypted += data

        # Send the encrypted key to the server
        connection.sendall(bytes(hex(encrypted).encode()))
        connection.send(b'ENDED')

        # Decrypt the client's public key
        decrypted = int(server_encrypted, 16)
        decrypted = int(str(int(decrypted))[::-1])
        for x in range(rounds, 0, -1):
            decrypted = decrypted >> rounds
            decrypted = decrypted ^ (shared_secret ** rounds)

        server_pub_key_bytes = binascii.unhexlify(hex(decrypted)[2:]).decode()

    server_pub_key = rsa.PublicKey.load_pkcs1(server_pub_key_bytes)
    # Determine max message size
    max_message_size = common.byte_size(server_pub_key.n) - 11

    # Return crypto key information
    return server_pub_key, server_pub_key_bytes, max_message_size


def client_start(port, ip):
    """
    Start the client
    :param port: Port to connect to
    :param ip: IP address of the server
    """

    # Generate RSA key
    print('\nGenerating RSA keys')
    # pub_key, priv_key = rsa.newkeys(4096, poolsize=2)
    #
    # #TESTING SAVE KEY
    # with open('client_pub.pem', mode='wb') as file:
    #     file.write(rsa.PublicKey.save_pkcs1(pub_key))
    #
    # with open('client_priv.pem', mode='wb') as file:
    #     file.write(rsa.PrivateKey.save_pkcs1(priv_key))
    #
    # sys.exit(0)

    #TESTING LOAD KEY
    with open('client_pub.pem', mode='rb') as file:
        pub_key = rsa.PublicKey.load_pkcs1(file.read())

    with open('client_priv.pem', mode='rb') as file:
        priv_key = rsa.PrivateKey.load_pkcs1(file.read())

    print(''.join(['Connecting to server at ', ip, ' on port ', str(port)]))

    # Spawn client
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip, port)

    # Connect to server
    while True:
        try:
            connection.connect(server_address)
            break
        except ConnectionRefusedError:
            print('Could not connect to server', file=sys.stderr)
            print('Retrying in 5 seconds...')
            time.sleep(5)

        except ConnectionResetError as e:
            print(e)
            raise BrokenPipeError

        except ValueError as e:
            print(e)
            raise BrokenPipeError

    # Send data to server
    try:

        # Exchange RSA keys with server
        server_pub_key, server_pub_key_bytes, max_message_size = exchange_key(connection, pub_key)

        talk_to_server(connection, server_pub_key, max_message_size, priv_key)

    except rsa.pkcs1.DecryptionError:
        print('Failed to decrypt message from server')

    except BrokenPipeError:
        pass

    except ConnectionResetError:
        print('Server disconnected')

    except ValueError:
        print('Server disconnected')

    # Close connection to server
    finally:
        print('Closing connection')
        connection.close()
