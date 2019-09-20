"""
Created by: Ryan Stanbury
"""

import rsa
import time


def send_file(connection, pub_key, my_file, max_message_size, output=True):
    """
    Send file to server
    :param connection: Connection to server
    :param pub_key: Server's public key
    :param my_file: File to upload
    :param max_message_size: Maximum number of bytes that can be encrypted
    :param output: If output should be displayed
    :return:
    """

    # Open the file requested
    with open(my_file, 'rb') as file:

        # Read and send data from file
        while True:
            data = file.read(max_message_size)

            # Stop sending once file has finished being sent
            if not data:
                if output is True:
                    print('Finished sending file')
                break

            # Send data from the file
            else:
                if output is True:
                    print('Transmitting file...')
                data = rsa.encrypt(data, pub_key)
                connection.sendall(data)
                time.sleep(1)

        # Tell the server the file is finished being sent
        time.sleep(1)
        connection.sendall(rsa.encrypt(b'ENDED', pub_key))


def download_file(connection, priv_key, file_name, output=True):
    """
    Download file from client
    :param connection: Connection to client
    :param priv_key: Server's private key
    :param file_name: File to upload
    :param output: If output should be displayed
    :return:
    """

    # Receive next part of file
    data = rsa.decrypt(connection.recv(2048), priv_key)

    # If file not found on server
    if data == b'MISSING':
        raise ValueError

    # Create file
    with open(file_name, 'wb') as file:

        # Receive parts of file until completed
        while True:

            # Write incoming message to disk if not the end
            if not data == b'ENDED':
                file.write(data)
                if output is True:
                    print('Writing incoming file to disk')

            # Finish writing to disk
            else:
                if output is True:
                    print('Finished receiving file')
                break

            # Receive next part of file
            data = rsa.decrypt(connection.recv(2048), priv_key)
