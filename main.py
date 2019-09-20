#!/usr/bin/python3.7

"""
Created by: Ryan Stanbury
"""

import sys
import ipaddress
import server
import client
import threading

# Options for presentation or debugging
rsa_keys_per_session = False
diffe_key_exchange = False
saved_rsa_keys = False


def fuzzing(username, password):
    """
    To be used only for fuzzing sections
    :return:
    """

    # Connect to database for credentials
    sql_ip, user, pwd, sql_port = server.db_info()
    credentials = server.db_connect(sql_ip, user, pwd, sql_port)
    database = server.db_setup(sql_ip, user, pwd, sql_port, credentials)

    return server.login(database, username, password)


def check_server_ip(ip):
    """
    Get a server IP to use
    :param ip: None or from command line
    :return: Proper IP of the server
    """

    # Keep track if corrects args were used
    first_run_client = 1

    # Get the IP from the user
    while True:

        # Check if ip is already set
        if ip is None:
            first_run_client = 0
            ip = input('Server IP address: ')

        # Make sure the IP address is valid
        try:
            ipaddress.ip_address(ip)
            if first_run_client == 1:
                print(' '.join(['Connecting to server at:', ip]))
            break

        except TypeError:
            raise ValueError

        except ipaddress.AddressValueError:
            raise ValueError

        except ipaddress.NetmaskValueError:
            raise ValueError

        # Reset ip and give error message
        except ValueError:
            ip = None
            print('Please enter a proper ipv4 address (xxx.xxx.xxx.xxx)', file=sys.stderr)

    return ip


def check_port(port):
    """
    Get a correct port to use
    :param port: None or from command line
    :return: Proper port to communicate on
    """

    # Keep track if corrects args were used
    first_run_port = 1

    # Port number
    while True:

        # Check if port is already set
        if port is None:
            first_run_port = 0
            port = input('Port: ')

        # Make sure the port the user entered is valid
        try:
            if 1024 <= int(port) <= 49151:
                if first_run_port == 1:
                    print(' '.join(['Using port:', str(port)]))
                break

            # If the port number is too high/low
            else:
                raise ValueError

        # Reset port and give error message
        except ValueError:
            print('Invalid port, please enter a port between 1024-49151', file=sys.stderr)
            port = None

    return port


def check_program_type(program_type):
    """
    Get a correct type of program to run as
    :param program_type: None or from command line
    :return: Server or Client
    """

    # Server or Client
    while True:

        # If no arguments are passed
        if program_type is None:

            # Ask the user for type of program to be run
            program_type = input('Should this machine be set up as a server or a client?'
                                 '\n1 - Server\n2 - Client\nEnter 1 or 2: ')

            # Accept or reject user's choice
            if program_type == '1':
                program_type = 'server'
                break
            elif program_type == '2':
                program_type = 'client'
                break
            else:
                print('Invalid option, try again', file=sys.stderr)

        # If using arguments
        else:

            # Accept or reject user's choice
            if program_type == 'server':
                print('Running as: Server')
                break
            elif program_type == 'client':
                print('Running as: Client')
                break

            # Reset the program type
            else:
                program_type = None
                print('Invalid program type, please try again', file=sys.stderr)

    return program_type


def save_settings(program_type, port, ip=None):
    """
    Create settings file
    :param program_type: Server = 1, Client = 2
    :param port: Port to communicate on
    :param ip: IP of the server to connect to
    """

    with open('settings.txt', 'w') as options:
        # Write the user's choices to the settings file
        options.write(''.join([program_type, '\n']))
        options.write(''.join([port, '\n']))

        # Write the IP address to the file if the variable exists
        if ip is not None:
            options.write(ip)


def settings(program_type=None, port=None, ip=None):
    """
    Get the parameters for how to run the program
    :param program_type: Server = 1, Client = 2
    :param port: Port to communicate on
    :param ip: IP of the server to connect to
    """

    try:
        # Detect if command line arguments were used
        if program_type is not None and port is not None:

            # Create new settings and overwrite old settings file if it exists
            raise FileNotFoundError

        # Try to load config file
        with open('settings.txt', 'r') as options:

            # Detect basic settings
            server_or_client = check_program_type(options.readline().strip())
            port = check_port(options.readline().strip())

            # Start as server on specified port
            if server_or_client == 'server':
                server.server_start(port=int(port))

            # Start as client with specified port and IP
            elif server_or_client == 'client':
                ip = check_server_ip(options.readline().strip())
                client.client_start(port=int(port), ip=ip)

    # If no config file exists, run first time setup
    except FileNotFoundError:

        if program_type is None:
            # Welcome message on first time setup
            print('Welcome to Secure Storage!')
            print('It seems this is the first time you are running this program, let\'s set a few things up.\n')

        # Get the program type
        program_type = check_program_type(program_type)

        # Get the port number
        port = check_port(port)

        # Ask for the server IP if the program will run as a client
        if program_type == 'client':

            # Get the server IP
            ip = check_server_ip(ip)

        # Write the options to a file
        save_settings(program_type=program_type, port=port, ip=ip)

        # Spawn Server or Client
        if program_type == 'server':
            server.server_start(port=int(port))
        elif program_type == 'client':
            client.client_start(port=int(port), ip=ip)


def main():
    """
    Start of the program, catches command line arguments and initializes the program
    :return:
    """

    try:

        # Check if command line arguments were used
        if len(sys.argv) > 1:

            # Verify correct number of arguments were used
            if len(sys.argv) != 3 and len(sys.argv) != 4:

                # Display error message and proper format to use
                print("Invalid number of arguments", file=sys.stderr)
                print("Correct server format: main.py server [port]", file=sys.stderr)
                print("Correct client format: main.py client [port] [ip]", file=sys.stderr)

            else:

                # Get the program type from the user
                program_type = sys.argv[1]

                # Get the port from the user
                port = sys.argv[2]

                # If arguments specify server
                if len(sys.argv) == 3:
                    settings(program_type=program_type, port=port)

                # If arguments specify client
                elif len(sys.argv) == 4:
                    ip = sys.argv[3]
                    settings(program_type=program_type, port=port, ip=ip)

        else:
            # Initialize program with no arguments used
            settings()

    # Close gracefully if the program is force quit
    except KeyboardInterrupt:
        print('\nQuiting program', file=sys.stderr)

        # Stop all of the server connections
        for thread in threading.enumerate():
            thread.setName('stop')

        print('Hit any button to close the program')


if __name__ == '__main__':
    main()
