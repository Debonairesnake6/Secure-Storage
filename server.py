"""
Created by: Ryan Stanbury
"""

import socket
import time
import rsa
from rsa import common
import shared
import os
import sys
import threading
import pymysql
import getpass
import bcrypt
import ipaddress
import logging
import datetime
import pyDHE
import binascii
import main
import select

# Global logger
logger = None


def login(database, user, pwd):
    """
    Attempt to log the client into the service
    :param database: Database to query
    :param user: Username
    :param pwd: Password
    :return: True = successful login, False = failed login
    """

    # If the username or password contain invalid characters
    for user_input in (user, pwd):
        for char in user_input.encode():
            if char == 0:
                return False

    # If the username or password is too long
    if len(user) > 30 or len(pwd) > 60:
        return False

    # Create cursor to interact with the database
    cursor = database.cursor()

    # Get the stored password hash + salt for the desired user
    statement = 'SELECT password FROM users ' \
                'WHERE user = %s'
    value = user

    try:
        cursor.execute(statement, value)

    # If the username has unexpected input
    except AttributeError:
        return False

    stored_hash = cursor.fetchall()

    # If the user exists
    if len(stored_hash) == 1:

        # Hash + salt the given password
        pwd = pwd.encode()
        salt = stored_hash[0][0]
        given_pass = bcrypt.hashpw(pwd, salt.encode())

        # Check if the password is correct
        if given_pass.decode('utf-8') == stored_hash[0][0]:
            return True

        # The password is incorrect
        else:
            return False

    # If the user doesn't exist
    elif len(stored_hash) == 0:
        return False


def try_again():
    """
    Ask the user if they would like to re-enter the information
    :return: Yes or No response
    """

    # Give options to user
    retry = input('1 - Yes\n'
                  '2 - No\n'
                  'Choice:')

    # Return with the user's choice
    if retry == '2':
        return 'No'
    elif retry == '1':
        return 'Yes'
    else:
        print('Invalid option, please try again', file=sys.stderr)


def password_requirements(pwd):
    """
    Verify the entered password meets the requirements
    :param pwd: Given password
    :return: Hash + salted password passing requirements, or invalid for weak password
    """

    # Counts for parts of valid password
    num_cnt = 0
    lower_cnt = 0
    upper_cnt = 0
    special_cnt = 0

    # Get counts for each type of character
    for char in pwd:

        # Count numbers
        try:
            int(char)
            num_cnt += 1

        except ValueError:
            # Count lower case characters
            if char.islower() is True:
                lower_cnt += 1

            # Count upper case characters
            elif char.isupper() is True:
                upper_cnt += 1

            # Count special characters
            else:
                special_cnt += 1

    # Go through password requirements
    if num_cnt < 2 \
            or lower_cnt < 1 \
            or upper_cnt < 1 \
            or special_cnt < 1 \
            or len(pwd) < 12:

        # Print what the requirements are
        print('Password requirements;\n'
              '2+ numbers\n'
              '1+ lowercase letter\n'
              '1+ uppercase letter\n'
              '1+ special character\n'
              '12+ characters\n')

        # Return string stating the password was poor
        return 'invalid'

    # Hash and salt the password before returning it
    else:
        salt = bcrypt.gensalt()
        pwd = bcrypt.hashpw(pwd.encode(), salt)
        return pwd


def create_user(database):
    """
    Create new user in the database
    :param database: Database connection
    :return:
    """

    # Get the username from the user
    user = input('\nUsername: ')

    # Get a valid password from the user
    while True:
        pwd = getpass.getpass('Password: ')

        # Send password to get verified it is strong enough
        pwd = password_requirements(pwd)

        # Check if the password met the requirements
        if pwd != 'invalid':
            break

    # Get a permission level from the user
    while True:
        level = input('Level: ')

        # Get the levels currently in the database
        cursor = database.cursor()
        cursor.execute('SELECT level from user_levels')
        db_levels = cursor.fetchall()

        # Check if the level is in the database
        if (level,) not in db_levels:

            # Get the option from the user
            print('Invalid security level, would you like to create that security level?')

            # Ask the user if they would like to create the level
            if try_again() == 'No':
                print('Please enter a valid security level', file=sys.stderr)
            else:
                if create_security_level(database, level) is True:
                    break

        else:
            break

    # Attempt to add the user into the database
    try:
        # Create cursor to control database
        cursor = database.cursor()

        # Create statement and execute query
        statement = 'INSERT INTO ' \
                    'users(user, password, level) ' \
                    'VALUES (%s, %s, %s)'
        values = (user, pwd, level)
        cursor.execute(statement, values)

        # Push changes to database
        database.commit()
        print('%s was added with security level: %s' % (user, level))

    except pymysql.InternalError as e:
        print(e)

    # Catch if table is missing
    except pymysql.ProgrammingError:
        print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
        sys.exit(0)

    # Catch username already existing
    except pymysql.IntegrityError as e:
        if e.args[0] == 1062:
            print('Could not create user \'%s\', username already exists\n' % user, file=sys.stderr)
        elif e.args[0] == 1452:
            print('Invalid security level\n', file=sys.stderr)
        else:
            print(e)


def delete_user(database):
    """
    Delete a user from the database
    :param database: Database to query
    """

    # Get the user to delete
    remove_user = input('\nWhich user would you like to remove?: ')
    statement = 'DELETE FROM users ' \
                'WHERE user=%s'

    # Create cursor to interact with the database
    cursor = database.cursor()

    # Attempt to remove the user from the database
    try:
        cursor.execute(statement, remove_user)

        # Push changes to the database
        database.commit()
        print('Removed %s from the database' % remove_user)

    # Catch if the table is missing
    except pymysql.ProgrammingError as e:
        if e.args[0] == 1064:
            print('Invalid syntax for the statement {}'.format(statement))
        else:
            print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
            sys.exit(0)


def modify_user(database):
    """
    Modify information about a user in the database
    :param database: Database to query
    """

    # Create cursor to interact with database
    cursor = database.cursor()

    # Verify the user already exists
    while True:
        # Ask which user should be modified
        user = input('\nWhich user would you like to modify?: ')

        try:
            # Create statement to query database
            statement = 'SELECT user FROM users ' \
                        'WHERE user=%s'
            cursor.execute(statement, user)

            # Verify the user exists
            exists = cursor.fetchall()

        # Catch if table is missing
        except pymysql.ProgrammingError:
            print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
            sys.exit(0)

        # If the user exists
        if len(exists) == 1:
            break

        # If the user does not exist
        elif len(exists) == 0:
            print('The user does not exists in the database', file=sys.stderr)

        # If multiple of the same user exist
        else:
            print('The database has multiple copies of the same user, please resolve this issue', file=sys.stderr)
            sys.exit(0)

    # Ask what to modify about the user
    while True:
        change = input('\nWhat would you like to modify about the user?\n'
                       '1 - Password\n'
                       '2 - Level\n'
                       'Choice: ')

        # Change the password
        if change == '1':
            # Loop until strong enough password
            while True:
                pwd = getpass.getpass('\nEnter the new password for %s:' % user)

                # Verify the password meets the requirements
                pwd = password_requirements(pwd)

                # Break out of password loop if strong enough
                if pwd != 'invalid':
                    break

            try:
                # Create statement to submit to make changes
                statement = 'UPDATE users ' \
                            'SET password=%s ' \
                            'WHERE user=%s'
                cursor.execute(statement, (pwd, user))

                # Push changes to database
                database.commit()
                print('Successfully changed the password for %s' % user)

            # Catch if table is missing
            except pymysql.ProgrammingError:
                print('The proper table no longer exists.\nPlease restart the program to fix this issue.',
                      file=sys.stderr)
                sys.exit(0)

            # Break back to main menu
            break

        # Change the security level
        elif change == '2':
            level = input('Enter the new security level for %s: ' % user)

            try:
                # Create statement to submit to make changes
                statement = 'UPDATE users ' \
                            'SET level=%s ' \
                            'WHERE user=%s'
                cursor.execute(statement, (level, user))

                # Push changes to database
                database.commit()
                print('Seccessfully changed the level for %s' % user)

            # Catch if table is missing
            except pymysql.ProgrammingError:
                print('The proper table no longer exists.\nPlease restart the program to fix this issue.',
                      file=sys.stderr)
                sys.exit(0)

            # Break back to the main menu
            break

        # Catch invalid input
        else:
            print('Please select a valid option', file=sys.stderr)


def create_security_level(database, level=None):
    """
    Create a new security level
    :param database: Database to query
    :param level: Name of the security level
    :return: True = success, False = failure
    """

    # Get security information from user
    if level is None:
        level = input('What is the name of the security level?: ')
    includes = input('What other level does it inherit? (Leave blank if none): ')

    # Add new security level to the database
    try:
        # Create a cursor to interact with the database
        cursor = database.cursor()

        # Create statement and execute query
        statement = 'INSERT INTO ' \
                    'user_levels(level, includes) ' \
                    'VALUES (%s, %s)'
        values = (level, includes)
        cursor.execute(statement, values)

        # Push changes to database
        database.commit()
        print('Security level %s has been added' % level)
        return True

    # Catch if table is missing
    except pymysql.ProgrammingError:
        print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
        sys.exit(0)

    except pymysql.IntegrityError as e:
        if e.args[0] == 1062:
            print('Security level %s already exists' % level, file=sys.stderr)
            return False
        else:
            print(e)
            return False


def delete_security_level(database):
    """
    Delete security level from the database
    :param database: Database to query
    """

    # Get the security level to delete
    level = input('\nWhich level would you like to remove?: ')

    # Create cursor to interact with database
    cursor = database.cursor()

    try:
        # Create and execute statement
        statement = 'DELETE FROM user_levels ' \
                    'WHERE level=%s'
        cursor.execute(statement, level)

        # Push changes to database
        database.commit()
        print('Removed security level %s from the database' % level)

    # Catch if table is missing
    except pymysql.ProgrammingError:
        print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
        sys.exit(0)

    except pymysql.IntegrityError as e:
        if e.args[0] == 1451:
            print('Cannot remove security level %s. At least 1 user is using that level.' % level, file=sys.stderr)
        else:
            print(e, file=sys.stderr)


def create_file(database, path=None, owner=None, security_level=None):
    """
    Add a file to the database
    :param database: Database to query
    :param path: Path of file
    :param owner: User that owns the file
    :param security_level: Security level of the file
    :return: True = success, False = failure
    """

    # Create cursor to interact with the database
    cursor = database.cursor()

    # If the fields were already given
    if path is not None and owner is not None and security_level is not None:

        # Insert file with given fields
        try:
            # Create statement to execute
            statement = 'INSERT INTO ' \
                        'file_permissions (path, owner, level) ' \
                        'VALUES (%s, %s, %s)'
            values = (path, owner, security_level)
            cursor.execute(statement, values)

            database.commit()
            logger.info('{}: Successfully added {} to the database'.format(threading.current_thread().name, path,))
            return True

        # Catch if table is missing
        except pymysql.ProgrammingError:
            print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
            sys.exit(0)

        # Catch invalid security level
        except pymysql.IntegrityError as e:
            if e.args[0] == 1452:
                logger.info('{}: Invalid security level for {}'.format(threading.current_thread().name, path))
                return False
            else:
                logger.info('{}: Error occurred for {}: {}'.format(threading.current_thread().name, path, e.args[1]))
                return False

    # Get the file path from the user
    while True:
        path = input('What is the file path?: ')

        # Verify file exists
        if os.path.isfile(path) is True:
            break

        # If it doesn't then loop
        else:

            # Ask the user if they want to continue
            while True:
                print('Could not find the file specified, would you like to try again?', file=sys.stderr)

                if try_again() == 'No':
                    return
                else:
                    break

    # Get the owner from the user
    while True:
        owner = input('Which users owns the file? (leave blank for none): ')

        # If the owner is blank don't check if they exist
        if owner != '':

            cursor.execute('SELECT user FROM users')
            users = cursor.fetchall()

            # If the user doesn't exist
            if (owner,) not in users:
                print('The user %s does not exist, would you like to try again?' % owner, file=sys.stderr)

                if try_again() == 'No':
                    return

            # If the owner does exist
            elif (owner,) in users:
                break

        # If the file doesn't have an owner
        elif owner == '':
            break

    # Get the security level from the user and execute statement
    while True:
        security_level = input('What is the security level of the file?: ')

        try:
            # Create statement to execute
            statement = 'INSERT INTO ' \
                        'file_permissions (path, owner, level) ' \
                        'VALUES (%s, %s, %s)'
            values = (path, owner, security_level)
            cursor.execute(statement, values)

            database.commit()
            print('Successfully added the file information to the database')
            return

        except pymysql.IntegrityError as e:
            if e.args[0] == 1452:
                print('Invalid security level\n', file=sys.stderr)
            else:
                print(e)


def delete_file(database, path=None, output=True):
    """
    Remove a file form the database
    :param database: Database to query
    :param path: Path of file
    :param output: Display status message if not overwriting file
    :return: True = success, False = failure
    """
    # Get the user to delete
    if path is None:
        path = input('\nWhich file would you like to remove?: ')

    # Create cursor to interact with the database
    cursor = database.cursor()

    try:
        # Attempt to remove the user from the database
        statement = 'DELETE FROM file_permissions ' \
                    'WHERE path=%s'
        cursor.execute(statement, path)

        # Push changes to the database
        database.commit()

        if output is True:
            print('Removed the file information from the database')
        return True

    except pymysql.IntegrityError as e:
        print(e)
        return False

    # Catch if table is missing
    except pymysql.ProgrammingError:
        print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
        sys.exit(0)


def modify_file(database):
    """
    Modify file information in the database
    :param database: Database to query
    """
    # Create cursor to interact with database
    cursor = database.cursor()

    # Verify the user already exists
    while True:
        # Ask which user should be modified
        path = input('\nWhich file would you like to modify?: ')

        try:
            # Create statement to query database
            statement = 'SELECT path FROM file_permissions ' \
                        'WHERE path=%s'
            cursor.execute(statement, path)
            exists = cursor.fetchall()

        # Catch if table is missing
        except pymysql.ProgrammingError:
            print('The proper table no longer exists.\nPlease restart the program to fix this issue.', file=sys.stderr)
            sys.exit(0)

        # If the file exists
        if len(exists) == 1:
            break

        # If the file doesn't exist
        elif len(exists) == 0:
            print('The file does not exists in the database', file=sys.stderr)

        # If multiple of the same file exist
        else:
            print('The database has multiple copies of the same file, please resolve this issue', file=sys.stderr)
            sys.exit(0)

    # Ask what to modify about the user
    while True:
        change = input('\nWhat would you like to modify about the file?\n'
                       '1 - Owner\n'
                       '2 - Level\n'
                       'Choice: ')

        # Change the owner
        if change == '1':

            # Get the new owner from the user
            while True:
                owner = input('Who is the new owner of the file? (leave blank for none): ')

                # If the owner is blank, don't check if they exist
                if owner != '':

                    try:
                        cursor.execute('SELECT user FROM users')
                        users = cursor.fetchall()

                    # Catch if table is missing
                    except pymysql.ProgrammingError:
                        print('The proper table no longer exists.\nPlease restart the program to fix this issue.',
                              file=sys.stderr)
                        sys.exit(0)

                    # If the user doesn't exist
                    if (owner,) not in users:
                        print('The user %s does not exist, would you like to try again?', file=sys.stderr)

                        if try_again() == 'No':
                            return

                    # If the owner does exist
                    elif (owner,) in users:
                        break

                # If the file doesn't have an owner
                elif owner == '':
                    break

            try:
                # Create statement to submit to make changes
                statement = 'UPDATE file_permissions ' \
                            'SET owner=%s ' \
                            'WHERE path=%s'
                cursor.execute(statement, (owner, path))

                # Push changes to database
                database.commit()
                print('Successfully changed the owner for the file')

            # Catch if table is missing
            except pymysql.ProgrammingError:
                print('The proper table no longer exists.\nPlease restart the program to fix this issue.',
                      file=sys.stderr)
                sys.exit(0)

            # Break back to main menu
            return

        # Change the security level
        elif change == '2':

            # Get the security level from the user
            while True:
                level = input('Enter the new security level for the file: ')

                try:
                    # Get the levels currently in the database
                    cursor = database.cursor()
                    cursor.execute('SELECT level from user_levels')
                    db_levels = cursor.fetchall()

                # Catch if table is missing
                except pymysql.ProgrammingError:
                    print('The proper table no longer exists.\nPlease restart the program to fix this issue.',
                          file=sys.stderr)
                    sys.exit(0)

                # If the level is in the database
                if (level,) not in db_levels:

                    # Get the option from the user
                    while True:
                        print('Invalid security level, would you like to try again?', file=sys.stderr)

                        # Ask the user if they would like to try again
                        if try_again() == 'No':
                            return
                        else:
                            break

                # If the file is not in the database
                else:
                    break

            try:
                # Create statement to submit to make changes
                statement = 'UPDATE file_permissions ' \
                            'SET level=%s ' \
                            'WHERE path=%s'
                cursor.execute(statement, (level, path))

                # Push changes to database
                database.commit()
                print('Successfully changed the level for the file')

            # Catch if table is missing
            except pymysql.ProgrammingError:
                print('The proper table no longer exists.\nPlease restart the program to fix this issue.',
                      file=sys.stderr)
                sys.exit(0)

            # Break back to the main menu
            return

        # Catch invalid input
        else:
            print('Please select a valid option', file=sys.stderr)


def view_clients(block=False):
    """
    Display the IP and port of connected clients
    :param block: Detect if coming from the block client method
    """

    # Hold all client and active threads
    active_clients = []
    active_threads = threading.enumerate()

    # Check each thread to verify it is a client
    for thread in active_threads:

        try:
            # Check if the name is a valid IP
            ipaddress.ip_address(thread.name.split(':')[0])

            # Add the client to the client dictionary
            active_clients.append('{}:{}'.format(str(thread.name.split(':')[0]), str(thread.name.split(':')[1])))

        # Catch threads which are not clients
        except ValueError:
            pass

    print('\nActive clients;')
    # Print each client
    for cnt, client in enumerate(active_clients):
        print('{} - {}'.format(cnt + 1, client))

    # If queried by the block client method
    if block is True:
        return active_clients, active_threads


def block_client():
    """
    Stop a client's connection
    """

    while True:
        # Get the current client list
        active_clients, active_threads = view_clients(block=True)

        # Ask the user for which client to block
        client = input('\nWhich client would you like to block?: ')

        # Verify the selected client is valid
        try:
            client = int(client)

            # Check if the specified client is an actual connection
            if client > len(active_clients):
                break

            # Close the selected connection
            else:
                for thread in active_threads:
                    if thread.name == active_clients[client - 1]:
                        thread.setName('stop')
                return
        except ValueError:

            # Ask the user if they would like to try again
            print('Invalid client selected, would you like to try again?', file=sys.stderr)
            if try_again() == 'No':
                break

        except RuntimeError as e:
            print(e, file=sys.stderr)


def server_input(database):
    """
    Ask the user how they would like to interact with the server
    :param database: Database to connect to
    """

    while True:
        option = input('\nWhat would you like to do?\n'
                       '1  - Create user\n'
                       '2  - Delete user\n'
                       '3  - Modify user\n'
                       '4  - Create security level\n'
                       '5  - Delete security level\n'
                       '6  - Create file\n'
                       '7  - Delete file\n'
                       '8  - Modify file\n'
                       '9  - View clients\n'
                       '10 - Block client\n'
                       'Choice:')

        if threading.current_thread().name == 'stop':
            return

        if option == '1':
            create_user(database)
        elif option == '2':
            delete_user(database)
        elif option == '3':
            modify_user(database)
        elif option == '4':
            create_security_level(database)
        elif option == '5':
            delete_security_level(database)
        elif option == '6':
            create_file(database)
        elif option == '7':
            delete_file(database)
        elif option == '8':
            modify_file(database)
        elif option == '9':
            view_clients()
        elif option == '10':
            block_client()
        else:
            print('Invalid option, please try again', file=sys.stderr)


def db_info(ip=None, port=None):
    """
    Get the information to connect to the database
    :param ip: IP address of the database
    :param port: Port to connect on
    :return: IP address, username, password, int(port)
    """

    user = None
    pwd = None

    # Get the address of the server
    while True:
        if ip is None:
            ip = input('What is the IP address of the MySQL server?: ')
        try:
            ipaddress.ip_address(ip)
            break
        except ValueError:
            ip = None
            print('Please enter a proper ipv4 address (xxx.xxx.xxx.xxx)', file=sys.stderr)

    # Get the username
    if user is None:
        user = input('What is your username?: ')

    # Get the password
    if pwd is None:
        pwd = getpass.getpass('Password: ')

    # Get port
    while True:
        if port is None:
            port = input('What port is the server running on?: ')
        try:
            if 0 < int(port) < 65536:
                break
        except ValueError:
            port = None
            print('Invalid port, please enter a port between 1-65535', file=sys.stderr)

    # Return the information about the database
    return ip, user, pwd, int(port)


def db_connect(ip, user, pwd, port, db=''):
    """
    Connect to the database
    :param ip: IP of the database
    :param user: Username to log into the database
    :param pwd: Password of the user
    :param port: Port to connect on
    :param db: Name of the database
    :return: Connection to database
    """

    # Keep attempting to connect to the database
    while True:

        # Attempt to connect to the database
        try:
            credentials = pymysql.connect(host=ip, user=user, passwd=pwd, db=db, port=port)
            return credentials

        # Catch errors when trying to connect
        except pymysql.OperationalError as e:

            # Catch invalid login info
            if e.args[0] == 1045:
                print('\nInvalid user/pass, please try again', file=sys.stderr)
                ip, user, pwd, port = db_info(ip=ip, port=port)

            # Catch any unknown errors
            else:
                print('\nUnable to connect to the MySQL database.\nReason:', e.args[1], file=sys.stderr)

                try_again_answer = input('Entered information;\n'
                                         'IP - %s\n'
                                         'User - %s\n'
                                         'Port - %s\n'
                                         'Would you like to try again? (yes/no):' % (ip, user, port))

                # Ask the user if they would like to try again
                if try_again_answer == 'yes':
                    ip, user, pwd, port = db_info()

                # If the user wants to stop
                else:
                    print('Quitting...')
                    sys.exit(0)


def db_setup(ip, user, pwd, port, credentials):
    """
    Setup the database with the required tables
    :param ip: IP of the server
    :param user: Username to login to the database
    :param pwd: Password of the user
    :param port: POrt to connect on
    :param credentials: Database connection
    :return: Database connection
    """

    # Create cursor to interact with database
    cursor = credentials.cursor()

    # Create database if it does not exist
    cursor.execute('SHOW DATABASES')
    if ('secure_storage',) not in cursor.fetchall():
        print('Creating SecureStorage database...')
        cursor.execute('CREATE DATABASE secure_storage')

    # Connect to database and create cursor
    credentials = db_connect(ip, user, pwd, port, db='secure_storage')
    cursor = credentials.cursor()

    # Grab all current tables to verify if the needed one exist
    cursor.execute('SHOW TABLES')
    tables = cursor.fetchall()

    # Create user levels table if it does not exist
    if len(tables) == 0 or ('user_levels',) not in tables:
        print('Creating user levels table...')
        cursor.execute('CREATE TABLE user_levels('
                       'level VARCHAR(20) PRIMARY KEY,'
                       'includes VARCHAR(20))')

    # Create User table if it does not exist
    if len(tables) == 0 or ('users',) not in tables:
        print('Creating users table...')
        cursor.execute('CREATE TABLE users('
                       'id INT AUTO_INCREMENT PRIMARY KEY,'
                       'user VARCHAR(30) UNIQUE,'
                       'password VARCHAR(128),'
                       'level VARCHAR(20),'
                       'FOREIGN KEY (level) REFERENCES user_levels (level))')

    # Create file permission table if it does not exist
    if len(tables) == 0 or ('file_permissions',) not in tables:
        print('Creating file permission table...')
        cursor.execute('CREATE TABLE file_permissions('
                       'path VARCHAR (255) PRIMARY KEY,'
                       'owner VARCHAR(30),'
                       'level VARCHAR(20),'
                       'FOREIGN KEY (level) references user_levels (level))')

    # Finish and push changes
    credentials.commit()
    return credentials


def connection_handler(priv_key, pub_key, connection, database):
    """
    Handle the connection to the client
    :param priv_key: Server's private key
    :param pub_key: Server's public key
    :param connection: Connection to the client
    :param database: Connection to the database
    """

    # Start to talk to client
    logger.info('{}: Client connected'.format(threading.current_thread().name))

    # Open connection to client
    try:
        # Exchange RSA keys with client
        client_pub_key_bytes, client_pub_key, max_message_size = exchange_key(connection, pub_key)

        # Get the client to login
        while True:

            # Get the username and password from the client
            username = rsa.decrypt(connection.recv(1024), priv_key).decode()
            password = rsa.decrypt(connection.recv(1024), priv_key).decode()

            # Check for successful login
            if login(database, username, password):
                connection.sendall(rsa.encrypt(b'SUCCESS', client_pub_key))
                break

            # Login failure
            else:
                connection.sendall(rsa.encrypt(b'FAILURE', client_pub_key))

        # Transmit data between server and client
        while True:

            # Check if the client is sending data
            client_ready = select.select([connection], [], [], 0)

            # If data was sent
            if client_ready[0]:
                data = connection.recv(1024)

                # Client sends empty packet when closing the connection
                if not data:
                    logger.info('{}: Client terminated connection'.format(threading.current_thread().name))
                    raise BrokenPipeError

                # Decrypt the data
                else:
                    data = rsa.decrypt(data, priv_key)

                # Detect if incoming message is a file
                if data == b'UPLOAD':

                    upload(connection, client_pub_key, priv_key, username, database)

                elif data == b'DOWNLOAD':

                    download(connection, client_pub_key, priv_key, username, database, max_message_size)

                # Detect incoming echo message
                else:

                    # Receive and send message back to client
                    echo_message(data, connection, priv_key, client_pub_key, max_message_size)

            # Stop thread if it was asked to be
            if threading.current_thread().name == 'stop':
                raise BrokenPipeError

    except BrokenPipeError as e:
        logger.info('{}: {}'.format(threading.current_thread().name, e))

    # Catch if the client's connection breaks
    except ConnectionResetError as e:
        logger.info('{}: {}'.format(threading.current_thread().name, e))

    # Invalid username/password when decrypting
    except ValueError as e:
        logger.info('{}: {}'.format(threading.current_thread().name, e))

    # Failed to decrypt message
    except rsa.pkcs1.DecryptionError as e:
        logger.info('{}: {}'.format(threading.current_thread().name, e.args[0]))

    # Close connection to client
    finally:
        connection.close()
        logger.info('{}: Connection to client closed'.format(threading.current_thread().name))


def echo_message(data, connection, priv_key, client_pub_key, max_message_size):
    """
    Receive and echo back a message from the client
    :param data: First packet of the message
    :param connection: Connection to the client
    :param priv_key: Server's private key
    :param client_pub_key: Client's public key
    :param max_message_size: Maximum size of message to send based on RSA key
    :return:
    """

    # First part of the message
    message = data

    # Rebuild the rest of the message
    while True:
        # Receive next part
        data = connection.recv(1024)
        data = rsa.decrypt(data, priv_key)

        # Client sends empty packet when closing the connection
        if not data:
            raise BrokenPipeError

        # Accept next part of message
        elif not data == b'ENDED':
            message = message + data

        # End of message flag received
        else:
            break

    logger.info(''.join(['{}: Received \"'.format(threading.current_thread().name),
                         message.decode('utf-8'),
                         '\" from client']))

    # Simple echo server
    logger.info('{}: Echoing message back to client'.format(threading.current_thread().name))

    # Break message into sections to allow for padding
    part = b''
    for cnt, section in enumerate(message):

        # Add current character to string
        part += bytes([section])

        # Send data if at max size or last character
        if len(part) == max_message_size or cnt == len(message) - 1:
            connection.sendall(rsa.encrypt(part, client_pub_key))
            part = b''

    # Add delay with ENDED token to make sure this is the only thing sent in the packet
    time.sleep(1)
    connection.sendall(rsa.encrypt(b'ENDED', client_pub_key))


def exchange_key(connection, pub_key):
    """
    Exchange RSA keys with client
    :param connection: Connection to client
    :param pub_key: Server's public key
    :return: client_pub_key_bytes, client_pub_key
    """

    if main.diffe_key_exchange is False:
        # Send public key
        connection.sendall(rsa.PublicKey.save_pkcs1(pub_key))

        # Get client's public key
        client_pub_key_bytes = connection.recv(1024)

    else:

        # Rounds of bit-shifting and XOR
        rounds = 64

        while True:

            # Generate 4096-bit keys (RFC 3526 Group 16)
            server_diffe_key = pyDHE.new(16)
            shared_secret = server_diffe_key.negotiate(connection)

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
                server_success = True

            # Generate new keys upon failure and try again
            except UnicodeDecodeError:
                server_success = False
                pass
            except binascii.Error:
                server_success = False
                pass

            # Notify client about encryption status
            if server_success is False:
                connection.send(b'DHE')
            else:
                connection.send(b'CONTINUE')

            # Get encryption status from client
            client_success = connection.recv(1024)
            if server_success is False or client_success == b'DHE':
                continue
            elif client_success == b'CONTINUE':
                break

        # Send the encrypted key to the client
        connection.sendall(bytes(hex(encrypted).encode()))
        connection.send(b'ENDED')

        # Hold encrypted client key
        client_encrypted = b''

        # Receive encrypted key from client
        while True:
            data = connection.recv(8192)
            if data == b'ENDED':
                break
            elif data[-5:] == b'ENDED':
                client_encrypted += data[:-5]
                break
            client_encrypted += data

        # Decrypt the client's public key
        decrypted = int(client_encrypted, 16)
        decrypted = int(str(decrypted)[::-1])
        for x in range(rounds, 0, -1):
            decrypted = decrypted >> rounds
            decrypted = decrypted ^ (shared_secret ** rounds)

        client_pub_key_bytes = binascii.unhexlify(hex(decrypted)[2:]).decode()

    # Verify the message received was a key
    try:
        client_pub_key = rsa.PublicKey.load_pkcs1(client_pub_key_bytes)

        # Determine max message size
        max_message_size = common.byte_size(client_pub_key.n) - 11

        return client_pub_key_bytes, client_pub_key, max_message_size

    # Detect invalid RSA key
    except ValueError:
        logger.error('{}: Invalid RSA key detected'.format(threading.current_thread().name))

        # Kill connection
        raise BrokenPipeError


def server_start(port):
    """
    Start the server
    :param port: Port to listen on
    :return:
    """

    # Get the current date and time
    date = datetime.datetime.now()
    log_format = '%(asctime)s %(message)s'
    day = '{:4d}-{:02d}-{:02d}'.format(date.year, date.month, date.day)
    current_time = '{:02d}-{:02d}-{:02d}'.format(date.hour, date.minute, date.second)

    # Create a new log file for the session
    try:
        logging.basicConfig(filename='Logs/ServerLogs - {} {}.txt'.format(day, current_time),
                            format=log_format,
                            level=logging.INFO)

    # If the folder was not found, create it then create the log file
    except FileNotFoundError:
        os.mkdir('Logs')
        logging.basicConfig(filename='Logs/ServerLogs - {} {}.txt'.format(day, current_time),
                            format=log_format,
                            level=logging.INFO)

    # Pull down the global logger and set it to the current logger
    global logger
    logger = logging.getLogger()

    if main.saved_rsa_keys is False:

        # Generate RSA key
        print('\nGenerating RSA key')
        pub_key, priv_key = rsa.newkeys(2048, poolsize=2)

    else:

        try:
            with open('server_pub.pem', mode='rb') as file:
                pub_key = rsa.PublicKey.load_pkcs1(file.read())

            with open('server_priv.pem', mode='rb') as file:
                priv_key = rsa.PrivateKey.load_pkcs1(file.read())

        except FileNotFoundError:
            print('Could not find RSA keys, will create them')

            pub_key, priv_key = rsa.newkeys(2048, poolsize=2)

            with open('server_pub.pem', mode='wb') as file:
                file.write(rsa.PublicKey.save_pkcs1(pub_key))

            with open('server_priv.pem', mode='wb') as file:
                file.write(rsa.PrivateKey.save_pkcs1(priv_key))

    # Spawn server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port)

    # Attempt to bind to socket
    try:
        sock.bind(server_address)

    # Catch if the port is already in use
    except OSError:
        print('Port already in use, please select a different port')
        sys.exit(0)

    # Connect to database for credentials
    sql_ip, user, pwd, sql_port = db_info()
    credentials = db_connect(sql_ip, user, pwd, sql_port)
    database = db_setup(sql_ip, user, pwd, sql_port, credentials)

    # Maximum amount of clients to listen for
    while True:
        client_max = input('How many client should be able to connect at a time?: ')

        # Verify the maximum number of clients is a valid number
        try:
            if 1 <= int(client_max) <= 1000:
                client_max = int(client_max)
                break

            # If the number is outside of the specified range
            else:
                raise ValueError

        # If the input was not a number
        except ValueError:
            print('Please enter a number between 1-1000', file=sys.stderr)

    # Start listening for clients
    sock.listen(client_max)

    # Array to hold threads
    all_client_threads = []

    # Get input from server
    thread = threading.Thread(target=server_input,
                              args=(database,),
                              name='server_input')
    all_client_threads.append(thread)
    thread.start()

    # Accept connections
    while True:

        # Make sure the number of clients doesn't exceed the max
        if len(all_client_threads) < client_max + 1:
            connection, client_address = sock.accept()

            # Create thread to handle client communication
            thread = threading.Thread(target=connection_handler,
                                      args=(priv_key, pub_key, connection, database),
                                      name=':'.join([client_address[0], str(client_address[1])]))

            # Append to thread list and start
            all_client_threads.append(thread)
            thread.start()
            thread.join()

        # If max connections wait
        else:
            time.sleep(2)


def upload(connection, client_pub_key, priv_key, username, database):
    """
    Client wants to upload a file to the server
    :param connection: Connection to client
    :param client_pub_key: Client's public key
    :param priv_key: Server's private key
    :param username: Check for permissions based on username
    :param database: Database connection
    """

    # Download file from client
    logger.info('{}: Detected incoming file'.format(threading.current_thread().name))

    # Retrieve file path
    data = rsa.decrypt(connection.recv(1024), priv_key)
    file_path = data.decode('utf-8')
    folders = file_path.split('/')

    # Get the file size of the file being uploaded
    file_size = int(rsa.decrypt(connection.recv(1024), priv_key).decode())

    # Hold the user's total storage in bytes
    user_total = 0

    # Grab each file size and combine them
    for dirpath, dirnames, filenames in os.walk('Files/{}'.format(username)):
        for file in filenames:
            relative_path = os.path.join(dirpath, file)
            user_total += os.path.getsize(relative_path)

    # Compare storage to max size
    if user_total + file_size > 10737418240:
        connection.sendall(rsa.encrypt(b'SIZE EXCEEDED', client_pub_key))
        return

    # Set up the user's folder
    if os.path.isdir('{}/{}'.format(os.getcwd(), 'Files')) is False:
        os.mkdir('Files')
    if os.path.isdir('{}/{}/{}'.format(os.getcwd(), 'Files', username)) is False:
        os.mkdir('{}/{}'.format('Files', username))

    # Remember main folder before switching to client's folder
    program_folder = os.getcwd()
    os.chdir('{}/{}'.format('Files', username))
    home_folder = os.getcwd()

    # Verify the file path does not go outside of scope
    for cnt, folder in enumerate(folders):

        # The last entry is the filename
        if cnt == len(folders) - 1:
            os.chdir(program_folder)

        # If the directory goes back one folder
        elif folder == '..':
            os.chdir('../')

        # Process the current folder
        else:

            # Check if the path is within the Files directory
            if '{}'.format(os.getcwd())[:len(home_folder)] == home_folder:

                # If the folder already exists
                if os.path.isdir(folder):
                    os.chdir(folder)

                # If the folder does not yet exist
                else:
                    os.mkdir(folder)
                    os.chdir(folder)

            # If the path is outside of the scope
            else:
                connection.sendall(rsa.encrypt(b'TRAVERSAL', client_pub_key))
                logger.info('{}: File outside of scope {}'.format(threading.current_thread().name, folders))
                os.chdir(program_folder)
                return

    # Adjust the file path to the correct folder and log the action
    file_path = '{}/{}/{}'.format('Files', username, file_path)
    logger.info('{}: Creating file {}'.format(threading.current_thread().name, file_path))

    # If the file does not exist, allow upload with permissions
    exists, file_security_level = file_exist_check(database, file_path, security=True)

    # Ask for file permissions
    connection.sendall(rsa.encrypt(b'PERMISSION CHECK', client_pub_key))
    security_level = rsa.decrypt(connection.recv(1024), priv_key).decode()

    # If the file doesn't already exist in the database
    if exists is False:

        # Check if the user has the need permission to upload
        if inherits(database, username, security_level):

            # Notify the user to send the file
            connection.sendall(rsa.encrypt(b'CONTINUE', client_pub_key))

            # Download the file from the client
            try:
                shared.download_file(connection, priv_key, file_path, output=False)

            # If the file doesn't exist then stop
            except ValueError:
                return

            # Add file to database
            if create_file(database, path=file_path, owner=username, security_level=security_level):
                connection.sendall(rsa.encrypt(b'SUCCESS', client_pub_key))
                logger.info('{}: Successfully created file'.format(threading.current_thread().name))

            # Error adding file
            else:
                connection.sendall(rsa.encrypt(b'FAILURE', client_pub_key))
                logger.info('{}: Failed creating file'.format(threading.current_thread().name))

        # User does not have correct permissions
        else:
            connection.sendall(rsa.encrypt(b'FAILURE', client_pub_key))

    # Ask if the file should be overwritten
    else:

        # If the user has the desired permission
        if inherits(database, username, security_level):

            # Ask the user to overwrite file
            connection.sendall(rsa.encrypt(b'OVERWRITE', client_pub_key))
            overwrite = rsa.decrypt(connection.recv(1024), priv_key)

            # Overwrite file
            if overwrite == b'YES':

                # Download file from client
                shared.download_file(connection, priv_key, file_path, output=False)

                # Remove old entry from database
                if delete_file(database, path=file_path, output=False):

                    # Add new entry into database
                    if create_file(database, path=file_path, owner=username, security_level=security_level):

                        # Tell client was successful
                        connection.sendall(rsa.encrypt(b'SUCCESS', client_pub_key))
                        logger.info('{}: Successfully created file'.format(threading.current_thread().name))
                        return

                # If either failed than send failure message
                connection.sendall(rsa.encrypt(b'FAILURE', client_pub_key))
                logger.info('{}: Failed creating file'.format(threading.current_thread().name))
                return

            # Cancel
            else:
                return

        # If the user does not have the desired permission
        else:
            connection.sendall(rsa.encrypt(b'FAILURE', client_pub_key))
            logger.info('{}: Failed creating file'.format(threading.current_thread().name))
            return


def download(connection, client_pub_key, priv_key, username, database, max_message_size):
    """
    Client wants to download a file from the server
    :param connection: Connection to client
    :param client_pub_key: Client's public key
    :param priv_key: Server's private key
    :param username: Check for permissions based on username
    :param database: Connection to the database
    :param max_message_size: Maximum number of bytes that can be encrypted
    """

    # Receive file name from user
    data = connection.recv(1024)
    file_path = 'Files/{}/{}'.format(username, rsa.decrypt(data, priv_key).decode())

    # Verify the user has permission to download the file
    if download_verification(username, database, file_path) is False:
        connection.sendall(rsa.encrypt(b'MISSING', client_pub_key))
        return

    # Get file name from user
    try:
        shared.send_file(connection, client_pub_key, file_path, max_message_size, output=False)

    # Catch file not found
    except FileNotFoundError:
        connection.sendall(rsa.encrypt(b'MISSING', client_pub_key))


def download_verification(username, database, file_path):
    """
    Check if the file exists and the user has permission
    :param username: Username of the client
    :param database: Connection to the database
    :param file_path: Path of the file to retrieve
    :return: True = success, False = failure
    """

    # Query the database to see if the file exists
    file_exists, file_security_level = file_exist_check(database, file_path, security=True)
    if file_exists is False:
        return False

    # Return if the user has the desired permission
    if inherits(database, username, file_security_level):
        return True

    # Check if the user owns the file
    else:

        # Create statement and execute it
        cursor = database.cursor()
        statement = 'SELECT owner ' \
                    'FROM file_permissions ' \
                    'WHERE path=%s'
        cursor.execute(statement, file_path)
        owner = cursor.fetchall()

        # If the owner owns the file
        if owner[0][0] == username:
            return True

        # If the owner does not own the file
        else:
            return False


def file_exist_check(database, file_path, security=False):
    """
    Check if the file exists
    :param database: Connection to the database
    :param file_path: Path of the file
    :param security: If a security level is needed
    :return: True = success, False = failure
    """

    # Create cursor to interact with the database
    cursor = database.cursor()

    # Query the database to see if the file exists without security level
    if security is False:
        statement = 'SELECT path FROM file_permissions ' \
                    'WHERE path = %s'

    # Query the database to see if the file exists with security level
    else:
        statement = 'SELECT path, level FROM file_permissions ' \
                    'WHERE path = %s'
    cursor.execute(statement, file_path)
    exists = cursor.fetchall()

    # Quit if the file does not exist
    if len(exists) != 1 and security is False:
        return False

    # If the file does not exist, and asking for security level
    elif len(exists) != 1 and security is True:
        return False, None

    # Return verification of the existing file
    if security is False:
        return True

    # Return verification and security level
    else:
        return True, exists[0][1]


def inherits(database, username, desired_security_level):
    """
    Check if the user inherits a certain security level
    :param database: Database connection
    :param username: Username of the client
    :param desired_security_level: Security level needed
    :return: True = success, False = failure
    """

    # Create list of inherited permissions
    inherited = []

    # Creat cursor to interact with database
    cursor = database.cursor()

    # Query database to get user's security level
    statement = 'SELECT level FROM users ' \
                'WHERE user = %s'
    cursor.execute(statement, username)
    user_security_level = cursor.fetchall()[0][0]

    # Return true if the user has the desired permission
    if user_security_level == desired_security_level:
        return True

    # Keep checking inherited permissions
    while True:

        # Query the database to check for inherited permissions
        statement = 'SELECT includes FROM user_levels ' \
                    'WHERE level = %s'
        cursor.execute(statement, user_security_level)
        user_security_level = cursor.fetchall()[0][0]

        # Break if the inherited permission does not give access
        if user_security_level == '':
            return False

        # Check if the permission is in a loop
        elif user_security_level in inherited:
            return False

        # If the inherited permission grants the correct access, allow the download
        elif user_security_level == desired_security_level:
            return True

        else:
            inherited.append(user_security_level)
