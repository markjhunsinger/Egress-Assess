# -*- coding: utf-8 -*- 
"""

This is for functions potentially used by all modules

"""

import argparse
import os
import random
import re
import socket
import string
import sys
import time


def cli_parser():
    # Command line argument parser
    parser = argparse.ArgumentParser(add_help=False, description='Egress-Assess is used to test egress filters protecting a network.')
    parser.add_argument('-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)

    protocols = parser.add_argument_group('Client Protocol Options')
    protocols.add_argument('--client', default=None, metavar='[http]', nargs='?',
                           const='all', help='Extract data over the specified protocol. Omit value with --sweep to use all.')
    protocols.add_argument('--client-port', default=None, metavar='34567', type=int, help='Non-standard port to connect over.')
    protocols.add_argument('--list-clients', default=False, action='store_true', help='List all supported client protocols.')
    protocols.add_argument('--ip', metavar='192.168.1.2', default=None, help='IP to extract data to.')

    actors = parser.add_argument_group('Actor Emulation')
    actors.add_argument('--actor', default=None, metavar='[zeus]', help='Emulate the specified actor when doing C2 comms to server.')
    actors.add_argument('--list-actors', default=False, action='store_true', help='List all supported malware, APT group modules')

    servers = parser.add_argument_group('Server Protocol Options')
    servers.add_argument('--server', default=None, metavar='[http]', nargs='?',
                         const='all', help='Create a server for the specified protocol. Omit value with --sweep to use all.')
    servers.add_argument('--server-port', default=None, metavar='[80]', help='Specify a non-standard port for the specified protocol.')
    servers.add_argument('--list-servers', default=False, action='store_true', help='Lists all supported server protocols.')

    ftp_options = parser.add_argument_group('FTP Options')
    ftp_options.add_argument('--username', metavar='testuser', default=None, help='Username for FTP server authentication.')
    ftp_options.add_argument('--password', metavar='pass123', default=None, help='Password for FTP server authentication.')

    smb_options = parser.add_argument_group('SMB Options')
    smb_options.add_argument('--no-smb2', default=True, action='store_false', help='Disable SMB v2 support.')

    data_content = parser.add_argument_group('Data Content Options')
    data_content.add_argument('--file', default=None, metavar='/tmp/test.txt', help='Path to file to extract.')
    data_content.add_argument('--datatype', default=None, metavar='[ssn]', help='Generate fake data for the specified type.')
    data_content.add_argument('--data-size', default=1, type=int, help='Number of megs to send, default is 1MB')
    data_content.add_argument('--list-datatypes', default=False, action='store_true', help='List all supported data types that can be generated.')

    sweep_options = parser.add_argument_group('Sweep Mode')
    sweep_options.add_argument('--sweep', default=False, action='store_true',
                               help='Run in sweep mode: all protocols and datatypes.')
    sweep_options.add_argument('--sftp-port', default=None, metavar='2222', type=int,
                               help='Override SFTP port in sweep mode (default 22, often conflicts with SSH).')
    sweep_options.add_argument('--smb-port', default=None, metavar='8445', type=int,
                               help='Override SMB port in sweep mode (default 445, blocked by AWS).')
    sweep_options.add_argument('--smtp-port', default=None, metavar='587', type=int,
                               help='Override SMTP port in sweep mode (default 25; use 587 for submission).')

    args = parser.parse_args()

    if args.h:
        parser.print_help()
        sys.exit()

    if ((args.server == "ftp" or args.server == "sftp") or (
            args.client == "ftp" or args.client == "sftp")) and (
            args.username is None or args.password is None):
        print('[*] Error: FTP or SFTP connections require \
            a username and password!'.replace('    ', ''))
        print('[*] Error: Please re-run and provide the required info!')
        sys.exit(1)

    if args.sweep:
        if args.server is not None and args.client is not None:
            print('[*] Error: --sweep accepts --server or --client, not both.')
            sys.exit(1)
        if args.server is None and args.client is None:
            print('[*] Error: --sweep requires --server or --client.')
            sys.exit(1)
        if args.server_port is not None:
            print('[*] Error: --server-port cannot be used with --sweep (all default ports are used).')
            sys.exit(1)
        if args.server is not None and (args.username is None or args.password is None):
            print('[*] Error: Sweep server mode requires --username and --password.')
            sys.exit(1)
        if args.client is not None and (args.ip is None or args.username is None or args.password is None):
            print('[*] Error: Sweep client mode requires --ip, --username, and --password.')
            sys.exit(1)
        return args

    if args.client and args.ip is None:
        print('[*] Error: You said to act like a client, but provided no ip')
        print('[*] Error: to connect to.  Please re-run with required info!')
        sys.exit(1)

    if (args.client is not None) and (args.datatype is None) and (
            args.file is None):
        print('[*] Error: You need to tell Egress-Assess the type \
            of data to send!'.replace('    ', ''))
        print('[*] Error: to connect to.  Please re-run with required info!')
        sys.exit(1)

    if (args.client is None and args.server is None and
            args.list_servers is None and args.list_clients is None and
            args.list_datatypes is None):
        print("[*] Error: You didn't tell Egress-Assess to act like \
            a server or client!".replace('    ', ''))
        print('[*] Error: Please re-run and provide an action to perform!')
        parser.print_help()
        sys.exit(1)

    if args.actor is not None and args.ip is None:
        print('[*] Error: You did not provide an IP to egress data to!')
        print('[*] Error: Please re-run and provide an ip!')
        sys.exit(1)

    return args


def random_numbers(b):
    """
    Returns a random string/key of "b" characters in length, defaults to 5
    """
    random_number = int(''.join(random.choice(string.digits) for _ in range(b))) + 10000

    if random_number < 100000:
        random_number = random_number + 100000

    return str(random_number)


def random_string(length=-1):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    """
    if length == -1:
        length = random.randrange(6, 16)
    random_str = ''.join(random.choice(string.ascii_letters) for _ in range(length))
    return random_str


def received_file(filename):
    print(f'[+] {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())} - Received File - {filename}')


def title_screen():
    print("#" * 80)
    print("#" + " " * 32 + "Egress-Assess" + " " * 33 + "#")
    print("#" * 80 + "\n")


def ea_path():
    return os.getcwd()


def validate_ip(val_ip):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    ip_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
    if ip_re.match(val_ip):
        quads = (int(q) for q in val_ip.split('.'))
        for q in quads:
            if q > 255:
                return False
        return True
    return False


def writeout_text_data(incoming_data):
    # Get the date info
    current_date = time.strftime("%d/%m/%Y")
    current_time = time.strftime("%H:%M:%S")
    file_name = current_date.replace("/", "") + "_" + current_time.replace(":", "") + "text_data.txt"

    # Write out the file
    with open(ea_path() + "/" + file_name, 'w') as out_file:
        out_file.write(incoming_data)

    return file_name


def check_port_available(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def preflight_server_sweep(server_list):
    errors = []
    cert_path = os.path.join(ea_path(), 'server.pem')

    needs_cert = any(s.protocol == 'https' for s in server_list)
    if needs_cert and not os.path.isfile(cert_path):
        errors.append(f'server.pem not found at {cert_path} (required for https)')

    for server in server_list:
        if not hasattr(server, 'port'):
            continue  # ICMP — no port
        if not check_port_available(server.port):
            errors.append(f'Port {server.port} in use ({server.protocol})')

    return errors
