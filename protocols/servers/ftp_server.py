import os
import socket
import sys
import urllib.request
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def _detect_public_ip():
    # EC2 instance metadata (fast, no internet hop)
    for url in ('http://169.254.169.254/latest/meta-data/public-ipv4',
                'https://api.ipify.org',
                'https://checkip.amazonaws.com'):
        try:
            return urllib.request.urlopen(url, timeout=2).read().decode().strip()
        except Exception:
            continue
    return None


class Server:

    def __init__(self, cli_object):
        self.protocol = 'ftp'
        self.username = cli_object.username
        self.password = cli_object.password
        self.data_directory = ""
        if cli_object.server_port:
            self.port = int(cli_object.server_port)
        else:
            self.port = 21

        if cli_object.ip:
            self.ip = cli_object.ip
        else:
            self.ip = None

    def serve(self):
        # Current directory
        exfil_directory = os.path.join(os.getcwd(), 'transfer')
        loot_path = exfil_directory + "/"

        # Check to make sure the agent directory exists, and a loot
        # directory for the agent. If not, make them
        if not os.path.isdir(loot_path):
            os.makedirs(loot_path)

        try:
            authorizer = DummyAuthorizer()
            authorizer.add_user(self.username, self.password, homedir=loot_path, perm="elradfmwM")

            handler = FTPHandler
            handler.authorizer = authorizer

            # Define a customized banner (string returned when client connects)
            handler.banner = "Connecting to Egress-Assess's FTP server!"
            # Define public address and passive ports making NAT configurations more predictable
            masq = self.ip or _detect_public_ip()
            if masq:
                print(f'[*] FTP masquerade address: {masq}')
            handler.masquerade_address = masq
            handler.passive_ports = list(range(60000, 60100))

            try:
                server = FTPServer(('', self.port), handler)
                server.serve_forever()
            except socket.error:
                print(f'[*] Error: Port {self.port} is currently in use.')
                sys.exit()
        except ValueError:
            print('[*] Error: The directory you provided does not exist.')
            print('[*] Error: Re-start with a valid directory.')
            sys.exit()
