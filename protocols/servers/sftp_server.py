"""

Base code from https://searchcode.com/codesearch/raw/53300304/

"""

import os
import paramiko
import socket
import sys
import threading
import time
from common import helpers
from protocols.servers.serverlibs.sftp import sftp_classes


class Server:

    def __init__(self, cli_object):
        self.protocol = "sftp"
        self.username = cli_object.username
        self.password = cli_object.password
        self.sftp_directory = helpers.ea_path() + '/transfer'
        if cli_object.server_port:
            self.port = int(cli_object.server_port)
        else:
            self.port = 22
        self.host_key = paramiko.RSAKey.generate(2048)

    @staticmethod
    def accept_client(client, addr, root_dir, users, host_key):
        usermap = {}
        for user in users:
            usermap[user.username] = user

        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)

        impl = sftp_classes.SimpleSftpServer
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_si=impl, transport=transport,
                                        fs_root=root_dir, users=usermap)

        server = sftp_classes.SimpleSSHServer(users=usermap)
        transport.start_server(server=server)
        channel = transport.accept()
        while transport.is_active():
            time.sleep(3)

    def serve(self):
        loot_path = os.path.join(helpers.ea_path(), 'transfer') + "/"
        if not os.path.isdir(loot_path):
            os.makedirs(loot_path)

        user_map = [sftp_classes.User(username=self.username, password=self.password, chroot=False)]

        print(f'[*] Starting an SFTP server on port {self.port}.')

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.listen(10)
        except socket.error:
            print(f'[*] Error: Port {self.port} is currently in use.')
            sys.exit()

        while True:
            try:
                client, addr = server_socket.accept()
                t = threading.Thread(target=self.accept_client, args=[
                    client, addr, self.sftp_directory, user_map, self.host_key])
                t.daemon = True
                t.start()
            except KeyboardInterrupt:
                print('[*] Shutting down the SFTP server.')
                sys.exit()
