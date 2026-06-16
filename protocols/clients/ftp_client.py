"""

This is the ftp client code

"""

import os
import socket
import sys
from common import helpers
from ftplib import FTP
from ftplib import error_perm


class Client:

    def __init__(self, cli_object):
        self.protocol = 'ftp'
        self.remote_server = cli_object.ip
        self.username = cli_object.username
        self.password = cli_object.password

        if cli_object.client_port is None:
            self.port = 21
        else:
            self.port = cli_object.client_port

        if cli_object.file is None:
            self.file_transfer = False
        else:
            if '/' in cli_object.file:
                self.file_transfer = cli_object.file
            else:
                self.file_transfer = cli_object.file.split('/')[-1]

    def transmit(self, data_to_transmit):

        try:
            ftp = FTP()
            ftp.connect(self.remote_server, self.port)
        except socket.gaierror as e:
            raise RuntimeError(f'Cannot connect to FTP server {self.remote_server}:{self.port} - {e}')

        try:
            ftp.login(self.username, self.password)
        except error_perm as e:
            raise RuntimeError(f'FTP login failed - {e}')

        if not self.file_transfer:
            ftp_file_name = helpers.writeout_text_data(data_to_transmit)
            local_path = helpers.ea_path() + "/" + ftp_file_name
            local_size = os.path.getsize(local_path)
            ftp.storbinary(f"STOR {ftp_file_name}", open(local_path, 'rb'))
            remote_size = ftp.size(ftp_file_name)
            os.remove(local_path)
            if remote_size != local_size:
                ftp.quit()
                raise RuntimeError(f'Integrity check failed: sent {local_size}B, server has {remote_size}B')
        else:
            local_size = os.path.getsize(self.file_transfer)
            ftp.storbinary("STOR " + self.file_transfer, open(self.file_transfer, 'rb'))
            remote_size = ftp.size(os.path.basename(self.file_transfer))
            if remote_size != local_size:
                ftp.quit()
                raise RuntimeError(f'Integrity check failed: sent {local_size}B, server has {remote_size}B')

        ftp.quit()
        print('[*] File sent')
