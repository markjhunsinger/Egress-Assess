import paramiko
import socket
import os
from common import helpers


class Client:

    def __init__(self, cli_object):
        self.protocol = "sftp"
        self.username = cli_object.username
        self.password = cli_object.password
        self.remote_system = cli_object.ip
        if cli_object.client_port is None:
            self.port = 22
        else:
            self.port = cli_object.client_port

        if cli_object.file is None:
            self.file_transfer = False
        else:
            if '/' in cli_object.file:
                self.file_transfer = cli_object.file.split('/')[-1]
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        print('[*] Transmitting data...')

        sock = socket.create_connection((self.remote_system, self.port), timeout=10)
        transport = paramiko.Transport(sock)
        transport.connect()
        transport.auth_password(self.username, self.password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        if not self.file_transfer:
            sftp_file_name = helpers.writeout_text_data(data_to_transmit)
            full_path = helpers.ea_path() + '/' + sftp_file_name
            local_size = os.path.getsize(full_path)
            sftp.put(full_path, '/' + sftp_file_name)
            remote_size = sftp.stat('/' + sftp_file_name).st_size
            sftp.close()
            transport.close()
            os.remove(full_path)
            if remote_size != local_size:
                raise RuntimeError(f'Integrity check failed: sent {local_size}B, server has {remote_size}B')
        else:
            remote_name = self.file_transfer.split('/')[-1] if '/' in self.file_transfer else self.file_transfer
            local_size = os.path.getsize(self.file_transfer)
            sftp.put(self.file_transfer, '/' + remote_name)
            remote_size = sftp.stat('/' + remote_name).st_size
            sftp.close()
            transport.close()
            if remote_size != local_size:
                raise RuntimeError(f'Integrity check failed: sent {local_size}B, server has {remote_size}B')

        print('[*] Data sent')
