"""

SMB client using impacket SMBConnection — replaces smbclient shell invocation
so we can verify file size after upload.

"""

import os
from impacket.smbconnection import SMBConnection
from common import helpers


class Client:

    def __init__(self, cli_object):
        self.protocol = 'smb'
        self.remote_server = cli_object.ip
        if cli_object.client_port is None:
            self.port = 445
        else:
            self.port = cli_object.client_port
        if cli_object.file is None:
            self.file_transfer = False
        else:
            if '/' in cli_object.file:
                self.file_transfer = cli_object.file
                self.file_name = cli_object.file.split('/')[-1]
            else:
                self.file_transfer = cli_object.file
                self.file_name = cli_object.file

    def transmit(self, data_to_transmit):
        print('[*] Sending data over SMB...')

        if not self.file_transfer:
            smb_file_name = helpers.writeout_text_data(data_to_transmit)
            local_path = helpers.ea_path() + '/' + smb_file_name
            remote_name = smb_file_name
            cleanup = True
        else:
            local_path = self.file_transfer
            remote_name = self.file_name
            cleanup = False

        local_size = os.path.getsize(local_path)

        try:
            conn = SMBConnection(self.remote_server, self.remote_server, sess_port=self.port, timeout=10)
            conn.login('', '')

            with open(local_path, 'rb') as fh:
                conn.putFile('TRANSFER', remote_name, fh.read)

            matches = conn.listPath('TRANSFER', remote_name)
            if not matches:
                raise RuntimeError('Integrity check failed: file not found on server after upload')
            remote_size = matches[0].get_filesize()
            if remote_size != local_size:
                raise RuntimeError(f'Integrity check failed: sent {local_size}B, server has {remote_size}B')

            conn.logoff()
        finally:
            if cleanup and os.path.exists(local_path):
                os.remove(local_path)

        print('[*] File transmitted!')
