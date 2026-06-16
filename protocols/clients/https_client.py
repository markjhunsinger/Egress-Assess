"""

This is the web client code

"""

import hashlib
import ssl
import sys
import urllib.request
import urllib.error


class Client:

    def __init__(self, cli_object):
        self.data_to_transmit = ''
        self.remote_server = cli_object.ip
        self.protocol = 'https'
        if cli_object.client_port is None:
            self.port = 443
        else:
            self.port = cli_object.client_port

        if cli_object.file is None:
            self.file_transfer = False
        else:
            if "/" in cli_object.file:
                self.file_transfer = cli_object.file.split("/")[-1]
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if not self.file_transfer:
            url = 'https://' + self.remote_server + ':' + str(self.port) + '/post_data.php'

            try:
                resp = urllib.request.urlopen(url, data_to_transmit, context=ctx)
                server_hash = resp.read().decode().strip()
                resp.close()
                local_hash = hashlib.sha256(data_to_transmit).hexdigest()
                if server_hash and server_hash != local_hash:
                    raise RuntimeError('Integrity check failed: data was modified in transit (DLP/proxy?)')
                print('[*] File sent')
            except urllib.error.URLError as e:
                raise RuntimeError(f'Web server unreachable on {self.remote_server}:{self.port} - {e}')
        else:
            url = 'https://' + self.remote_server + ':' + str(self.port) + '/post_file.php'

            try:
                data_to_transmit = bytes(self.file_transfer, encoding='utf-8') + b".:::-989-:::." + data_to_transmit
                file = urllib.request.urlopen(url, data_to_transmit, context=ctx)
                file.close()
                print('[*] File sent')
            except urllib.error.URLError as e:
                raise RuntimeError(f'Web server unreachable on {self.remote_server}:{self.port} - {e}')
