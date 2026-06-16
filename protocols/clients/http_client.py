"""

This is the web client code

"""

import hashlib
import sys
import urllib.request
import urllib.error


class Client:

    def __init__(self, cli_object):
        self.data_to_transmit = None
        self.remote_server = cli_object.ip
        self.protocol = 'http'
        if cli_object.client_port is None:
            self.port = 80
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

        if not self.file_transfer:
            url = "http://" + self.remote_server + ":" + str(self.port) + "/post_data.php"

            # Post the data to the web server at the specified URL
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36'}
                req = urllib.request.Request(url, data_to_transmit, headers)
                resp = urllib.request.urlopen(req, timeout=10)
                server_hash = resp.read().decode().strip()
                resp.close()
                local_hash = hashlib.sha256(data_to_transmit).hexdigest()
                if server_hash and server_hash != local_hash:
                    raise RuntimeError('Integrity check failed: data was modified in transit (DLP/proxy?)')
                print('[*] File sent')
            except urllib.error.URLError as e:
                raise RuntimeError(f'Web server unreachable on {self.remote_server}:{self.port} - {e}')
        else:
            url = "http://" + self.remote_server + ":" + str(self.port) + "/post_file.php"
            try:
                data_to_transmit = bytes(self.file_transfer, encoding='utf-8') + b".:::-989-:::." + data_to_transmit
                file = urllib.request.urlopen(url, data_to_transmit, timeout=10)
                file.close()
                print('[*] File sent')
            except urllib.error.URLError as e:
                raise RuntimeError(f'Web server unreachable on {self.remote_server}:{self.port} - {e}')
