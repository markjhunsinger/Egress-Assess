import hashlib
import os
import time
from http.server import BaseHTTPRequestHandler
from common import helpers


class GetHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress per-request stdout noise

    def do_GET(self):
        self.send_response(404)
        self.end_headers()
        return

    def do_POST(self):
        exfil_directory = os.path.join(helpers.ea_path(), 'transfer')
        loot_path = exfil_directory + '/'

        if self.path == "/post_data.php":
            if not os.path.isdir(loot_path):
                os.makedirs(loot_path)

            screen_length = self.headers['content-length']
            screen_data = self.rfile.read(int(screen_length))
            data_hash = hashlib.sha256(screen_data).hexdigest()

            current_date = time.strftime("%m/%d/%Y")
            current_time = time.strftime("%H:%M:%S")
            screenshot_name = current_date.replace("/", "") + "_" + current_time.replace(":", "") + "web_data.txt"

            with open(loot_path + screenshot_name, 'a') as cc_data_file:
                cc_data_file.write('METADATA: From: ' + str(self.client_address) + ' ' + str(self.address_string) + '\n\n')
                cc_data_file.write(str(screen_data))

            self.send_response(200)
            self.end_headers()
            self.wfile.write(data_hash.encode())

        elif self.path == "/post_file.php":
            self.send_response(200)
            self.end_headers()

            if not os.path.isdir(loot_path):
                os.makedirs(loot_path)

            screen_length = self.headers['content-length']
            screen_data = self.rfile.read(int(screen_length))

            file_name = screen_data.split(b".:::-989-:::.")[0].decode('utf-8')
            file_data = screen_data.split(b".:::-989-:::.")[1].decode('utf-8')

            with open(loot_path + file_name, 'wb') as cc_data_file:
                helpers.received_file(file_name)
                cc_data_file.write(bytes(file_data, encoding='utf-8'))

        elif self.path == "/posh_file.php":
            self.send_response(200)
            self.end_headers()

            if not os.path.isdir(loot_path):
                os.makedirs(loot_path)

            length = self.headers['content-length']
            filename = self.headers['Filename']
            data = self.rfile.read(int(length))

            with open(loot_path + filename, 'wb') as cc_data_file:
                cc_data_file.write(data)

        else:
            self.send_response(404)
            self.end_headers()
