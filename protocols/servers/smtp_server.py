import os
import socket
import sys
import time
from aiosmtpd.controller import Controller
from common import helpers
from protocols.servers.serverlibs.smtp import smtp_class


class Server:

    def __init__(self, cli_object):

        self.protocol = 'smtp'
        if cli_object.server_port:
            self.port = int(cli_object.server_port)
        else:
            self.port = 25

    def serve(self):

        exfil_directory = os.path.join(helpers.ea_path(), 'transfer/')

        if not os.path.isdir(exfil_directory):
            os.makedirs(exfil_directory)

        handler = smtp_class.CustomSMTPHandler(exfil_directory.rstrip('/'))
        controller = Controller(handler, hostname='0.0.0.0', port=self.port)

        try:
            controller.start()
        except socket.error:
            print(f'[*] Error: Port {self.port} is currently in use.')
            print('[*] Error: Please re-start when not in use.')
            sys.exit()

        print(f'[*] Started an SMTP server on port {self.port}.')

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print('[*] Shutting down the SMTP server.')
            controller.stop()
            sys.exit()
