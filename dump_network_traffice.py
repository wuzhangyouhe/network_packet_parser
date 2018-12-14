#!/usr/bin/env python

'''
the code is using for network traffic layers parsing.
    for example , parsing ethernet header, ip header

author : LIU Tao
'''

import socket
import struct
import textwrap

def main():
    # working in ubuntu only
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr= conn.recvfrom(655356) # why using 36
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol:{}'.format(dest_mac, src_mac, eth_proto))

# Sniffing ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]

#Return properly formatted MAC address (say AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_addr):
    bytes_str = map('{:02x}'.format, mac_addr)
    return ':'.join(bytes_str).upper()

main()