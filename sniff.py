'''
File: packet_sniffer.py
Author: Dimitris Karakostas
Description: Network sniffer for all ingoing/outgoing traffic with ethernet level information. Based on an inplementation by Silver Moon, http://www.binarytides.com/python-packet-sniffer-code-linux/
'''

import socket
import sys
import signal
import logging
from struct import *
from datetime import datetime
import constants
from iolibrary import kill_signal_handler, get_arguments_dict, setup_logger


signal.signal(signal.SIGINT, kill_signal_handler)


class Sniffer(object):
    '''
    Network Packet Sniffer
    '''
    def __init__(self, args_dict={}):
        self.args_dict = args_dict
        if 'sniff_logger' not in args_dict:
            if args_dict['verbose'] < 3:
                setup_logger('sniff_logger', 'sniff.log', args_dict, logging.ERROR)
            else:
                setup_logger('sniff_logger', 'sniff.log', args_dict)
            self.sniff_logger = logging.getLogger('sniff_logger')
            self.args_dict['sniff_logger'] = self.sniff_logger
        else:
            self.sniff_logger = args_dict['sniff_logger']

    def setup(self):
        '''
        Setup network socket.
        '''
        try:
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error, msg:
            self.sniff_logger.error('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()
        self.sniff_logger.info('Network socket setup successfully.')

    def eth_addr(self, a):
        '''
        Unpack ethernet address to human readable mode.
        '''
        b = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
        return b

    def sniff(self):
        '''
        Sniff all traffic.
        '''
        self.setup()
        while True:
            buff = 65565
            packet = self.s.recvfrom(buff)
            packet = packet[0]

            eth_header = packet[:constants.ETHERNET_HEADER_LENGTH]
            eth = unpack(constants.ETHERNET_HEADER_UNPACK, eth_header)
            eth_protocol = socket.ntohs(eth[2])
            self.sniff_logger.debug('Destination MAC : ' + self.eth_addr(packet[0:6]) + ' Source MAC : ' + self.eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol) + ' Time: ' + str(datetime.now()))

            if eth_protocol == constants.IP_TAG:
                ip_header = packet[constants.ETHERNET_HEADER_LENGTH:20+constants.ETHERNET_HEADER_LENGTH]
                iph = unpack(constants.IP_HEADER_UNPACK, ip_header)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                self.sniff_logger.debug('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

                if protocol == constants.TCP_TAG:
                    t = iph_length + constants.ETHERNET_HEADER_LENGTH
                    tcp_header = packet[t:t+20]
                    tcph = unpack(constants.TCP_HEADER_UNPACK, tcp_header)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4
                    h_size = constants.ETHERNET_HEADER_LENGTH + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size
                    data = packet[h_size:]

                    self.sniff_logger.debug('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length) + ' Data Size: ' + str(data_size) + '\nData : ' + data)

                    with open('out.out', 'a') as f:
                        if str(s_addr) == constants.GMAIL_IP:
                            f.write('Endpoint application payload: ' + str(data_size) + '\n')
                        elif str(d_addr) == constants.GMAIL_IP:
                            f.write('User application payload: ' + str(data_size) + '\n')

                elif protocol == constants.ICMP_TAG:
                    u = iph_length + constants.ETHERNET_HEADER_LENGTH
                    icmph_length = 4
                    icmp_header = packet[u:u+4]
                    icmph = unpack(constants.ICMP_HEADER_UNPACK, icmp_header)
                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]
                    h_size = constants.ETHERNET_HEADER_LENGTH + iph_length + icmph_length
                    data_size = len(packet) - h_size
                    data = packet[h_size:]

                    self.sniff_logger.debug('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum) + '\nData : ' + data)

                elif protocol == constants.UDP_TAG:
                    u = iph_length + constants.ETHERNET_HEADER_LENGTH
                    udph_length = 8
                    udp_header = packet[u:u+8]
                    udph = unpack(constants.UDP_HEADER_UNPACK, udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]
                    h_size = constants.ETHERNET_HEADER_LENGTH + iph_length + udph_length
                    data_size = len(packet) - h_size
                    data = packet[h_size:]

                    self.sniff_logger.debug('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum) + '\nData : ' + data)

                else:
                    self.sniff_logger.debug('Unknown Protocol')


if __name__ == '__main__':
    args_dict = get_arguments_dict(sys.argv)
    sn = Sniffer(args_dict)
    sn.sniff()
