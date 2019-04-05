import socket, sys, select
import binascii
from struct import *
from utils import *

'''
ARP Header
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Hardware Type          |        Protocol Type          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Mac Addr len | Proto Addr len|       Operation Code          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sender Mac Address(0~3)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Sender Mac Address(4~5)      |         Sender IP (0~1)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Sender IP (2~3)     |  Target Mac Address(0~1)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Mac Address(2~5)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Targer IP                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''

REMOTE = 'david.choffnes.com'


class EthernetPacket:
    def __init__(self):
        self.dst_mac = ''
        self.src_mac = ''
        self.protocol = socket.htons(8)    #ip protocol
        self.data = ''

    def encode(self):
        dst_mac = binascii.unhexlify(self.dst_mac)
        src_mac = binascii.unhexlify(self.src_mac)

        ethernet_packet = pack('!6s6sH', dst_mac, src_mac, self.protocol) + self.data
        return ethernet_packet

    def decode(self, packet):
        [self.dst_mac, self.src_mac, self.protocol] = unpack('!6s6sH', packet[:14])
        self.data = packet[14:]
        self.dst_mac = binascii.hexlify(self.dst_mac)
        self.src_mac = binascii.hexlify(self.src_mac)

class ARPPacket:
    def __init__(self):
        self.htype = 0x0001 # ethernet
        self.ptype = 0x0800 # arp resolution
        self.hlen = 6 #hardware address length
        self.plen = 4 #ip address
        self.oper = 0
        self.src_mac = ''   # sender mac addr
        self.dst_mac = ''   # receiver mac addr
        self.src_ip = ''    
        self.dst_ip = ''

    def encode(self):
        # operation 1: request
        # operation 2: reply
        bi_src_mac = binascii.unhexlify(self.src_mac)
        bi_dst_mac = binascii.unhexlify(self.dst_mac)
        bi_src_ip = socket.inet_aton(self.src_ip)
        bi_dst_ip = socket.inet_aton(self.dst_ip)

        packet = pack("!HHBBH6s4s6s4s", self.htype, self.ptype, \
                    self.hlen, self.plen, self.oper, \
                    bi_src_mac, bi_src_ip, bi_dst_mac, bi_dst_ip)
        return packet

    def decode(self, rawpacket):
        [self.htype, self.ptype, self.hlen, self.plen, self.oper, \
         bi_src_mac, bi_src_ip, bi_dst_mac, bi_dst_ip] = \
            unpack("!HHBBH6s4s6s4s", rawpacket)

        self.src_mac = binascii.hexlify(bi_src_mac)
        self.dst_mac = binascii.hexlify(bi_dst_mac)

        self.src_ip = socket.inet_ntoa(bi_src_ip)
        self.dst_ip = socket.inet_ntoa(bi_dst_ip)

class Ethernet:
    def __init__(self):
        self.src_mac = ''
        self.dst_mac = ''
        self.gateway_mac = ''
        self.interface = get_interface(get_local_ip(REMOTE))
        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.send_sock.bind((self.interface, 0))
        self.recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        self.recv_sock.setblocking(0)

    def send(self, packetRaw):
        if self.gateway_mac == "":
            gatewayip = get_gateway_ip()
            try:
                self.gateway_mac = self.getGateway(gatewayip)
            except:
                print 'Failed to get arp REPLY'
                sys.exit(0)

        packet = EthernetPacket()
        packet.dst_mac = self.gateway_mac
        self.dst_mac = packet.dst_mac
        packet.src_mac = self.src_mac
        packet.data = packetRaw

        self.send_sock.send(packet.encode())

    def recv(self):
        packet = EthernetPacket()
        while True:
            ready = select.select([self.recv_sock], [], [], 60)
            if ready[0]:
                packetRaw = self.recv_sock.recv(4096)
            else:
                print 'recv socket timed out'
                sys.exit(0)
            packet.decode(packetRaw)
            if packet.dst_mac == self.src_mac:
                return packet.data

    def close(self):
        if self.send_sock != None:
            self.send_sock.close()
        if self.recv_sock != None:
            self.recv_sock.close()

    def getGateway(self, dst_ip):
        _send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        _recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
        _recv_sock.settimeout(2)

        src_ip = get_local_ip(REMOTE)
        interface = get_interface(src_ip)
        self.src_mac = get_local_mac(src_ip)
        #print self.src_mac

        arpPacket = ARPPacket()
        arpPacket.src_mac = self.src_mac
        arpPacket.src_ip = src_ip
        arpPacket.dst_mac = '000000000000'
        arpPacket.dst_ip = dst_ip
        arpPacket.oper = 1

        epacket = EthernetPacket()
        epacket.src_mac = self.src_mac
        epacket.dst_mac = 'FFFFFFFFFFFF'
        epacket.protocol = 0x0806
        epacket.data = arpPacket.encode()

        _send_sock.sendto(epacket.encode(), (interface, 0))

        arp_res = ARPPacket()
        while True:
            packetRaw = _recv_sock.recvfrom(4096)[0]
            epacket.decode(packetRaw)
            #print epacket.dst_mac
            if epacket.dst_mac == self.src_mac:
                arp_res.decode(epacket.data[:28])
                #print arp_res.src_ip
                #print arp_res.dst_ip
                if arp_res.src_ip == dst_ip and arp_res.dst_ip == src_ip:
                    break

        _send_sock.close()
        _recv_sock.close()
        #print arp_res.src_mac
        return arp_res.src_mac


if __name__ == "__main__":
    s = Ethernet()
    ip = get_gateway_ip()
    print ip
    print s.getGateway(ip)

