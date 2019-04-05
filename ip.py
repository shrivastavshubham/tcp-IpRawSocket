import socket
import sys
from random import randint
from struct import *
import select

from ethernet import *
from utils import ip_checksum, get_local_ip

EthernetFrame = True

'''
IP Header
0                   1                   2                   3   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''

class IPPacket:
    def __init__(self, src = '', dst = '', msg = ''): 
        # ip header fields
        self.ip_ihl = 5
        self.ip_ver = 4
        self.ip_ver_ihl = (self.ip_ver << 4) + self.ip_ihl
        self.ip_tos = 0
        self.ip_tot_len = 0  # ?kernel will fill the correct total length
        self.ip_id = 0   #Id of this packet
        #self.ip_flag_df = 1     # dont frag
        #self.ip_flag_mf = 0
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_check = 0    # ?kernel will fill the correct checksum
        self.ip_src = src
        self.ip_dst = dst
        self.msg = msg

    def reset(self):
        self.ip_ihl = 5
        self.ip_ver = 4
        self.ip_ver_ihl = (self.ip_ver << 4) + self.ip_ihl
        self.ip_tos = 0
        self.ip_tot_len = 0  # ?kernel will fill the correct total length
        self.ip_id = 0   #Id of this packet
        #self.ip_flag_df = 1     # dont frag
        #self.ip_flag_mf = 0
        self.ip_frag_off = 0
        self.ip_ttl = 255
        self.ip_proto = socket.IPPROTO_TCP
        self.ip_check = 0    # ?kernel will fill the correct checksum
        self.ip_src = 0
        self.ip_dst = 0
        self.msg = ''

    def encode(self):
        self.ip_id = randint(0, 65535)
        self.ip_tot_len = self.ip_ihl * 4 + len(self.msg)
        ip_src = socket.inet_aton(self.ip_src)
        ip_dst = socket.inet_aton(self.ip_dst)
        # assemble the ip header
        ip_header = pack('!BBHHHBBH4s4s' ,
                         self.ip_ver_ihl, 
                         self.ip_tos,
                         self.ip_tot_len, 
                         self.ip_id, 
                         self.ip_frag_off, 
                         self.ip_ttl, 
                         self.ip_proto, 
                         self.ip_check,
                         ip_src, 
                         ip_dst)

        self.ip_check = ip_checksum(ip_header)
        # reassemble with the correct checksum
        ip_header = pack('!BBHHHBBH4s4s' ,
                         self.ip_ver_ihl, 
                         self.ip_tos,
                         self.ip_tot_len, 
                         self.ip_id, 
                         self.ip_frag_off, 
                         self.ip_ttl, 
                         self.ip_proto, 
                         self.ip_check,
                         ip_src, 
                         ip_dst)

        ip_packet = ip_header + self.msg

        return ip_packet

    def decode(self, response):
        ip_header = response[0:20]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        ip_ver_ihl = iph[0]
        self.ver = ip_ver_ihl >> 4
        self.ihl = ip_ver_ihl & 0x0F
        self.ip_tos = iph[1]
        self.ip_tot_len = iph[2]
        self.ip_id = iph[3]
        self.ip_frag_off = iph[4]
        self.ip_ttl = iph[5]
        self.ip_proto = iph[6]
        self.ip_check = iph[7]
        self.ip_src = socket.inet_ntoa(iph[8])
        self.ip_dst = socket.inet_ntoa(iph[9])

        self.data = response[self.ihl*4 : self.ip_tot_len]
        ip_header = response[:self.ihl*4]

        if ip_checksum(ip_header) != 0:
            print 'Received packet IP checksum error'

    def print_all(self):
        print 'IP header listing:'
        print self.ip_ver_ihl 
        print self.ip_tos
        print self.ip_tot_len 
        print self.ip_id
        print self.ip_frag_off
        print self.ip_ttl
        print self.ip_proto
        print self.ip_check
        print self.ip_src
        print self.ip_dst
        print self.msg


class IPSocket:
    def __init__(self, src_ip = '', dst_ip = ''):
        self.src = src_ip
        self.dst = dst_ip

        if EthernetFrame == True:
            self.Ethernet = Ethernet()
        else:
            # create the sending and receiving sockets
            try:
                self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            except socket.error , msg:
                print 'Send ocket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
                sys.exit()
            try:
                self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            except socket.error , msg:
                print 'Receiver socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
                sys.exit()
            self.recv_sock.setblocking(0)

    def check_ip_packet(self, packet):
        if packet.ip_dst != self.src:
            print "ip dismatch"
            return false
        if packet.ip_src != self.dst:
            print "ip dismatch"
            return false    
        if packet.proto != socket.IPPROTO_TCP:
            return false
        return true

    def send(self, msg):
        packet = IPPacket(self.src, self.dst, msg)
        packet = packet.encode()

        if EthernetFrame == True:
            self.Ethernet.send(packet)
        else:
            self.send_sock.sendto(packet, (self.dst, 0))

    def recv(self, timeout):

        if EthernetFrame == True:
            # create an empty packet
            packet_recv = IPPacket()

            while True:
                packet_recv.reset()
                response = self.Ethernet.recv()

                # parse the response
                packet_recv.decode(response)

                if packet_recv.ip_proto == socket.IPPROTO_TCP and packet_recv.ip_dst == self.src and packet_recv.ip_src == self.dst:
                    return packet_recv.data

        else:
            # create an empty packet
            packet_recv = IPPacket()

            while True:
                packet_recv.reset()
                ready = select.select([self.recv_sock], [], [], timeout)
                if ready[0]:
                    response = self.recv_sock.recv(4096)
                else:
                    print "Receive Socket Timeout"
                    return false

                # parse the response
                packet_recv.decode(response)

                if packet_recv.ip_proto == socket.IPPROTO_TCP and packet_recv.ip_dst == self.src and packet_recv.ip_src == self.dst:
                    return packet_recv.data

    def close(self):
        if EthernetFrame == True:
            self.Ethernet.close()
        else:
            # close the sockets
            self.send_sock.close()
            self.recv_sock.close()
 
if __name__ == "__main__":
    pass
