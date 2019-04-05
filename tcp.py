import socket, sys, time
import collections
import re

from struct import *
from random import randint

from ip import IPSocket
from utils import *

HTTP_PORT = 80
DEFAULT_TIME_OUT = 60


'''
TCP Header
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''

class TCPPacket:
    def __init__(self, src_ip='', src_port=0, dst_ip='', dst_port=0, data=''):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = 0
        self.ack_seq = 0
        self.doff = 5
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.window = 4096
        self.check = 0
        self.urgent = 0
        self.data = data

    def reset(self):
        self.src_ip = ''
        self.dst_ip = ''
        self.src_port = 0
        self.dst_port = 0
        self.seq = 0
        self.ack_seq = 0
        self.doff = 5
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.window = 4096
        self.check = 0
        self.urgent = 0
        self.data = ''

    def encode(self):
        '''Encode the TCP header and append the TCP data
           Return the whole datagram
        '''
        offset_res = (self.doff << 4) + 0

        tcp_flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh <<3) + (self.ack << 4) + (self.urg << 5)
        # Assemble header used for checksum
        tcp_header = pack('!HHLLBBHHH',
                         self.src_port,
                         self.dst_port,
                         self.seq,
                         self.ack_seq,
                         offset_res,
                         tcp_flags,
                         self.window,
                         self.check,
                         self.urgent)

        # Assemble the pseudo header
        sourceAddress = socket.inet_aton(self.src_ip)
        destAddress = socket.inet_aton(self.dst_ip)
        placeHolder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(self.data)

        pseudoHeader = pack('!4s4sBBH' , sourceAddress , destAddress , placeHolder , protocol , tcp_length);
        pseudoHeader = pseudoHeader + tcp_header + self.data

        # Calculate the checksum
        self.check = tcp_checksum(pseudoHeader)

        # Re-assemble the TCP header
        tcp_header = pack('!HHLLBBH', self.src_port, self.dst_port, self.seq, self.ack_seq, offset_res, tcp_flags, self.window) + pack('H', self.check) + pack('!H', self.urgent)

        return tcp_header + self.data

    def decode(self, packet):
        ''' Decode the received packet to the packet class
            Check the checksum, if error return False
        '''
        header_temp = unpack('!HHLLBBH', packet[0:16])
        self.src_port = header_temp[0]
        self.dst_port = header_temp[1]
        self.seq = header_temp[2]
        self.ack_seq = header_temp[3]
        offset_res = header_temp[4]
        self.doff = offset_res >> 4
        tcp_flags = header_temp[5]

        # Flags
        self.fin = tcp_flags & 0x01
        self.syn = (tcp_flags & 0x02) >> 1
        self.rst = (tcp_flags & 0x04) >> 2
        self.psh = (tcp_flags & 0x08) >> 3
        self.ack = (tcp_flags & 0x10) >> 4
        self.urg = (tcp_flags & 0x20) >> 5

        self.window = header_temp[6]
        self.check = unpack('H', packet[16:18])
        self.urgent = unpack('!H', packet[18:20])

        self.data = packet[self.doff*4 : ]

        # Assemble the pseudo header
        sourceAddress = socket.inet_aton(self.src_ip)
        destAddress = socket.inet_aton(self.dst_ip)
        placeHolder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = self.doff * 4 + len(self.data)

        pseudoHeader = pack('!4s4sBBH' , sourceAddress , destAddress , placeHolder , protocol , tcp_length);
        pseudoHeader = pseudoHeader + packet

        if tcp_checksum(pseudoHeader) != 0:
            print 'Received packet TCP checksum error'
            return False

    def print_all(self):
        print 'From:' + self.src_ip + ' To:' + self.dst_ip
        print 'From port:',
        print self.src_port,
        print ' To port: ', 
        print self.dst_port

        print 'seq: ' ,
        print self.seq,
        print ' ack_seq: ',
        print self.ack_seq

        #print 'doff: ' + self.doff + ' ack: ' + self.ack + ' psh: ' + self.psh 
        #print 'rst: ' + self.rst + ' syn: ' + self.syn + ' fin: ' + self.fin
        #print self.window
        #print self.check
        #print self.urgent
        print self.data


class TCP():
    def __init__(self):
        self.src_ip = ''
        self.src_port = 0
        self.dst_ip = ''
        self.dst_port = 0
        self.seq = 0
        self.ack_seq = 0
        self.sock = IPSocket()
        self.cwnd = 1


    def connect(self, remotehost):
        '''Connect to the given remote host, perform three way hand shake
        '''
        # setup the socket
        self.dst_ip = socket.gethostbyname(remotehost)
        self.dst_port = HTTP_PORT
        self.src_ip = get_local_ip(remotehost)
        self.src_port = get_port()
        self.sock = IPSocket(self.src_ip, self.dst_ip)

        # three-way hand shake start here
        # First SYN send, seq = random, ack = 0
        self.seq = randint(0, 65535)
        packet = self.generate_tcp_packet('syn')
        # cache the packet
        packet_r = packet
        self.sock.send(packet.encode())
        print 'Connecting to ' + remotehost + ' ......',

        # receive the ACK + SYN response
        # packet.reset()
        packet = self.get_ip_payload()

        # If timeout, resend the original packet
        while packet == 'TIMEOUT' or packet == 'CHECKSUM_ERROR' :
            self.sock.send(packet_r)
            print 'Not Receiving ACK+SYN, resend SYN request'
            packet = self.get_ip_payload()

        # If the ACK+SYN matches, update the ack and seq
        # next outbound packet ack = inbound seq + 1
        # next outbound seq = inbound ack
        if packet.ack_seq == (self.seq + 1) and packet.syn == 1 and packet.ack == 1:
            self.ack_seq = packet.seq + 1
            self.seq = packet.ack_seq
            self.increase_cwnd()
            #print 'cwnd increased'
        else:
            print 'Wrong SYN+ACK from remotehost'
            self.sock.send(packet_r)

        # Send the ACK, finish handshake
        packet = self.generate_tcp_packet('ack')
        self.sock.send(packet.encode())

        print 'Connected'

    def send(self, data):
        ''' Send the request to remote host, check if the server acked in time
            return the retry times for one packet
        '''
        request = self.generate_tcp_packet('psh, ack')
        request.data = data
        #print 'Request:'
        #request.print_all()

        retry_times = 0

        # send the GET request to the server
        self.sock.send(request.encode())

        #receive the packet
        packet = self.receiveGetACK()

        # failed to receive the ack
        while not packet:
            retry_times += 1
            # send the GET request to the server
            self.sock.send(request.encode())
            print 'retry sending the ack'
            #receive the packet
            packet = self.receiveGetACK()

        # note the first ACK has no payload, thus len(data) should be zero
        if packet.ack_seq == self.seq + len(data):
            self.seq = packet.ack_seq
            self.ack_seq = packet.seq
        else:
            print 'server received missmatched send packets'
            sys.exit(0)
        return retry_times

    def sendGet(self, request):
        ''' Interface for send request
            Implement cwnd naively by multiple increase and decrese to 1 when timeout
            Because the server's MSS is much larger than the request's size
        '''
        length = len(request)
        pos = 0
        while (pos < length):
            if (pos + self.cwnd) < (length + 1):
                r = self.send(request[pos : pos + self.cwnd])
                pos += self.cwnd
                if r == 0:
                    self.increase_cwnd()
                else:
                    self.decrease_cwnd()
                #print self.cwnd
            else:
                self.send(request[pos:])
                pos += self.cwnd

    def receiveGetACK(self):
        ''' Try to receive the GET request's ACK within timeout
            If lower level has timeout or decode issue, return False
            Else return the packet
        '''
        packet = TCPPacket()

        timestamp = time.time()
        while(time.time() - timestamp) < DEFAULT_TIME_OUT:
            packet = self.get_ip_payload()
            if packet.ack != 1:
                return False
            else:
                return packet
        return False


    def get_ip_payload(self):
        ''' Get the IP layer's payload, only return corresponding port packet
            if lower level TIMEOUT or corrput packet during transmission
                return False
            else return the packet
        '''
        packet = TCPPacket()
        response = self.sock.recv(DEFAULT_TIME_OUT)
        # if timed out, return time out
        if not response:
            return False

        #add for the pseudo header
        packet.src_ip = self.dst_ip
        packet.dst_ip = self.src_ip
        packet.decode(response)
        #packet.print_all()

        # only return the port corrent packet
        if packet.src_port == self.dst_port and packet.dst_port == self.src_port:
            return packet
        else:
            return False


    def transmission(self):
        ''' After the GET being send, start receive the inbound traffic
            Properly ACK each packet, perform the out of order reception
            In the end, sort the received packet, and return the combined payload
        '''
        receivedData = {}
        receivedDataLength = 0

        windowSize = 20480

        while True:
            packet = self.get_ip_payload()
            receivedDataLength += len(packet.data)
            # print 'len(packet.data): ',
            # print receivedDataLength
            receivedData[packet.seq] = packet.data

            # implement the sliding window to notify the remote host of the receiver's window
            if windowSize - len(packet.data) < 0:
                windowSize = 0
            else:
                windowSize -= len(packet.data)

            # Locate the Http header end location, minused by the received data length
            # is the actuall received data's length

            _pos = packet.data.find("\r\n\r\n")
            contentLengthPos = packet.data.find("Content-Length:")
            contentLength = -1

            if _pos > 0:
                httpHeaderEnd = _pos + 4
                # print 'Http header end position',
                # print httpHeaderEnd
                receivedDataLength -= httpHeaderEnd
                # print 'received Data Length: ',
                # print receivedDataLength
                
                # Useful for dealing with error code like 403
                # which include the contentLength
                if contentLengthPos > 0:
                    l = re.search("Content-Length: (\d+)", packet.data)
                    contentLength = int(l.group(1))
                    # print 'contentLength: ',
                    # print contentLength

            # server actively closed the connection
            if packet.fin == 1:
                # packet.print_all()
                self.connection_tear_down(packet.seq, packet.ack_seq, packet.data)
                break

            # ack the just received data
            self.ack_seq = packet.seq + len(packet.data)
            request = self.generate_tcp_packet('ack')
            request.window = windowSize
            self.sock.send(request.encode())

            # after the ack, increase the window
            windowSize += len(packet.data)

            # if received enough data and server passively wait for FIN
            if contentLength > 0:
                if receivedDataLength == contentLength:
                    # packet.print_all()
                    self.connection_tear_down_client(packet.seq, packet.ack_seq, packet)
                    break

        # transmission finished, packet are received out of order, need to sort them
        sortedData = collections.OrderedDict(sorted(receivedData.items()))
        data = ""
        for d in sortedData:
            data += sortedData[d]
        return data

    def connection_tear_down_client(self, seq, ack_seq, packet):
        # client ------------------>  server
        #   (6782, 5572) FIN ACK
        # client <------------------  server
        #   (5572, 6783)  ACK
        # client <------------------  server
        #   (5572, 6783)  FIN PSH ACK
        # client ------------------>  server
        #   (6783, 5573) ACK

        self.seq = packet.ack_seq
        self.ack_seq = packet.seq + len(packet.data)
        request = self.generate_tcp_packet('fin, ack')
        self.sock.send(request.encode())

        # Get the first ACK
        packet = self.receiveGetACK()
        if packet.ack_seq == (self.seq + 1):
            # Get the second FIN ACK
            packet = self.receiveGetACK()
            self.seq = packet.ack_seq
            self.ack_seq = packet.seq + 1
            request = self.generate_tcp_packet('ack')
            self.sock.send(request.encode())
            return True
            #print 'disconnected'

        return False


    def connection_tear_down(self, seq, ack_seq, data):

        # server ------------------>  client
        #   (22783, 102) FIN ACK
        # server <------------------  client
        #   (102, 22784) FIN ACK
        # server ------------------>  client
        #   (22784, 103) ACK

        self.seq = ack_seq
        self.ack_seq = seq + len(data) + 1
        request = self.generate_tcp_packet('fin, ack')
        self.sock.send(request.encode())

        # get the last ack
        packet = self.receiveGetACK()
        if packet.ack_seq == (self.seq + 1):
            return True
            #print 'disconnected'

        return False

    def increase_cwnd(self):
        ''' If no packet drop or timeout, multiple increase the cwnd
        '''
        self.cwnd *= 2
        if self.cwnd >= 1000:
            self.cwnd = 1000

    def decrease_cwnd(self):
        ''' Decrease the cwnd to 1, if sent packet detected a packet drop or timeout
        '''
        self.cwnd = 1
 
    def generate_tcp_packet(self, flag):
        '''Generate a tcp packet using various getted results
        '''
        packet = TCPPacket();
        packet.src_port = self.src_port
        packet.dst_port = self.dst_port
        packet.src_ip = self.src_ip
        packet.dst_ip = self.dst_ip
        packet.seq = self.seq
        packet.ack_seq = self.ack_seq
        # possible flag combinations for outbound traffic: syn; ack; fin,ack
        # possible flag combinations for inbound traffic: syn,ack; ack; psh,ack; fin,psh,ack
        if flag == 'ack': packet.ack = 1
        if flag == 'syn': packet.syn = 1
        if flag == 'rst': packet.rst = 1
        if flag == 'fin, ack':
            packet.fin = 1
            packet.ack = 1
        if flag == 'psh, ack':
            packet.psh = 1
            packet.ack = 1
        return packet


if __name__ == "__main__":
    sock = TCP()
    sock.connect('david.choffnes.com')
