import socket, subprocess,re


def get_port():
    '''Pick a free port number
       http://stackoverflow.com/questions/1365266/
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 80))
    port = sock.getsockname()[1]
    sock.close()
    return port

def get_local_ip(host):
    '''Get the active ethernet interface's IP address
    '''
    ip_local = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip_local = s.getsockname()[0]
        s.close()
    except:
        pass
    return ip_local

def get_local_mac(ip):
    '''Get the active ethernet interface's MAC address
    '''
    output = subprocess.check_output(['ifconfig', '-a']).split('\n\n')

    i = 0
    while i < len(output):
        if ip in output[i]:
  #          print output[i]
            break

    output = output[i].split('\n')
    for o in output:
        mac = re.search(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', o, re.I)
        if mac:
            return mac.group(0).replace(':', '')
        else:
 #           print 'unable to locate mac address'
            pass

def get_interface(ip):
    '''Get the active ethernet interface
    '''
    output = subprocess.check_output(['ifconfig', '-a']).split('\n\n')

    i = 0
    while i < len(output):
        if ip in output[i]:
 #           print output[i]
            break

    output = output[i].split('\n')
   
    return output[0][0:4]


def get_gateway_ip():
    '''Get the active ethernet interface's gateway ip address
    '''
    output = subprocess.check_output(['route', '-n']).split('\n')
    for line in output:
        data = line.split()
        if data[0] == '0.0.0.0':
            return data[1]


def ip_checksum(data):
    ''' taken from http://codewiki.wikispaces.com/ip_checksum.py
    '''
    pos = len(data)
    if (pos & 1):  # If odd...
        pos -= 1
        check_sum = ord(data[pos])  # Prime the check_sum with the odd end byte
    else:
        check_sum = 0

    #Main code: loop to calculate the checkcheck_sum
    while pos > 0:
        pos -= 2
        check_sum += (ord(data[pos + 1]) << 8) + ord(data[pos])

    check_sum = (check_sum >> 16) + (check_sum & 0xffff)
    check_sum += (check_sum >> 16)

    result = (~ check_sum) & 0xffff #Keep lower 16 bits
    result = result >> 8 | ((result & 0xff) << 8)  # Swap bytes
    return result

def tcp_checksum(msg):
    '''
    '''
    s = 0
    for i in range(0, len(msg), 2):
        if i+1 <= len(msg)-1:
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        else:
            w = ord(msg[i])
        s = s + w
    s = (s>>16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


if __name__ == "__main__":
    ip = (get_local_ip('david.choffnes.com'))
    mac = get_local_mac(ip)
    gateway = get_gateway_ip()

    get_interface(ip)
    pass
