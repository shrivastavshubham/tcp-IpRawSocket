import argparse
from urlparse import urlparse
import sys
import time

from tcp import TCP

def getFilename(path):
    ''' Get the filename from the input path
        If no name assigned, return index.html
    '''
    length = len(path)
    index = length - 1

    # no path is given by the user
    if length == 0:
        return 'index.html'
    # Try to locate the filename index in the path
    for i in range(length - 1, 0, -1):
        if path[i] == '/':
            index = i
            break
    # return the given filename from path
    if index == (length - 1):
        return 'index.html'
    else:
        return path[index+1:]

def getRequest(path, host):
    request = 'GET ' + path + ' HTTP/1.0\r\n' + 'User-Agent: Wget/1.14 (linux-gnu)\r\n' + 'Accept: */*\r\n' + 'Host: ' + host + '\r\n' + 'Connection: keep-alive' + '\r\n\r\n'
    print request
    return request

def saveFile(filename, data):

    f = open(filename, "w+")
    f.write(data)
    f.close()


def main(url):

    parsed = urlparse(url)
    # exit on unsupported application protocol
    if parsed.scheme.lower() != 'http':
        print '"' + parsed.scheme  + '"' + ' scheme address is not supported'
        sys.exit()
    host = parsed.netloc
    filename = getFilename(parsed.path)
    request = getRequest(parsed.path, host)
    print filename
    print request
    # Initiate the download
    startTime = time.time()
    sock = TCP()
    sock.connect(host)
    sock.sendGet(request)

    # Start the retrieve
    filedata = sock.transmission()
    	
    print filedata

    # if found it is a non-200 packet, exit
    if not filedata.startswith("HTTP/1.1 200"):
        print ('Non-200 HTTP status code is not supported')
    	sys.exit(0)

    # remove the HTTP header:
    pos = filedata.find("\r\n\r\n")
    if pos > -1:
        pos += 4
        filedata = filedata[pos:]

    endTime = time.time()

    # save file to disk
    saveFile(filename, filedata)
    print len(filedata),
    print 'Bytes received'
    #timecost = '%.2g' % (endTime - startTime)
    #print timecost,
    #print 'seconds passed. Average speed:',
    #throughput = '%f' % (len(filedata) / float(timecost) / 1000)
    #print throughput,
    #print 'KBps'
    sock.sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type = str, help = 'URL of the file')
    args = parser.parse_args()
    url = args.url
    main(url)
