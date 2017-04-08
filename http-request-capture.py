#!/usr/bin/env python
# --*--coding: utf-8 --*--

from scapy.all import *
from logger import logger
import time

HTTP_PORT = 80
reqUrlsFile = open('req-urls.txt', 'w+')

class HttpRequestCapture:
    def __init__(self):
        self.httpLoad = ''
        self.httpFragged = False
        self.httpPack = None

    def parser(self, pkt):
        if not pkt.haslayer(Raw):
            return
        elif not HTTP_PORT in [pkt[TCP].sport, pkt[TCP].dport]:
            return

        self.parseHttp(pkt[Raw].load, pkt[IP].ack)

    def parseHttp(self, load, ack):
        if ack == self.httpPack:
            self.httpLoad = self.httpLoad + load
            load = self.httpLoad
            self.httpFragged = True
        else:
            self.httpLoad = load
            self.httpPack = ack
            self.httpFragged = False

        try:
            headerLines, contentLines = load.split("\r\n\r\n")
            headerLines = headerLines.split('\r\n')
        except Exception:
            headerLines = load.split('\r\n')
            contentLines = ''

        httpReqUrl = self.getHttpReqUrl(headerLines)

        if httpReqUrl:
            logger(time.strftime('%a, %d %b %Y %H:%M:%S %z: '), httpReqUrl)
            self.saveReqUrl(httpReqUrl);

    def getHttpReqUrl(self, headerLines):
        host = ''
        httpReqUri = ''
        httpMethod  = headerLines[0][0:headerLines[0].find("/")].strip()

        if httpMethod != 'GET':
            return

        host = self.getHost(headerLines)

        for line in headerLines:
            if 'GET /' in line:
                httpReqUri = line.split('GET ')[1].split(' HTTP/')[0].strip()

        return ''.join([host, httpReqUri])

    def getHost(self, headerLines):
        host = ''
        for line in headerLines:
            if 'Host:' in line:
                # print(line)
                host = line.split('Host: ')[1]
        return host.strip()

    def saveReqUrl(self, reqUrl):
        reqUrlsFile.write(reqUrl+'\n')

if __name__ == "__main__":
    httpRequestCapture = HttpRequestCapture()
    try:
        logger('HTTP REQUEST CAPTURE STARTED')
        sniff(prn=httpRequestCapture.parser, filter='tcp', iface='en0')
    except KeyboardInterrupt:
        reqUrlsFile.close( )
        exit()
