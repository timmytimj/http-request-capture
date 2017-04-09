#!/usr/bin/env python
# --*--coding: utf-8 --*--

import time
from scapy.all import TCP, IP, sniff, Raw
from logger import logger

HTTP_PORT = 80
REQ_URLS_FILE = open('req-urls.txt', 'w')

class HttpRequestCapture(object):
    '''HttpRequestCapture class'''
    def __init__(self):
        self.http_load = ''
        self.http_fragged = False
        self.http_pack = None

    def parser(self, pkt):
        '''
        @param {Object} params.pkt
        '''
        if not pkt.haslayer(Raw):
            return
        elif HTTP_PORT not in [pkt[TCP].sport, pkt[TCP].dport]:
            return

        self.parse_http(pkt[Raw].load, pkt[IP].ack)

    def parse_http(self, load, ack):
        '''
        @param {String} params.load
        @param {Integer} params.ack
        '''
        if ack == self.http_pack:
            self.http_load = self.http_load + load
            load = self.http_load
            self.http_fragged = True
        else:
            self.http_load = load
            self.http_pack = ack
            self.http_fragged = False

        try:
            header_lines = load.split('\r\n\r\n')[0].split('\r\n')
        except ValueError:
            header_lines = load.split('\r\n')

        http_req_url = self.get_http_req_url(header_lines)

        if http_req_url:
            logger(time.strftime('%a, %d %b %Y %H:%M:%S %z: '), http_req_url)
            REQ_URLS_FILE.write(''.join([http_req_url, '\n']))

    def get_http_req_url(self, header_lines):
        '''
        @param {List} params.header_lines
        @return {String}
        '''
        host = ''
        http_req_uri = ''
        http_method = header_lines[0][0:header_lines[0].find("/")].strip()

        if http_method != 'GET':
            return

        host = self.get_host(header_lines)

        for line in header_lines:
            if 'GET /' in line:
                http_req_uri = line.split('GET ')[1].split(' HTTP/')[0].strip()

        return ''.join([host, http_req_uri])

    def get_host(self, header_lines):
        '''
        @param {List} params.header_lines
        @return {String}
        '''
        host = ''
        for line in header_lines:
            if 'Host:' in line:
                host = line.split('Host: ')[1]
        return host.strip()

if __name__ == "__main__":
    try:
        logger('HTTP REQUEST CAPTURE STARTED')
        sniff(prn=HttpRequestCapture().parser, filter='tcp', iface='en0')
    except KeyboardInterrupt:
        REQ_URLS_FILE.close()
        exit()
