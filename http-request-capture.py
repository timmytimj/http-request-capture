from scapy.all import *

httpPort = 80
reqUrlsFile = open('req-urls.txt', 'w+')

class HttpRequestCapture:

    def __init__(self):
        self.httpLoad = ''
        self.httpFragged = False
        self.httpPack = None

    def parser(self, pkt):
        if not pkt.haslayer(Raw):
            return
        elif not httpPort in [pkt[TCP].sport, pkt[TCP].dport]:
            return

        load = pkt[Raw].load
        ack = pkt[IP].ack

        self.parseHttp(load, ack)

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
            contentLines = ""

        httpReqUrl = self.getHttpReqUrl(headerLines)

        if httpReqUrl:
            logger('Http Req Url: ', httpReqUrl)
            self.saveReqUrl(httpReqUrl);

    def getHttpReqUrl(self, headerLines):
        httpReqUrl = ''
        httpReqUri = ''
        httpMethod  = headerLines[0][0:headerLines[0].find("/")].strip()

        if httpMethod != 'GET':
            return

        httpReqUrl = self.getHost(headerLines)

        for line in headerLines:
            if 'GET /' in line:
                httpReqUri = line.split('GET ')[1].split(' HTTP/')[0].strip()

        return ''.join([httpReqUrl, httpReqUri])

    def getHost(self, headerLines):
        host = ''
        for line in headerLines:
            if 'Host:' in line:
                # print(line)
                host = line.split('Host: ')[1]
        return host.strip()

    def saveReqUrl(self, reqUrl):
        reqUrlsFile.write(reqUrl+'\n')

def logger(title, content):
    w = '\033[0m'
    g = '\033[32m'
    print(g + title + w + content)

if __name__ == "__main__":
    print('Start Capture Reqest')

    httpRequestCapture = HttpRequestCapture()

    try:
        sniff(prn=httpRequestCapture.parser, iface='en0', filter='tcp');
    except KeyboardInterrupt:
        reqUrlsFile.close( )
        exit()
