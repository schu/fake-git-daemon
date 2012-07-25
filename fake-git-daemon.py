#!/usr/bin/env python

import logging
import re
import socket
import struct
import sys

from threading import Thread
from time import sleep

from daemon import Daemon

LOG_FILE = '/tmp/fake-git-daemon.log'
PID_FILE = '/tmp/fake-git-daemon.pid'
HOST = 'localhost'
PORT = 9418

BRANCH = 'refs/heads/master'
HEAD = '870f66e7914d3d601e0775e988b127bde6a27a2b'
PACK = '\
\x50\x41\x43\x4b\x00\x00\x00\x02\x00\x00\x00\x06\x98\x0e\x78\x9c\x9d\xcb\x4b\
\x0a\xc2\x30\x14\x46\xe1\x79\x56\x91\xb9\xb4\xdc\xdc\xbc\x2a\x88\xd8\x99\xdb\
\xb8\x4d\xfe\x68\xe9\x93\x12\xc1\xe5\xab\x5b\x70\x78\x3e\x38\xf5\x00\x34\x75\
\x70\x36\xe5\xc1\xa7\xa1\x2b\x5c\x42\x88\xde\x1b\x63\x8b\xef\xd8\x07\xc7\x81\
\x01\x32\xcc\x67\xb5\xcb\x81\xb5\xea\x18\xc5\x94\x9c\x9c\x73\x1c\x05\x99\xa9\
\x58\x71\xd9\x0f\x70\x31\x1b\x1f\x03\x02\xc8\x52\xf6\x4a\x5e\xf5\xb9\x1d\xba\
\x9f\xc7\x04\x7d\x6f\x75\x9f\x26\x1c\xfa\x22\xbf\xbe\xe1\x2d\xcb\x3e\xa3\x4d\
\xdb\x72\xd5\xc6\x3a\x3e\x87\xd0\x11\xeb\x13\x31\x91\xfa\xea\x32\xd6\x8a\xff\
\x6e\x55\x64\x42\xf3\x18\x6b\x93\x05\xcb\xb6\xaa\x0f\xa4\xd2\x44\x18\x98\x0b\
\x78\x9c\x9d\xcb\x41\x0e\xc2\x20\x10\x40\xd1\x3d\xa7\x98\xbd\x69\x43\x41\xa6\
\x34\x31\xc6\xee\xbc\xc6\x30\x0c\x4a\x5a\xc4\x10\x4c\x3c\xbe\x7a\x05\x97\xff\
\x25\xbf\x37\x11\x98\x50\x62\x72\x36\xa0\xb7\xcc\x48\xc9\xa1\x0d\x12\xd9\x19\
\xbf\x68\x09\xde\xc5\xc0\x76\x0e\x9e\x15\xbd\xfa\xbd\x36\x58\xf7\xcc\x02\xd7\
\x11\x56\xde\xa4\xc1\x89\x7e\x7d\x91\x37\x95\xe7\x2e\x23\xd7\x72\x86\xc9\x1e\
\xcd\x82\x38\x23\xc2\x41\x1b\xad\xd5\x57\x4b\xee\x5d\xfe\xbb\x55\xa2\x4d\x86\
\x5b\xee\x43\x24\x29\xf5\xa1\x3e\x6e\xc0\x37\xe3\xa5\x02\x78\x9c\x33\x34\x30\
\x30\x33\x31\x51\x08\x72\x75\x74\xf1\x75\xd5\xcb\x4d\x61\xf8\xf5\x39\xc2\x48\
\x40\x4c\x29\xab\x74\xed\xc9\x93\x75\x7f\xd5\xb7\x32\xac\x4b\x8d\x00\x00\xd8\
\xac\x0d\x9c\xb0\x08\x78\x9c\x4b\x4b\xcc\x4e\xd5\x4d\xcf\x2c\xd1\x4d\x49\x4c\
\xcd\xcd\xcf\xe3\x4a\xa3\x33\x1f\x00\x8a\xbd\x2d\x99\xa5\x02\x78\x9c\x33\x34\
\x30\x30\x33\x31\x51\x08\x72\x75\x74\xf1\x75\xd5\xcb\x4d\x61\x38\xf0\x3d\xfa\
\xba\x13\x5b\x9f\xf6\x6e\x89\x19\xac\x31\x9b\x3e\x3a\xcc\xde\xef\x73\x03\x00\
\xda\xd6\x0e\x14\x75\xfa\xf3\x58\x32\x10\x16\x22\x6a\x75\xad\xc9\xc9\x7e\xfd\
\x27\xb5\x00\xae\x65\x58\x78\x9c\x6b\x60\x74\x98\xe0\x00\x00\x04\xa9\x01\x92\
\xd7\x24\xa8\x14\x03\x08\x8b\xac\xd0\x6f\x54\x75\xf8\x7b\x22\x43\x8f\xf1\x8a\
\xee'


USAGE = 'usage: %s start|stop|restart' % sys.argv[0]

BUF_SIZE = 2048

logging.basicConfig(format='%(message)s')

PKT_FLUSH = '0000'
PKT_NOREF = '003e0000000000000000000000000000000000000000 capabilities^{}\0\n'
PKT_DONE = '0009done'
PKT_NAK = '0007NAK'


def _pkt_line(oid, ref):
    return '%0.4x%s %s\n' % (len(oid) + len(ref) + 6, oid, ref)


class upload_pack(Thread):

    def __init__(self, client):
        Thread.__init__(self)
        self.client = client

    def run(self):

        self.client.send(_pkt_line(HEAD, 'HEAD'))
        self.client.send(_pkt_line(HEAD, BRANCH))
        self.client.send(PKT_FLUSH)

        data = self.client.recv(BUF_SIZE)
        if data == PKT_FLUSH:
            self.client.close()
            return

        while True:

            # client is talking, we don't care for now

            for pkt in data.rsplit('\n'):
                if pkt == PKT_DONE:
                    self.client.send(PKT_NAK)
                    self.client.send(PACK)
                    self.client.send(PKT_FLUSH)
                    self.client.close()
                    return

            data = self.client.recv(BUF_SIZE)


class receive_pack(Thread):

    def __init__(self, client):
        Thread.__init__(self)
        self.client = client

    def run(self):

        self.client.send(PKT_NOREF)
        self.client.send(PKT_FLUSH)
        self.client.send(PKT_FLUSH)
        self.client.close()


class fgd(Daemon):

    def __init__(self, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null',
                 host=HOST, port=PORT, loglevel=logging.WARN,
                 logfile=LOG_FILE, pidfile=PID_FILE):

        Daemon.__init__(self, pidfile, stdin=stdin, stdout=stdout, stderr=stderr)

        lf = logging.FileHandler(logfile)

        self.logger = logging.getLogger()
        self.logger.setLevel(loglevel)
        self.logger.addHandler(lf)

        self.host = host
        self.port = port

        self.socket = None

    def socket_init(self):
        if self.socket:
            return

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)

        self.logger.info('listening on %s:%s' % (self.host, self.port))

    def run(self):
        if not self.socket:
            self.socket_init()

        while True:
            client, address = self.socket.accept()
            self.logger.info('%s:%s connected' % (address[0], address[1]))

            try:
                data = client.recv(BUF_SIZE)

                # expecting command in pkt-line format, e.g.
                # 0032git-upload-pack /project.git\0host=myserver.com\0
                pkt = re.match('^([a-z-]*) ([^\0]*)\0host=([^\0]*)\0$', data[4:])

                cmd = pkt.group(1)
                path = pkt.group(2)
                host = pkt.group(3)

                self.logger.debug('cmd: %s    path: %s    host: %s' %
                                  (cmd, path, host))
            except:
                client.close()
                self.logger.info('%s:%s dropped' % (address[0], address[1]))
                continue

            if cmd == 'git-upload-pack':
                up = upload_pack(client)
                up.start()
            elif cmd == 'git-receive-pack':
                rp = receive_pack(client)
                rp.start()
            else:
                client.close()
                self.logger.info('%s:%s dropped' % (address[0], address[1]))

            sleep(0.2)


def _main(argv):
    if not argv:
        sys.exit(USAGE)

    d = fgd()

    if argv[0] == 'start':
        d.start()
    elif argv[0] == 'stop':
        d.stop()
    elif argv[0] == 'restart':
        d.stop()
        sleep(1)
        d.start()
    else:
        sys.exit(USAGE)


if __name__ == '__main__':
    _main(sys.argv[1:])
