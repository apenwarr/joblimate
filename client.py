#!/usr/bin/env python2
import json, os, select, socket, subprocess, struct, sys
from helpers import read_tlv, send_tlv, log, debug


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('\0joblimate')  # unix abstract namespace
    fd = sock.fileno()

    req = dict(
        exe=sys.argv[1],
        argv=list(sys.argv[1:]),
        env=dict(os.environ),
         cwd=os.getcwd()
    )
    sreq = json.dumps(req)

    send_tlv(fd, 0, sreq)
    while 1:
        r, _, _ = select.select([fd, 0], [], [])
        debug('ready: %r', r)
        if fd in r:
            tag, b = read_tlv(fd)
            debug('got: %r %r', tag, b)
            if tag == 0:
                rv, = struct.unpack('!i', b)
                debug('exit: %d', rv)
                if rv < 0:
                    os.kill(os.getpid(), -rv)
                else:
                    exit(rv)
            elif tag == 1:
                os.write(1, b)
            elif tag == 2:
                os.write(2, b)
            else:
                assert 0, 'invalid tag %d' % tag
        if 0 in r:
            b = os.read(0, 1024)
            send_tlv(fd, 1, b)
            if not b:
                debug('stdin: EOF')


if __name__ == '__main__':
    main()
