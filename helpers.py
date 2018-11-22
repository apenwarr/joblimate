import os, struct, sys

DEBUG=0


def log(fmt, *args):
    if args:
        s = str(fmt) % args
    else:
        s = str(fmt)
    sys.stderr.write(s + '\n')


def debug(fmt, *args):
    if DEBUG:
        log(fmt, *args)


def send_tlv(fd, tag, s):
    s = str(s)
    h = struct.pack('!II', tag, len(s))
    n = os.write(fd, h + s)
    assert n == 8 + len(s)


def read_all(fd, n):
    bb = ''
    while n > 0:
        b = os.read(fd, n)
        if not b: break
        n -= len(b)
        bb += b
    return bb


def read_tlv(fd):
    h = read_all(fd, 8)
    assert len(h) == 8
    tag, n = struct.unpack('!II', h)
    v = read_all(fd, n)
    assert len(v) == n, 'got %d expected %d' % (len(v), n)
    return tag, v
