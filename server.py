#!/usr/bin/env python2
import fcntl, json, os, select, socket, subprocess, struct, sys, traceback
from helpers import read_tlv, send_tlv, log, debug

BACKLOG=10


def close_on_exec(fd, enable):
    v = fcntl.fcntl(fd, fcntl.F_GETFD)
    if enable:
        v |= fcntl.FD_CLOEXEC
    else:
        v &= ~fcntl.FD_CLOEXEC
    fcntl.fcntl(fd, fcntl.F_SETFD, v)


def replace_env(env):
    for k in os.environ.keys():
        del os.environ[k]
    for k, v in env.iteritems():
        os.environ[k] = v


def handle_conn(sock, peername):
    log('connection from %r', peername)
    fd = sock.fileno()

    tag, b = read_tlv(fd)
    debug('got blob: %d bytes', len(b))
    req = json.loads(b)
    debug('decoded:')
    for key, val in req.items():
        val = str(val)
        if len(val) > 70:
            val = val[:67] + '...'
        debug('%r: %r', key, val)

    p = subprocess.Popen(
        args=req['argv'],
        executable=req['exe'],
        cwd=req['cwd'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=lambda: replace_env(req['env'])
    )

    so = p.stdout.fileno()
    se = p.stderr.fileno()
    fds = set([fd, so, se])
    waitset = set([0, 1, 2])
    while so in fds or se in fds:
        # FIXME: handle random client disconnects with p.kill(SIGHUP).
        # FIXME: we can get into a deadlock unless we also select for write.
        #   Example: subproc stdout pipe is entirely full, but we're
        #   still trying to write to its stdin, but it will never read from
        #   its stdin.  The correct solution is to apply backpressure through
        #   sock in that case (and then the client has to handle it when
        #   there's no room left to write more stuff into sock).
        r, _, _ = select.select(list(fds), [], [])
        debug('ready: %r', r)
        if fd in r:
            tag, b = read_tlv(fd)
            debug('got: %r %r', tag, b)
            if tag == 1:
                if b:
                    p.stdin.write(b)
                else:
                    p.stdin.close()
            else:
                assert 0, 'invalid tag %d' % tag
        if so in r:
            b = os.read(so, 1024)
            debug('stdout: %r', b)
            send_tlv(fd, 1, b)
            if not b:
                fds.remove(so)
        if se in r:
            b = os.read(se, 1024)
            debug('stderr: %r', b)
            send_tlv(fd, 2, b)
            if not b:
                fds.remove(se)
    rv = p.wait()
    if rv is not None:
        send_tlv(fd, 0, struct.pack('!i', rv))
    sock.close()


def main():
    lsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind('\0joblimate')  # unix abstract namespace
    lsock.listen(BACKLOG)
    while 1:
        log('')
        log('waiting on %r', lsock.getsockname())
        sock, peername = lsock.accept()
        close_on_exec(sock, True)
        try:
            handle_conn(sock, peername)
        except Exception as e:
            traceback.print_exc()
        sock.close()


if __name__ == '__main__':
    main()
