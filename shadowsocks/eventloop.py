#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import time
import socket
import select
import traceback
import errno
import logging
from collections import defaultdict

from shadowsocks import shell

__all__ = ['EventLoop', 'POLL_NULL', 'POLL_IN', 'POLL_OUT', 'POLL_ERR',
           'POLL_HUP', 'POLL_NVAL', 'EVENT_NAMES']

'''
这里是用来生成 POLL_IN 和 POLL_OUT 的掩码所用
'''
POLL_NULL = 0x00  # 00000000
'''
流入事件
'''
POLL_IN = 0x01  # 00000001
'''
流出事件
'''
POLL_OUT = 0x04   # 00000100
'''
A POLLERR means the socket got an asynchronous error. In TCP, this typically means a RST has been received or sent. If the file descriptor is not a socket, POLLERR might mean the device does not support polling.
'''
POLL_ERR = 0x08  # 00001000
'''
A POLLHUP means the socket is no longer connected. In TCP, this means FIN has been received and sent.
'''
POLL_HUP = 0x10   # 00001010

POLL_NVAL = 0x20  # 00010000

EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL'
}

# check timeouts every TIMEOUT_PRECISION seconds
TIMEOUT_PRECISION = 1000

class KqueueLoop(object):
    MAX_EVENT = 1024

    def __init__(self):
        self._kqueue = select.kqueue()
        self._fds = {}

    def _control(self, fd, mode, flags):
        events = []
        if mode & POLL_IN:
            events.append(
                select.kevent(fd, select.KQ_FILTER_READ, flags)
            )
        if mode & POLL_OUT:
            events.append(
                select.kevent(fd, select.KQ_FILTER_WRITE, flags)
            )
        for e in events:
            self._kqueue.control([e], 0)

    def poll(self, timeout):
        if timeout < 0:
            timeout = None
        events = self._kqueue.control(
            None, KqueueLoop.MAX_EVENT, timeout
        )
        result = defaultdict(lambda: POLL_NULL)
        for e in events:
            fd = e.ident
            if e.filter == select.KQ_FILTER_READ:
                result[fd] |= POLL_IN
            elif e.filter == select.KQ_FILTER_WRITE:
                result[fd] |= POLL_OUT
        return result.items()

    def register(self, fd, mode):
        self._fds[fd] = mode
        self._control(fd, mode, select.KQ_EV_ADD)

    def unregister(self, fd):
        self._control(fd, self._fds[fd], select.KQ_EV_DELETE)
        del self._fds[fd]

    def modify(self, fd, mode):
        self.unregister(fd)
        self.register(fd, mode)

    def close():
        self._kqueue.close()

class EventLoop(object):
    def __init__(self):
        self._impl = KqueueLoop()  # Implementation
        mode = 'kqueue'

        self._fdmap = {}
        self._last_time = time.time()
        self._periodic_callbacks = []
        self._stopping = False
        logging.info('使用 kqueue loop 模式')

    def poll(self, timeout=None):
        events = self._impl.poll(timeout)
        result = []

        for fd, eventMode in events:
            result.append((self._fdmap[fd][0], fd, eventMode))

        return result

    def add(self, f, mode, handler):
        '''
        往 eventloop 里面添加目标
        :params f: socket
        :params mode: POLL_IN or POLL_OUT or POLL_ERR or 组合
        :params handler: 该 socket 的处理器
        '''
        # 获取 socket 文件的 文件描述符
        fd = f.fileno()
        # fd => (socket, handler)
        self._fdmap[fd] = (f, handler)
        # 注册该文件描述符
        self._impl.register(fd, mode)

    def remove(self, f):
        fd = f.fileno()
        del self._fdmap[fd]
        self._impl.unregister(fd)

    def add_periodic(callback):
        self._periodic_callbacks.append(callback)

    def remove_periodic(callback):
        self._periodic_callbacks.remove(callback)

    def modify(self, f, mode):
        fd = f.fileno()
        self._impl.modify(fd, mode)

    def stopping(self):
        self._stopping = True

    def run(self):
        events = []
        while not self._stopping:
            asap = False
            try:
                events = self.poll(TIMEOUT_PRECISION)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    asap = True
                    logging.debug('poll: %s', e)
                else:
                    logging.error('poll: %s', e)
                    traceback.print_exc()
                    continue

            for sock, fd, eventMode in events:
                handler = self._fdmap.get(fd, None)

                if handler is not None:
                    handler = handler[1]
                    try:
                        handler.handle_event(sock, fd, eventMode)
                    except (OSError, IOError) as e:
                        shell.print_exception(e)

    def __del__(self):
        self._impl.close()


# from tornado
def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None
