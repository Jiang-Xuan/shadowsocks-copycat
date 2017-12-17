#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import errno
import struct
import logging
import traceback
import random

from shadowsocks import crypto, eventloop, shell, common
from shadowsocks.common import parse_header

TIMEOUT_CLEAN_SIZE = 512

MSG_FASTOPEN = 0x20000000

# SOCKS METHOD definition
METHOD_NOAUTH = 0

# SOCKS command definition
CMD_CONNECT = 1       # 00000001
CMD_BIND = 2          # 00000010
CMD_UDP_ASSOCIATE = 3 # 00000011

'''
for each opening port, we have a TCP Reply
for each connection, we have a TCP Relay Handler to handle the connection

for each handler, we have 2 sockets:
    local: connected to the client
    remote: connected to remote server

for each handler, it could be at one of serveral stages:
    as sslocal:
    stage 0 auth METHOD received from local, reply with selection message
    stage 1 addr received from local, query DNS from remote
    stage 2 UDP assoc
    stage 3 DNS resolved, connect to remote
    stage 4 still connecting, more data from local received
    stage 5 remote connected, piping local and remote
'''
STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

'''
for each handler, we have 2 stream directions:
    upstream: from client to server direction
              read local and write to remote
    downstream: fron server to client direction
              read remote and write to local
'''

STREAM_UP = 0
STREAM_DOWN = 1

'''
for each stream, it's waiting for reading, or writing, or both
'''
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024
UP_STREAM_BUF_SIZE = 16 * 1024
DOWN_STREAM_BUG_SIZE = 32 * 1024

'''
helper exceptions for TCPRelayHandler
'''
class BadSocksHeader(Exception):
    pass
class NoAcceptableMethods(Exception):
    pass

class TCPRelayHandler(object):
    def __init__(self, server, fd_to_handlers, loop,local_sock, config, dns_resolver, is_local):
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        self._dns_resolver = dns_resolver
        self._stage = STAGE_INIT
        self._cryptor = crypto.Cryptor(config['password'],
                                       config['method'],
                                       config['crypto_path'])
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._client_address = local_sock.getpeername()[:2]
        self._remote_address = None
        self._forbidden_iplist = config.get('forbidden_ip')
        if is_local:
            self._chosen_server = self._get_a_server()
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(local_sock, eventloop.POLL_IN | eventloop.POLL_ERR, self._server)
        self.last_activity = 0
        self._update_activity()
    
    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']

        if type(server_port) == list:
            server_port = random.choice(server_port)
        if type(server) == list:
            server = random.choice(server)
        logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

class TCPRelay(object):
    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        self._config = config
        self._is_local = is_local
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}

        self._timeout = config['timeout']
        self._timeouts = []
        self._timeout_offset = 0
        self._handler_to_timeouts = {}

        if is_local:
            listen_addr = config['local_address']
            listen_port = config['local_port']

        self._listen_port = listen_port

        addrs = socket.getaddrinfo(listen_addr, listen_port, 0, socket.SOCK_STREAM, socket.SOL_TCP)

        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" % (listen_addr, listen_port))

        af, socktype, proto, canonname, sa = addrs[0]

        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        server_socket.listen(1024)

        self._server_socket = server_socket
        self._stat_callback = stat_callback

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        
        self._eventloop = loop
        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR,
                            self)



