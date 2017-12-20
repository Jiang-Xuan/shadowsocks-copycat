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
import time

from shadowsocks import cryptor, eventloop, shell, common
from shadowsocks.common import parse_header

# 每一次轮询最多的 超时清理的大小
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
这些状态控制着 socket 的监听模式
'''
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

WAIT_STATUS_NAMES = {
    WAIT_STATUS_INIT: 'WAIT_STATUS_INIT',
    WAIT_STATUS_READING: 'WAIT_STATUS_READING',
    WAIT_STATUS_WRITING: 'WAIT_STATUS_WRITING',
    WAIT_STATUS_READWRITING: 'WAIT_STATUS_READWRITING'
}

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

def _check_auth_method(data):
    '''
    socks5 客户端握手包 \x05\x01\x00
    检查认证方法
    '''
    if len(data) < 3:
        logging.warning('method selection header too short')
        raise BadSocksHeader
    sockes_version = common.ord(data[0])
    nmethods = common.ord(data[1])
    if sockes_version != 5:
        logging.warning('unsupported SOCKS protocal version ' + str(sockes_version))
        raise BadSocksHeader
    if nmethods < 1 or len(data) != nmethods + 2:
        logging.warning('NMETHODS and number of METHODS mismatch')
        raise BadSocksHeader
    noauth_exist = False
    for method in data[2:]:
        if common.ord(method) == METHOD_NOAUTH:
            noauth_exist = True
            break
    if not noauth_exist:
        logging.warning('none of SOCKS METHOD\'s'
                        'requested by client is supported')
        raise NoAcceptableMethods

class TCPRelayHandler(object):
    def __init__(self, server, fd_to_handlers, loop,local_sock, config, dns_resolver):
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        self._dns_resolver = dns_resolver
        self._stage = STAGE_INIT
        self._cryptor = cryptor.Cryptor(config['password'],
                                       config['method'],
                                       config['crypto_path'])
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._client_address = local_sock.getpeername()[:2]
        self._remote_address = None
        self._forbidden_iplist = config.get('forbidden_ip')
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

    def _update_activity(self, data_len = 0):
        self._server.update_activity(self, data_len)

    def handle_event(self, sock, event):
        '''
        handle all events in this handler and dispatch them to methods
        如果 sock 是服务器监听的 都是 socket 就不会走到这里, 需要到这里处理的 socket 是处理客户端(client_socket)连接和服务端(server_socket)连接的, 这里会处理所有的事件然后将其分发到其对应的方法内
        '''
        if self._stage == STAGE_DESTROYED:
            logging.debug('ignore handl_event: destoryed')
            return

        # 如果发生事件的是 服务端(server_socket)连接的 socket
        if sock == self._remote_sock:
            logging.info(
                '[%d] - [%d]: handle_event 触发事件的是 _remote_sock' %
                (self._local_sock.fileno(), self._remote_sock.fileno())
            )
            if event & eventloop.POLL_ERR:
                logging.info(
                    '[%d] - [%d]: handle_event _remote_sock 触发 POLL_ERR' %
                    (self._local_sock.fileno(), self._remote_sock.fileno()))
                self._on_remote_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                logging.info(
                    '[%d] - [%d]: handle_event _remote_sock 触发 POLL_IN 读取 remote 数据 => _on_remote_read'
                    % (self._local_sock.fileno(), self._remote_sock.fileno()))
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                logging.info(
                    '[%d] - [%d]: handle_event _remote_sock 触发 POLL_OUT 写入 remote 数据 => _on_remote_write'
                    % (self._local_sock.fileno(), self._remote_sock.fileno()))
                self._on_remote_write()
        elif sock == self._local_sock:
            if event & eventloop.POLL_ERR:
                self._on_local_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_OUT):
                self._on_local_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_local_write()
        else:
            logging.warn('unknown socket')

    def _on_local_read(self):
        '''
        从客户端来了数据
        处理所有来自 local 的数据并将其分发到其方法中
        '''
        if not self._local_sock:
            return
        data = None
        buf_size = UP_STREAM_BUF_SIZE

        try:
            data = self._local_sock.recv(buf_size)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return

        logging.info('[%d]: _on_local_read local 数据被读取 数据为: [%s]' %
                     (self._local_sock.fileno(),
                      ''.join(['0x%02x ' % ord(x) for x in data])))
        # 如果没有数据, 说明对方 socket 主动关闭
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))

        if self._stage == STAGE_STREAM:
            self._handle_stage_stream(data)
            return
        elif self._stage == STAGE_INIT:
            self._handle_stage_init(data)

        elif self._stage == STAGE_CONNECTING:
            self._handle_stage_connecting(data)
        elif self._stage == STAGE_ADDR:
            self._handle_stage_addr(data)

    def _handle_stage_init(self, data):
        logging.info(
            '[%d]: _handle_stage_init 处理该 local socket 的握手阶段 握手数据[%s]' %
            (self._local_sock.fileno(),
             ''.join(['0x%02x ' % ord(x) for x in data])))
        try:
            _check_auth_method(data)
        except BadSocksHeader:
            self.destory()
            return
        except NoAcceptableMethods:
            self._write_to_sock(b'\x05\xff', self._local_sock)
            self.destory()
            return

        logging.info(
            '[%d]: _handle_stage_init 校验握手数据包(%s)成功, 写入响应握手包(\\x05\\x00)' %
            (
                self._local_sock.fileno(),
                ''.join(['0x%02x ' % ord(x) for x in data])
            )
        )
        self._write_to_sock(b'\x05\x00', self._local_sock)
        logging.info(
            '[%d]: _handle_stage_init 握手包响应成功, 进入 STAGE_ADDR 阶段' %
            (self._local_sock.fileno())
        )
        self._stage = STAGE_ADDR

    def _update_stream(self, stream, status):
        dirty = False
        if stream == STREAM_DOWN:
            logging.info(
                '[%d]: _update_stream 当前的 STREAM_DOWN 的数据流向为 %s 更新 STREAM_DOWN 的数据流方向为 %s' %
                (
                    self._local_sock.fileno(),
                    WAIT_STATUS_NAMES.get(self._downstream_status),
                    WAIT_STATUS_NAMES.get(status)
                )
            )
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True
        if not dirty:

            return

        if self._local_sock:
            event = eventloop.POLL_ERR
            if self._downstream_status & WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            if self._upstream_status & WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            self._loop.modify(self._local_sock, event)
        if self._remote_sock:
            event = eventloop.POLL_ERR
            if self._downstream_status & WAIT_STATUS_READING:
                event |= eventloop.POLL_IN
            if self._upstream_status & WAIT_STATUS_WRITING:
                event |= eventloop.POLL_OUT
            self._loop.modify(self._remote_sock, event)

    def _write_to_sock(self, data, sock):
        if not data or not sock:
            return False

        # 标识数据是否完全发送
        uncomplete = False
        try:
            l = len(data)
            s = sock.send(data)

            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            errno_no = eventloop.errno_from_exception(e)
            if errno_no in (errno.EAGAIN, errno.EINPROGRESS, errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destory()
                return False
        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                logging.error('write_all_to_sock: unknown socket')
        else:
            if sock == self._local_sock:                
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                logging.error('write_all_to_sock: unknown socket')
        return True

    def _handle_stage_addr(self, data):
        logging.info(
            '[%d]: _handle_stage_addr 处理该阶段的数据(%s)' %
            (
                self._local_sock.fileno(),
                ''.join(['0x%02x ' % ord(x) for x in data])
            )
        )
        cmd = common.ord(data[1])

        if cmd == CMD_CONNECT:
            logging.info(
                '[%d]: _handle_stage_addr socks5 连接命令(\\x01) ' %
                (self._local_sock.fileno())
            )
            data = data[3:]

        header_result = parse_header(data)

        if header_result is None:
            raise Exception('can not parse header')
        addrtype, remote_addr, remote_port, header_length = header_result
        logging.info(
            '[%d]: _handle_stage_addr data的解析结果(addrtype: %s, remote_addr: %s, remote_port: %d, header_length: %d)' %
            (self._local_sock.fileno(), common.to_str(addrtype), remote_addr, remote_port, header_length)
        )

        logging.info('[%d]: _handle_stage_addr connecting %s:%d from %s:%d' %
                     (self._local_sock.fileno(), common.to_str(remote_addr), remote_port,
                      self._client_address[0], self._client_address[1]))

        self._remote_address = (common.to_str(remote_addr), remote_port)

        # 暂停读取 _local_sock 数据, 没有函数处理 STAGE_DNS 阶段的数据
        self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
        logging.info(
            '[%d]: _handle_stage_addr 进入 STAGE_DNS 阶段, 查询服务器的 IP地址' %
            (self._local_sock.fileno())
        )
        self._stage = STAGE_DNS

        self._write_to_sock(b'\x05\x00\x00\x01'
                            b'\x00\x00\x00\x00\x10\x10',
                            self._local_sock)
        data_to_send = self._cryptor.encrypt(data)
        logging.info(
            '[%d]: _handle_stage_addr 响应给浏览器(\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x10\\x10)成功, 加密后的请求数据(%s)'
            % (self._local_sock.fileno(), data_to_send))
        self._data_to_write_to_remote.append(data_to_send)

        logging.info(
            '[%d]: _handle_stage_addr 将加密后的数据存放到 _data_to_write_to_remote 之后调用 DNS 请求解析 ss 服务端地址' %
            (self._local_sock.fileno())
        )
        self._dns_resolver.resolve(self._chosen_server[0],
                                   self._handle_dns_resolved)

    def _handle_stage_connecting(self, data):
        logging.info(
            '[%d] - [%d]: _handle_stage_connecting 处理 stSTAGE_CONNECTING 阶段的数据(%s)'
            % (self._local_sock.fileno(), self._remote_sock.fileno(),
               data.replace('\r\n', ' ')))
        data = self._cryptor.encrypt(data)
        self._data_to_write_to_remote.append(data)
        logging.info(
            '[%d] - [%d]: _handle_stage_connecting 加密后数据(%s) 数据被添加进 _data_to_write_to_remote 因为此时 remote_sock[fd: %d] 还没有建立连接, 一旦建立连接, 走的就是 STAGE_STREAM 逻辑' %
            (
                self._local_sock.fileno(),
                self._remote_sock.fileno(),
                ''.join(['0x%02x ' % ord(x) for x in data]),
                self._remote_sock.fileno()
            )
        )

    def _handle_dns_resolved(self, result, error):
        logging.info(
            '[%d]: _handle_dns_resolved DNS 解析完成(ip: %s, ip: %s)' %
            (self._local_sock.fileno(), result[0], result[1])
        )
        if error:
            logging.info(
                '[%d]: _handler_dns_resolved DNS 解析出错(err: %s) 调用destroy销毁该连接' %
                (self._local_sock.fileno(), error)
            )
            addr, port = self._client_address[0], self._client_address[1]
            logging.error(
                '%s when handling connection from %s:%d' %
                (error, addr, port)
            )
            self.destroy()
            return
        if not (result and result[1]):
            self.destroy()
            return

        ip = result[1]
        logging.info(
            '[%d]: _handle_dns_resolved 进入 STAGE_CONNECTING 阶段, 开始连接 ss 服务端' %
            (self._local_sock.fileno()))
        self._stage = STAGE_CONNECTING
        remote_addr = ip
        remote_port = self._chosen_server[1]

        logging.info('[%d]: _handle_dns_resolved 创建连接 ss 服务端的 socket ' %
                     (self._local_sock.fileno()))
        remote_sock = self._create_remote_sock(remote_addr, remote_port)
        logging.info(
            '[%d]: _handle_dns_resolved 连接 ss 服务端 的 socket(fd: [%d]) 创建成功' %
            (self._local_sock.fileno(), self._remote_sock.fileno()))

        try:
            logging.info(
                '[%d] - [%d]: _handle_dns_resolved 调用 connect 方法尝试连接 ss 服务器' %
                (self._local_sock.fileno(), self._remote_sock.fileno()))
            remote_sock.connect((remote_addr, remote_port))
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                pass

        logging.info(
            '[%d] - [%d]: _handle_dns_resolved 和 ss 服务器的连接还在创建中, 将 remote_sock 加入 loop 中'
            % (self._local_sock.fileno(), self._remote_sock.fileno()))
        self._loop.add(remote_sock, eventloop.POLL_ERR | eventloop.POLL_OUT,
                       self._server)

        logging.info(
            '[%d] - [%d]: _handle_dns_resolved 进入 STAGE_CONNECTING 中' %
            (self._local_sock.fileno(), self._remote_sock.fileno()))
        self._stage = STAGE_CONNECTING
        # 监听 remote_sock 的写事件, 因为想要向远程写数据
        self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
        # 监听 remote_sock 的读事件, 因为 remote_sock 有可能因为意外关闭连接(timeout, refused, 远程没有开启这个端口)
        self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _create_remote_sock(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)

        if len(addrs) == 0:
            raise Exception(
                'getaddrinfo failed for %s:%d' %
                (ip, port)
            )

        # addressfamily socket类型 协议 权威性名字 socketaddress
        af, socktype, proto, canonname, sa = addrs[0]

        if self._forbidden_iplist:
            if common.to_str(sa[0]) in self._forbidden_iplist:
                raise Exception(
                    'IP %s is in forbidden list, reject' %
                    common.to_str(sa[0])
                )
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock
    def _on_remote_write(self):
        logging.info(
            '[%d] -[%d]: _on_remote_write _data_to_write_to_remote中的数据写向 _remote_sock 此时远程连接成功建立, 进入 STAGE_STREAM 阶段'
            % (self._local_sock.fileno(), self._remote_sock.fileno()))
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            logging.info(
                '[%d] - [%d]: _on_remote_write _data_to_write_to_remote有数据, 拼起来, 置空_data_to_write_to_remote, 将拼起来的数据写向 _remote_sock'
                % (self._local_sock.fileno(), self._remote_sock.fileno()))
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data, self._remote_sock)
        else:
            logging.info(
                '[%d] - [%d]: _on_remote_write _data_to_write_to_remote没有数据, STREAM_UP 流向置为读, 因为没有数据在STREAM_UP 上面写'
                % (self._local_sock.fileno(), self._remote_sock.fileno()))
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)

    def _handle_stage_stream(self, data):
        logging.info(
            '[%d] - [%d]: _handle_stage_stream STAGE_STREAM 阶段, 直接将数据(%s)加密后写向 _remote_sock'
            % (self._local_sock.fileno(), self._remote_sock.fileno(), data))
        data = self._cryptor.encrypt(data)
        self._write_to_sock(data, self._remote_sock)
        return

    def _on_remote_read(self):
        logging.info('[%d] - [%d]: _on_remote_read 从远程读取数据' %
                     (self._local_sock.fileno(), self._remote_sock.fileno()))
        data = None

        buf_size = UP_STREAM_BUF_SIZE

        try:
            data = self._remote_sock.recv(buf_size)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT,
                                                     errno.EAGAIN,
                                                     errno.EWOULDBLOCK):
                return
        logging.info('[%d] - [%d]: _on_remote_read 从远程读取数据成功' %
                     (self._local_sock.fileno(), self._remote_sock.fileno()))
        if not data:
            logging.info(
                '[%d] - [%d]: _on_remote_read 远程读取数据(%s)为空, 远程已经关闭了连接 调用销毁函数 destroy'
                % (self._local_sock.fileno(), self._remote_sock.fileno(),
                   data))
            self.destroy()
            return

        self._update_activity(len(data))
        data = self._cryptor.decrypt(data)
        logging.info('[%d] - [%d]: _on_remote_read 解密从远程读取的数据(%s)' %
                     (self._local_sock.fileno(), self._remote_sock.fileno(),
                      data.replace('\r\n', ' ')))
        try:
            logging.info(
                '[%d] - [%d]: _on_remote_read try将解密过后的数据(%s)写向 _local_sock' %
                (self._local_sock.fileno(), self._remote_sock.fileno(),
                 data.replace('\r\n', ' ')))
            self._write_to_sock(data, self._local_sock)
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            self.destroy()

    def destroy(self):
        if self._stage == STAGE_DESTROYED:
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            logging.debug('destroy: %s:%d' %
                          self._remote_address)
        else:
            logging.debug('destroy')

        if self._remote_sock:
            logging.debug('destroying remote')
            self._loop.remove(self._remote_sock)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroy local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)


class TCPRelay(object):
    def __init__(self, config, dns_resolver, stat_callback=None):
        self._config = config
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}

        self._timeout = config['timeout']
        self._timeouts = []
        self._timeout_offset = 0
        self._handler_to_timeouts = {}

        listen_addr = config['local_address']
        listen_port = config['local_port']

        self._listen_port = listen_port

        addrs = socket.getaddrinfo(listen_addr, listen_port, 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)

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
        logging.info('[%d]: add_to_loop 将服务端 socket 加入 loop' %
                     (self._server_socket.fileno()))
        self._eventloop.add(self._server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR,
                            self)

    def handle_event(self, sock, fd, eventMode):
        if sock == self._server_socket:
            if eventMode & eventloop.POLL_ERR:
                raise Exception('server_socket error')
            try:
                logging.info('[%d]: handle_event 客户端向服务端socket请求连接' %
                             (self._server_socket.fileno()))
                conn = self._server_socket.accept()
                logging.info(
                    '[%d]: handle_event 服务器接受该请求, 并生成一个 socket[fd: %d] 和其通讯' %
                    (self._server_socket.fileno(), conn[0].fileno()))
                TCPRelayHandler(
                    self, self._fd_to_handlers,
                    self._eventloop, conn[0],
                    self._config, self._dns_resolver
                )
            except (OSError, IOError) as e:
                errno_no = eventloop.errno_from_exception(e)
                if errno_no in (errno.EAGAIN, errno.EINPROGRESS, errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, eventMode)
            else:
                logging.warn('poll removed fd %d', fd)

    def update_activity(self, handler, data_len):
        if data_len and self._stat_callback:
            self._stat_callback(self._listen_port, data_len)

        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)

        if index >= 0:
            self._timeouts[index] = None
        length = len(self._timeouts)

        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)

        if index >= 0:
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]
