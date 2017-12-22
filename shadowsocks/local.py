#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, asyncdns, tcprelay, eventloop

def main():
    # 检查当前的运行环境 是否支持, 如果不支持, sys.exit(1) 退出
    shell.check_python()

    config = shell.get_config(True)
    # deamon.deamon_exec(config)

    logging.info('start local at %s:%d' %
                (config['local_address'], config['local_port']))
    dns_resolver = asyncdns.DNSResolver()
    tcp_server = tcprelay.TCPRelay(config, dns_resolver)
    loop = eventloop.EventLoop()

    tcp_server.add_to_loop(loop)

    loop.run()

if __name__ == '__main__':
    main()
