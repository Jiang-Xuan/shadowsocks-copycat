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

'''javascript 分析日志的代码
function replace(regex, opt) {
  regex = regex.source
  opt = opt || ''
  return function self(name, val) {
    if(!name) return new RegExp(regex, opt)
    val = val.source || val
    // val = val.replace(/(^|[^\[])\^/g, '$1')
    regex = regex.replace(name, val)

    return self
  }
}

// 这里是 logging 的开头[2017-12-21 19:57:22 INFO     ]
const loggingStart = /^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\s(?:INFO|DEBUGG|WARNING)\s*/
// 这个匹配生命周期的开始 字符串
const lifecycleStart = /\*\*\*\s\[(\d*)\]:\s(LIFECYCLE\sSTART)\s\*\*\*\s*\*\*\*\s\[\1\]:\s\2\sEND\s\*\*\*/
// 这里匹配生命周期的结束 字符串
let lifecycleEnd = /\*\*\*\s\[(filedescriptor)\]:\s(LIFECYCLE\sEND)\s\*\*\*\s*\*\*\*\s\[\1\]:\s\2\sEND\s\*\*\*/
// 执行生命周期开始正则之后的结果
const execStartStrResult = lifecycleStart.exec(str)
// 匹配成功的 该次通讯的 file descriptor
const fileDescriptor = execStartStrResult[1]
console.log(fileDescriptor)
// 这一次的匹配到这里
const matchIndex = execStartStrResult.index
console.log(matchIndex)
// 根据上面获取的 file descripto 生成 生命周期结束的正则表达式
lifecycleEnd = replace(lifecycleEnd)('filedescriptor', +fileDescriptor)()
// 执行生命周期结束正则之后的结果
const execEndStrResult = lifecycleEnd.exec(str)
console.log(execEndStrResult)

'''