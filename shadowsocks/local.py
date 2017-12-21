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

var strBackup = str
var count = 0
let result = []

while (strBackup.length) {
  const execStartStrResult = lifecycleStart.exec(strBackup)
  if (!execStartStrResult) {
    break
  }
  // debugger
  // 这个字符串里面贮藏着 *** [7]: LIFECYCLE START *** *** [7]: LIFECYCLE START END *** 起始字符串, 因为在下面我要裁切掉这一段, 但是我要显示这一段, 所以在这里做一个备份, 在向 result<Array> 里面 push 的时候会将这个一段字符添加进去
  const startStr = strBackup.substring(execStartStrResult.index, execStartStrResult.index + execStartStrResult[0].length)
  // 裁剪字符串, 这里会将上面说的字符给裁切掉
  strBackup = strBackup.substring(execStartStrResult.index + execStartStrResult[0].length)
  // 该次通讯的 file descriptor
  const fileDescriptor = execStartStrResult[1]
  console.log(fileDescriptor)
  // 这一次的匹配到这里
  console.log(execStartStrResult.index)
  // 生成 请求 END 字符匹配正则
  const tmpLifecycleEnd = replace(lifecycleEnd)('filedescriptor', +fileDescriptor)()
  const execEndStrResult = tmpLifecycleEnd.exec(str)
  console.log(execEndStrResult)
  
  result.push({
    index: count++,
    fileDescriptor: execStartStrResult[1],
    start: execStartStrResult.index,
    end: execEndStrResult.index + execEndStrResult[0].length,
    str: startStr + strBackup.substring(0, execEndStrResult.index + execEndStrResult[0].length)
  })
}

console.log(result)
'''