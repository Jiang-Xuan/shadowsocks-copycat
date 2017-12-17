#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import json
import sys
import getopt
import logging
import traceback

from functools import wraps

from shadowsocks.common import to_str

VERBOSE_LEVEL = 5

verbose = 0

def check_python():
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        print('Python 2.6+ required')
        sys.exit(1)
    elif info[0] == 3 and not info[0] >= 3:
        print('Python 3.3+ required')
        sys.exit(1)
    elif info[0] not in [2, 3]:
        print('Python version not supported')
        sys.exit(1)

def get_config(is_local):
    global verbose

    # 设置日志输出级别和格式
    logging.basicConfig(level = logging.DEBUG,
                        format = '%(levelname)-s: %(message)s')
    # 是否为 local 配置文件
    if is_local:
        shortopts = 'hd:s:b:p:k:l:m:c:t:vqa'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file','user=',
                    'libopenssl=', 'libmbedtls=', 'libsodium=', 'version']

    try:
        # try 寻找配置文件
        config_path = find_config()
        # 从命令行中提取参数
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        # 从参数中提取配置文件路径参数, 如果存在, 覆盖上面的默认配置文件路径
        for key, value in optlist:
            if key == '-c':
                config_path = value
        # 如果配置文件路径找到 尝试读取, 没有找到, 就为 {}
        if config_path:
            logging.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = parse_json_in_str(f.read().decode('utf8'))
                except ValueError as e:
                    logging.error('found an error in config.json: %s',
                                e.message)
                    sys.exit(1)
        else:
            config = {}

        # 计算参数中的 verbose 的等级
        # 格式化参数的数据类型
        v_count = 0
        for key, value in optlist:
            if key == '-p':
                config['server-port'] = int(value)
            elif key == '-k':
                config['password'] = to_bytes(value)
            elif key == '-l':
                config['local_port'] = int(value)
            elif key == '-s':
                config['server'] = to_str(value)
            elif key == '-m':
                config['method'] = to_str(value)
            elif key == '-b':
                config['local_address'] = to_str(value)
            elif key == '-v':
                v_count += 1
                config['verbose'] = v_count
            elif key == '-a':
                config['one_time_auth'] = True
            elif key == '-t':
                config['timeout'] = value
            elif key == '--fast-open':
                config['fast_open'] = True
            elif key == '--libopenssl':
                config['libopenssl'] = to_str(value)
            elif key == '--libsodium':
                config['libsodium'] = to_str(value)
            elif key == '--libmbedtls':
                config['libmbedtls'] = to_str(value)
            elif key == '--workers':
                config['workers'] = int(value)
            elif key == '--manager-address':
                config['manager_address'] = to_str(value)
            elif key == '--user':
                config['user'] = to_str(value)
            elif key == '--forbidden-ip':
                config['forbidden_ip'] = to_str(value).split(',')
            elif key in ('-h', '--help'):
                print_local_help()
            elif key == '--version':
                print_shadowsocks()
                sys.exit(0)
            elif key == '-d':
                config['deamon'] = to_str(value)
            elif key == '--pid-file':
                config['pid-file'] = to_str(value)
            elif key == '--log-file':
                config['log-file'] = to_str(value)
            elif key == '-q':
                v_count -= 1
                config['verbose'] = v_count
            elif key == '--prefer-ipv6':
                config['prefer-ipv6'] = True
    except getopt.GetoptError as e:
        print(e, file = sys.stderr)
        print_help(is_local)
        sys.exit(2)
    # 如果 config 为空值({})
    if not config:
        print('config not specified')
        print_help(is_local)
        sys.exit(2)

    # 提取配置文件中的数据, 如果没有, 采取默认值
    config['password'] = to_bytes(config.get('password', b''))
    config['method'] = to_str(config.get('method', 'aes-256-cfb'))
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['pid-file'] = config.get('pid-file', '/var/run/shadowsocks.pid')
    config['log-file'] = config.get('log-file', '/var/log/shadowsocks.log')
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = to_str(config.get('local_address', '127.0.0.1'))
    config['local_port'] = config.get('local_port', 1080)
    config['one_time_auth'] = config.get('one_time_auth', False)
    config['prefer_ipv6'] = config.get('prefer_ipv6', False)
    config['server_port'] = config.get('server_port', 8388)
    config['dns_server'] = config.get('dns_server', None)
    config['libopenssl'] = config.get('libopenssl', None)
    config['libmbedtls'] = config.get('libmbedtls', None)
    config['libsodium'] = config.get('libsodium', None)

    config['tunnel_remote'] = to_str(config.get('tunnel_remote', '8.8.8.8'))
    config['tunnel_remote_port'] = config.get('tunnel_remote_port', 53)
    config['tunnel_port'] = config.get('tunnel_port', 53)

    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose = config['verbose']
    logging.basicConfig(level = level,
                        format = '%(asctime)s %(levelname)-8s %(message)s',
                        datefmt = '%Y-%m-%d %H:%M:%S')

    check_config(config, is_local)

    return config

def check_config(config, is_local):
    if config.get('deamon', None) == 'stop':
        # no need to specify configuration for daemon stop
        return

    if is_local:
        if config.get('server', None) is None:
            logging.error('server addr not specified')
            sys.exit(2)
        else:
            config['server'] = to_str(config['server'])

        if config.get('tunnel_remote', None) is None:
            logging.error('tunnel_remote addr not specified')
            print_local_help()
            sys.exit(2)
        else:
            config['tunnel_remote'] = to_str(config['tunnel_remote'])

    if is_local and not config.get('password', None):
        logging.error('password not speciofied')
        print_local_help()
        sys.exit(2)

    if 'local_port' in config:
        config['local_port'] = int(config['local_port'])

    if 'server_port' in config and type(config['server_port']) != list:
        config['server_port'] = int(config['server_port'])

    if 'tunnel_port' in config:
        config['tunnel_port'] = int(config['tunnel_port'])

    if config.get('local_address', '') in [b'0.0.0.0']:
        logging.warn('warning: local set to listen on 0.0.0.0, it\'s not safe')
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warn('warning: server set to listen on %s:%s, are you sure?' %
                    (config['server'], config['server_port']))
    if (config.get('method', '') or '').lower() == 'table':
        logging.warn('warning: table is not safe; please use a safer cipher, '
                    'like AES-256-CFB')
    if (config.get('method', '') or '').lower() == 'rc4':
        logging.warn('warning: rc4 is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    if config.get('timeout', 300) < 100:
        logging.warn('warning: you timeout %d seems too short' %
                    int(config.get('timeout')))
    if config.get('timeout', 300) > 600:
        logging.warn('warning: you timeout %d seems too long' %
                    int(config.get('timeout')))
    if config.get('password') in [b'password']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your'
                     'config.json')
        sys.exit(1)
    if config.get('user', None) is not None:
        if os.name != 'posix':
            logging.error('user can be used only in Unix')
            sys.exit(1)
    if config.get('dns_server', None) is not None:
        if type(config.get('dns_server')) != list:
            config['dns_server'] = to_str(config['dns_server'])
        else:
            config['dns_server'] = [to_str(ds) for ds in config.get('dns_server')]
        logging.info('Specified DNS server: %s' % config['dns_server'])

    config['crypto_path'] = {'openssl': config['libopenssl'],
                             'mbedtls': config['mbedtls'],
                             'sodium': config['sodium']}

    cryptor.try_cipher(config['password'], config['method'],
                        config['crypto_path'])


def find_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path

    return None

def print_help(is_local):
    if is_local:
        print_local_help()

def print_local_help():
    print('''usage: sslocal [OPTINO]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply  configurations via either config file  or command line arguments.

Proxy options:
  -c CONFIG             path to config file
  -s SERVER_ADDR        server address
  -p SERVER_PORT        server port, default: 8388
  -b LOCAL_ADDR         local binding address, default: 127.0.0.1
  -l LOCAL_PORT         local port, default: 1080
  -k PASSWORD           password
  -m METHOD             encryption method, default: aes-256-cfb
                        Sodium:
                            chacha20-poly1305, chacha20-ietf-poly1305,
                            xchacha20-ietf-poly1305,
                            sodium:aes-256-gcm,
                            salsa20, chacha20, chacha20-ietf
                        Sodium 1.0.12:
                            xchacha20
                        Openssl:
                            aes-{128|192|256}-gcm, aes-{128|192|256}-cfb,
                            aes-{128|192|256}-ofb, aes-{128|192|256}-ctr,
                            camellia-{128|192|256}-cfb,
                            bf-cfb, cast5-cfb, des-cfb, idea-cfb,
                            rc2-cfb, seed-cfb,
                            rc4, rc4-md5, table.
                        Openssl 1.1:
                            aes-{128|192|256}-ocb
                        mbedTLS:
                            mbedtls:aes-{128|192|256}-cfb128,
                            mbedtls:aes-{128|192|256}-ctr,
                            mbedtls:camellia-{128|192|256}-cfb128,
                            mbedtls:aes-{128|192|256}-gcm
  -t TIMEOUT            timeout in seconds, default: 300
  -a ONE_TIME_AUTH      one time auth
  --fast-open           use TCP_FASTOPEN, requires Linux 3.7+
  -libopenssl=PATH      custom openssl crypto lib path
  -libmbedtls=PATH      custom mbedtls crypto lib path
  -libsodium=PATH       custom sodium crypto lib path

General options:
 -h, --help             show this helpmessage and exit
 -d start/stop/restart  daemon mode
 --pid-file=PID_FILE    pid file for daemon mode
 --log-file=LOG_FILE    log file for daemon mode
 --user=USER            username to run as
 -v, -vv                verbose mode
 -q, -qq                quite mode, only show warning/errors
 --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')

def _decode_list(data):
    rv = []
    for item in data:
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv.append(value)
    return rv

def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv

def parse_json_in_str(data):
    # 解析 json 并且 转换所有的数据从 Unicode 编码格式 到 str(utf8 编码格式)
    return json.loads(data, object_hook=_decode_dict)
