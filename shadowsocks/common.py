#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import socket
import struct

def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s

def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s

ADDRTYPE_IPV4 = 0x01
ADDRTYPE_IPV6 = 0x04
ADDRTYPE_HOST = 0x03
ADDRTYPE_AUTH = 0x10
ADDRTYPE_MASK = 0xF

def parse_header(data):
    '''
    去掉 VER CMD RSV 之后的数据
    example: \x01\x7f\x00\x00\x01\x0f\xa0
             \x03\x13jiangxuan.org\x0f\xa0
    '''
    addrtype = ord(data[0])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype & ADDRTYPE_MASK == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_addr = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logging.warn('header is too short')
    elif addrtype & ADDRTYPE_MASK == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1])
            if len(data) >= 4 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 + addrlen])[0]
                
                header_length = 4 + addrlen
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    else:
        logging.warn('upsupported addrtype %d, maybe wrong password or'
                     'encryption method' % addrtype)
    
    if dest_addr is None:
        return None
    return addrtype, to_bytes(dest_addr), dest_port, header_length
