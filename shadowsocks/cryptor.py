#!/usr/bin/env python 
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging

from shadowsocks import common
from shadowsocks.crypto import openssl


CIPHER_ENC_ENCRYPTION = 1
CIPHER_ENC_DESCYPTION = 0

METHOD_INFO_KEY_LEN = 0
METHOD_INFO_IV_LEN = 1
METHOD_INFO_CRYPTO = 2

method_supported = {}
method_supported.update(openssl.ciphers)

def random_string(length):
    return os.urandom(length)

cached_keys = {}

def try_cipher(key, method=None, crypto_path=None):
    Cryptor(key, method, crypto_path)

def EVP_BytesToKey(password, key_len, iv_len):
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0

    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len: key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv

class Cryptor(object):
    def __init__(self, password, method, crypto_path=None):
        '''
        Crypto wrapper
        :param password: str cipher password
        :param method: str cipher
        :param crypto_path: dict or none
            {'openssl': path, 'sodium': path, 'mbedtls': path}
        '''
        self.password = password
        self.key = None
        self.method = method
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        self.decipher_iv = None
        self.crypto_path = crypto_path
        method = method.lower()
        self._method_info = Cryptor.get_method_info(method)
        if self._method_info:
            self.cipher = self.get_cipher(
                password, method, CIPHER_ENC_ENCRYPTION,
                random_string(self._method_info[METHOD_INFO_IV_LEN])
            )
        else:
            logging.error('method %s not supported' % method)

    @staticmethod
    def get_method_info(method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def get_cipher(self, password, method, op, iv):
        password = common.to_bytes(password)
        m = self._method_info

        if m[METHOD_INFO_KEY_LEN] > 0:
            key, _ = EVP_BytesToKey(password,
                                    m[METHOD_INFO_KEY_LEN],
                                    m[METHOD_INFO_IV_LEN])
        else:
            key, iv = password, b''
        self.key = key
        iv = iv[:m[METHOD_INFO_IV_LEN]]
        if op == CIPHER_ENC_ENCRYPTION:
            self.cipher_iv = iv
        return m[METHOD_INFO_CRYPTO](method, key, iv, op, self.crypto_path)