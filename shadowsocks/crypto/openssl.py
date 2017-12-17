#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_char_p, c_int, c_long, byref, \
    create_string_buffer, c_void_p

from shadowsocks import common
from shadowsocks.crypto import util

__all__ = ['ciphers']

libcrypto = None
loaded = False
libsodium = None

buf = None
buf_size = 2048

ctx_cleanup = None

CIPHER_ENC_UNCHANGED = -1

def load_openssl(crypto_path = None):
    global loaded, libcrypto, libsodium, buf, ctx_cleanup

    crypto_path = dict(crypto_path) if crypto_path else dict()
    path = crypto_path.get('openssl', None)
    libcrypto = util.find_library(('crypto', 'eay32'),
                                 'EVP_get_cipherbyname',
                                 'libcrypto', path)
    if libcrypto is None:
        raise Exception('libcrypto(openssl) not found with path %s' % path)

    libcrypto.EVP_get_cipherbyname.restype = c_void_p
    libcrypto.EVP_CIPHER_CTX_new.restype = c_void_p

    libcrypto.EVP_CipherInit_ex.argtypes = (c_void_p, c_void_p, c_char_p,
                                            c_char_p, c_char_p, c_int)
    libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = (c_void_p, c_int. c_int, c_void_p)
    libcrypto.EVP_CipherUpdate.argtypes = (c_void_p, c_void_p, c_void_p,
                                           c_char_p, c_int)
    libcrypto.EVP_CipherFinal_ex.argtypes = (c_void_p, c_void_p, c_void_p)

    try:
        libcrypto.EVP_CIPHER_CTX_cleanup.argtypes = (c_void_p, )
        ctx_cleanup = libcrypto.EVP_CIPHER_CTX_cleanup
    except AttributeError:
        libcrypto.EVP_CIPHER_CTX_reset.argtypes = (c_void_p, )
        ctx_cleanup = libcrypto.EVP_CIPHER_CTX_reset
    
    buf = create_string_buffer(buf_size)

    loaded = True

def load_cipher(cipher_name):
    func_name = 'EVP_' + cipher_name.replace(b'-', b'_')
    if bytes != str:
        func_name = str(func_name, 'utf-8')
    cipher = getattr(libcrypto, cipher_name, None)
    if cipher:
        cipher.restype = c_void_p
        return cipher()
    return None

class OpenSSLCryptoBase(object):
    """
    OpenSSl crypto base class
    """
    def __init__(self, cipher_name, crypto_path = None):
        self._ctx = None
        self._cipher = None
        if not loaded:
            load_openssl(crypto_path)
        cipher_name = common.to_bytes(cipher_name)
        cipher = libcrypto.EVP_get_cipherbyname(cipher_name)
        if not cipher:
            cipher = load_cipher(cipher_name)
        if not cipher:
            raise Exception('cipher %s not found in libcrypto' % cipher_name)
        self._ctx = libcrypto.EVP_CIPHER_CTX_new()
        self._cipher = cipher
        if not self._ctx:
            raise Exception('can not create cipher context')
    
    def encrypt_once(self, data):
        return self.update(data)

    def decrypt_once(self, data):
        return self.update(data)

    def update(self, data):
        """
        Encrypt/decrypt data
        :param data: str
        :return: str
        """
        global buf_size, buf
        cipher_out_len = c_long(0)
        l = len(data)
        if buf_size < l:
            buf_size = l * 2
            buf = create_string_buffer(buf_size)
        libcrypto.EVP_CipherUpdate(
            self._ctx, byref(buf),
            byref(cipher_out_len), c_char_p(data), l
        )

        return buf.raw[:cipher_out_len.value]

