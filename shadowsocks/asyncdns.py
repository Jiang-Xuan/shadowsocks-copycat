#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

class DNSResolver(object):
    def __init__(self):
        self._loop = None
        self._cb_to_hostname = {}

    def resolve(self, hostname, callback):
        callback((hostname, hostname), None)
    
    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]