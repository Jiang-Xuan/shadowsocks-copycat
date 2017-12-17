#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import logging

def load_library(path, search_symbol, library_name):
    from ctypes import CDLL
    try:
        lib = CDLL(path)
        if hasattr(lib, search_symbol):
            logging.info('loading %s from %s', library_name, path)
            return lib
        else:
            logging.warning('can\'t find symbol %s in %s', search_symbol, path)
    except Exception:
        pass
    return None

def find_library(possible_lib_names, search_symbol, library_name, \
                 custom_path = None):
    import ctypes.util

    if custom_path:
        load_library(custom_path, search_symbol, library_name)
    
    paths = []

    if type(possible_lib_names) not in (list, tuple):
        possible_lib_names = [possible_lib_names]
    
    lib_names = []
    for lib_name in possible_lib_names:
        lib_names.append(lib_name)
        lib_names.append('lib' + lib_name)

    for name in lib_names:
        if os.name == 'nt':
            paths.extend(find_library_nt(name))
        else:
            path = ctypes.util.find_library(name)
            if path:
                paths.append(path)
    
    if not paths:
        import glob

        for name in lib_names:
            patterns = [
                '/usr/local/lib*/lib%s.*' % name,
                '/usr/lib*/lib%s.*' % name,
                'lib%s.*' % name,
                '%s.dll' % name
            ]

            for pat in patterns:
                files = glob.glob(pat)
                if files:
                    paths.append(files)
    
    for path in paths:
        lib = load_library(path, search_symbol, library_name)
        if lib:
            return lib
    
    return None

