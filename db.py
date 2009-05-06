# db.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.

from os import O_RDWR, O_CREAT
from tdb import Tdb

from config import log, LOG_VERBOSE, LOG_DEBUG

class WithTDB(Tdb):
    '''A TDB file that can be used as the expression of a `with' statement
    in a similar way to normal files'''
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def log_client(addr, info):
    try:
        # TODO: check if flags are necessary
        with WithTDB('clientStats.tdb', flags = O_RDWR|O_CREAT) as database:
            try:
                version = info['version']
                renderer = info['renderer']
                if '\"' in version + renderer:
                    raise ValueError('Invalid character in info string')
            except KeyError, e:
                raise ValueError('Missing info key: ' + str(e))

            database[addr.host] = '"{0}" "{1}"'.format(version, renderer)

            log(LOG_DEBUG, 'Recorded client stat for', addr)
    except ValueError, ex:
        log(LOG_VERBOSE, 'Client', addr, 'not logged:', ex)
