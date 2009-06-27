# db.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.

from contextlib import closing
from os import O_RDWR, O_CREAT
from tdb import Tdb

from config import log, LOG_VERBOSE, LOG_DEBUG

def log_client(addr, info):
    try:
        # TODO: check if flags are necessary
        with closing(Tdb('clientStats.tdb',
                         flags = O_RDWR|O_CREAT)) as database:
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
