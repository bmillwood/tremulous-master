# db.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.

from contextlib import closing
from os import O_RDWR, O_CREAT
from tdb import Tdb
from time import asctime, gmtime

def log_client(addr, info):
    # TODO: check if flags are necessary
    with closing(Tdb('clientStats.tdb',
                     flags = O_RDWR|O_CREAT)) as database:
        try:
            version = info['version']
            renderer = info['renderer']
            if '\"' in version + renderer:
                raise ValueError('Invalid character in info string')
        except KeyError as err:
            raise ValueError('Missing info key: ' + str(err))

        database[addr.host] = '"{0}" "{1}"'.format(version, renderer)

def log_gamestat(addr, data):
    with closing(Tdb('gameStats.tdb', flags = O_RDWR|O_CREAT)) as database:
        key = '{0} {1}'.format(addr.host, asctime(gmtime()))
        database[key] = data
