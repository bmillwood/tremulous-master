#!/usr/bin/env python
from sqlite3 import connect, OperationalError
from time import time
from functools import partial
from hashlib import md5

db_id = 'Using SQLite database backend'

unicise = partial(unicode, encoding = 'utf-8')

def log_client(addr, info):
    renderer = unicise(info['renderer'])
    version = unicise(info['version'])
    with connect('stats.db') as db:
        dbc = db.cursor()
        try:
            dbc.execute('INSERT INTO clients (addr, version, renderer) '
                        'VALUES (?, ?, ?)',
                        (addr.host, version, renderer))
        except OperationalError as err:
            # ValueError isn't really appropriate here but it's caught at
            # the call site and amounts to the same thing anyway
            raise ValueError('database failure: ' + str(err))

def log_gamestat(addr, data):
    with connect('stats.db') as db:
        dbc = db.cursor()
        try:
            dbc.execute('INSERT INTO gamestats (addr, time, data) '
                        'VALUES (?, ?, ?)',
                        (addr.host, int(time()), unicise(data)))
        except OperationalError as err:
            raise ValueError('database failure: ' + str(err))

def create_db(path):
    with connect(path) as db:
        dbc = db.cursor()
        dbc.execute('CREATE TABLE IF NOT EXISTS '
                    'clients (addr TEXT, version TEXT, renderer TEXT)')
        dbc.execute('CREATE TABLE IF NOT EXISTS '
                    'gamestats (addr TEXT, time INTEGER, data TEXT)')

if __name__ == '__main__':
    from sys import argv, exit
    if len(argv) > 1:
        exit('Usage: python {0} [file]'.format(argv[0]))
    try:
        p = argv[1]
    except IndexError:
        p = 'stats.db'
    create_db(p)
