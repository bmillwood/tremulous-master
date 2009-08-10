#!/usr/bin/env python
from sqlite3 import connect
from time import time
from hashlib import md5

db_id = 'Using SQLite database backend'

def log_client(addr, info):
    with connect('stats.db') as db:
        dbc = db.cursor()
        dbc.execute('INSERT INTO clients VALUES(?, ?, ?)',
                    (addr.host, info['renderer'], info['version']))

def log_gamestat(addr, data):
    with connect('stats.db') as db:
        dbc = db.cursor()
        dbc.execute('INSERT INTO gamestats VALUES(?, ?, ?)',
                    (addr.host, int(time()), data))

def create_db():
    from sys import argv, exit
    if len(argv) == 1:
        exit('Usage: {0} FILE'.format(argv[0]))
    assert len(argv) > 1
    with connect('stats.db') as db:
        dbc = db.cursor()
        dbc.execute('CREATE TABLE IF NOT EXISTS '
                    'clients (addr TEXT, version TEXT, renderer TEXT)')
        dbc.execute('CREATE TABLE IF NOT EXISTS '
                    'gamestats (addr TEXT, time INTEGER, data TEXT)')

if __name__ == '__main__':
    create_db()
