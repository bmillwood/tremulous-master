#!/usr/bin/env python
###############################################################################
# master.py - a master server for Tremulous
# Copyright (c) 2009 Ben Millwood
#
# Thanks to Mathieu Olivier, who wrote the original master in C
# (this project shares none of his code, but used it as a reference)
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
###############################################################################
"""The Tremulous Master Server

Protocol for this is pretty simple.
Accepted incoming messages:
    'heartbeat <game>\\n'
        <game> is ignored for the time being (it's always Tremulous in any
        case). It's a request from a server for the master to start tracking it
        and reporting it to clients. Usually the master will verify the server
        before accepting it into the server list.
    'getservers <protocol> [empty] [full]'
        A request from the client to send the list of servers.
"""

from socket import (socket, error as sockerr, has_ipv6, inet_pton,
                   AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
from select import select
from sys import exit, stdout, stderr
from random import choice, randint

import config

pending = {} # pending[addr] = challenge
servers = []

def parseinfo(infostring):
    info = dict()
    infostring = infostring.lstrip('\\')
    while True:
        bits = infostring.split('\\', 2)
        try:
            info[bits[0]] = bits[1]
            infostring = bits[2]
        except IndexError:
            break
    return info

def challenge():
    """Returns a string of config.CHALLENGE_LENGTH characters, chosen from
    those greater than ' ' and less than or equal to '~' (i.e. isgraph)
    Semicolons, backslashes and quotes are precluded because the server won't
    put them in an infostring; forward slashes are not allowed because the
    server's parsing tools can recognise them as comments
    Percent symbols: these used to be disallowed, but subsequent to r1148 they
    should be okay. Any server older than that will translate them into '.'
    and therefore fail to match."""
    valid = [c for c in map(chr, range(0x21, 0x7f)) if c not in '\\;\"/']
    return ''.join([choice(valid) for _ in range(config.CHALLENGE_LENGTH)])

def heartbeat(addr, data):
    c = challenge()
    pending[addr] = c
    outSock.sendto('\xff\xff\xff\xffgetinfo ' + c, addr)

def infoResponse(addr, data):
    if addr not in pending.keys():
        print 'Info response from unwatched server'
        return # we don't care about an inforesponse from this address
    print 'Info response from %s:%d' % addr, data
    data = data.split(None, 1)[1]
    info = parseinfo(data)
    print info
    try:
        sent = pending[addr]
        recvd = info['challenge']
        if sent == recvd:
            servers.append(addr)
            print servers
        else:
            print 'Mismatched challenge'
    except KeyError, ex:
        print 'KeyError', str(ex)
    del pending[addr]

def getservers(addr, data):
    inSock.sendto('\xff\xff\xff\xffgetserversResponse\\' + '\\'.join([
        inet_pton(AF_INET, server[0]) +
        chr(server[1] >> 8) + chr(server[1] & 0xff)
        for server in servers] + ['EOT\0\0\0']), addr)

try:
    inSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    inSock.bind((config.bindaddr, config.inPort))
    outSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    outSock.bind((config.bindaddr, config.outPort))
    #if has_ipv6:
    #   inSock6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
    #   inSock6.bind((config.bind6addr, config.inPort))
    #   outSock6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
except sockerr, (errno, strerror):
    stderr.write("Couldn't initialise sockets: %s\n" % (strerror,))
    raise

while True:
    (ready, _, _) = select([inSock, outSock], [], [])
    if inSock in ready:
        (data, addr) = inSock.recvfrom(2048)
        stdout.write('Packet on inSock from %s:%d\n' % addr)
        if data[:4] != '\xff\xff\xff\xff':
            stdout.write('  rejected (no header)\n')
            continue
        data = data[4:]
        responses = [
            ('heartbeat', heartbeat),
            ('getservers', getservers)
        ]
        for (name, func) in responses:
            if data.startswith(name):
                func(addr, data)
                break
        else:
            stdout.write('  content: %r\n' % (data,))
    if outSock in ready:
        (data, addr) = outSock.recvfrom(2048)
        stdout.write('Packet on outSock from %s:%d\n' % addr)
        if data[:4] != '\xff\xff\xff\xff':
            stdout.write('  rejected (no header)\n')
        data = data[4:]
        if data.startswith('infoResponse'):
            infoResponse(addr, data)
        else:
            stdout.write('  content: %r\n' % (data,))
# vim: set expandtab ts=4 sw=4 :
