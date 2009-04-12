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
Requires Python 2.6

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

from errno import EINTR
from random import choice
from select import select, error as selecterror
from socket import (socket, error as sockerr, has_ipv6,
                   AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
from time import time

import config
from config import log, LOG_ERROR, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG

# optional imports
try:
    from signal import signal, SIGHUP, SIG_IGN
    signal(SIGHUP, SIG_IGN)
except ImportError:
    pass
try:
    # I'm guessing the builtin inet_pton will be faster, but if it's not
    # available we'll just have to use mine
    from socket import inet_pton
except ImportError:
    def inet_pton(af, addr):
        if af == AF_INET:
            try:
                return ''.join(map(lambda b: chr(int(b)), addr.split('.')))
            except ValueError:
                raise sockerr('illegal IP address string passed to inet_pton')
        elif af == AF_INET6:
            bits = addr.split('::')
            if len(bits) > 2:
                raise sockerr('illegal IP address string passed to inet_pton')
            try:
                if len(bits) == 2:
                    lead, trail = map(lambda s: filter(bool, s.split(':')),
                                      bits)
                    full = map(lambda s: int(s, 16), lead)
                    full += [0 for i in range(8 - len(lead) - len(trail))]
                    full += map(lambda s: int(s, 16), trail)
                else:
                    full = map(lambda s: int(s, 16), addr.split(':'))
            except ValueError:
                raise sockerr('illegal IP address string passed to inet_pton')
            return ''.join([chr(b >> 8) + chr(b & 0xff) for b in full])
        else:
            raise sockerr(97, 'Address family not supported by protocol')

config.parse()

inSocks, outSocks = {}, {}

pending = {}
servers = {}

class Server(object):
    NEW, CHALLENGED, CONFIRMED = range(3)
    def __init__(self, sock, addr):
        self.addr = addr
        self.sock = outSocks[sock.family]
        self.state = self.NEW
        self.lastactive = 0

    def __str__(self):
        return {
            AF_INET: '{0[0]}:{0[1]}',
            AF_INET6: '[{0[0]}]:{0[1]}'
        }[self.sock.family].format(self.addr)

    def timeout(self):
        if self.state == self.CONFIRMED:
            return (time() - self.lastactive > config.SERVER_TIMEOUT)
        return (time() - self.lastactive > config.CHALLENGE_TIMEOUT)

    def heartbeat(self, data):
        self.challenge = challenge()
        self.sock.sendto('\xff\xff\xff\xffgetinfo ' + self.challenge,
            self.addr)
        if self.state == self.NEW:
            self.challengetime = time()
            self.state = self.CHALLENGED
        log(LOG_VERBOSE, '>> {0[0]}:{0[1]}: getinfo'.format(self.addr))

    def respond(self, data):
        if data.startswith('infoResponse'):
            return self.infoResponse(data)

    def infoResponse(self, data):
        if (self.state == self.CHALLENGED and
                time() - self.challengetime > config.CHALLENGE_TIMEOUT):
            log(LOG_VERBOSE, 'Challenge response rejected: too late')
            return False
        infostring = data.split(None, 1)[1]
        info = Info(infostring)
        try:
            if info['challenge'] != self.challenge:
                return False
            self.protocol = info['protocol']
            self.empty = (info['clients'] == '0')
            self.full = (info['clients'] == info['sv_maxclients'])
        except KeyError, ex:
            log(LOG_VERBOSE, 'Server info key missing:', ex)
            return False
        self.state = self.CONFIRMED
        self.lastactive = time()
        log(LOG_DEBUG, 'Last active time updated for '
                       '{0[0]}:{0[1]}'.format(self.addr))
        return True

class Info(dict):
    def __init__(self, string = None, **kwargs):
        dict.__init__(self, **kwargs)
        if string:
            self.parse(string)

    def __str__(self):
        # Blame #python for this one :)
        return '\\'.join(i for it in ([['']], self.iteritems(), [['']])
                           for t in it
                           for i in t)

    def parse(self, string):
        string = string.strip('\\')
        while True:
            bits = string.split('\\', 2)
            try:
                self[bits[0]] = bits[1]
                string = bits[2]
            except IndexError:
                break

def prune_timeouts(servers):
    for addr in filter(lambda k: servers[k].timeout(), servers.keys()):
        server = servers[addr]
        log(LOG_VERBOSE, 'Server dropped due to {0}s inactivity: '
                         '{1[0]}:{1[1]}'.format(time() - server.lastactive,
                                                  server.addr))
        del servers[addr]

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

def heartbeat(sock, addr, data):
    s = Server(sock, addr)
    log(LOG_VERBOSE, '<<', str(s) + ':', repr(data))
    if (config.maxservers >= 0 and
            len(servers) + len(pending) >= config.maxservers):
        log(LOG_VERBOSE, 'Warning: max server count exceeded, '
                         'heartbeat from {0[0]}:{0[1]} ignored'.format(addr))
        return
    if addr in servers.keys():
        servers[addr].heartbeat(data)
        pending[addr] = servers[addr]
        return
    s = Server(sock, addr)
    s.heartbeat(data)
    pending[addr] = s

def getservers(sock, addr, data):
    tokens = data.split()
    ext = (tokens.pop(0) == 'getserversExt')
    if ext:
        tokens.pop(0) # 'Tremulous'
    protocol = tokens.pop(0)
    empty = 'empty' in tokens
    full = 'full' in tokens

    start = '\xff\xff\xff\xffgetservers{0}Response'.format(
               'Ext' if ext else '')
    response = start
    end = '\\EOT\0\0\0'
    assert config.GSR_MAXLENGTH > len(response) + len(end)

    log(LOG_VERBOSE, '<<', str(Server(sock, addr)) + ':', repr(data))

    for server in servers.values():
        af = server.sock.family
        if af == AF_INET6 and not ext:
            log(LOG_DEBUG, 'Dropping', server, 'IPv6 and not ext', sep = ': ')
            continue
        if server.protocol != protocol:
            log(LOG_DEBUG, 'Dropping {0}: wrong protocol ({1} != {2})'.format(
                            server, server.protocol, protocol))
            continue
        if server.empty and not empty:
            log(LOG_DEBUG, 'Dropping', server, 'empty', sep = ': ')
            continue
        if server.full and not full:
            log(LOG_DEBUG, 'Dropping', server, 'full', sep = ': ')
            continue
        sep = '/' if af == AF_INET6 else '\\'
        add = (sep + inet_pton(af, server.addr[0]) +
               chr(server.addr[1] >> 8) + chr(server.addr[1] & 0xff))
        if len(response) + len(add) + len(end) > config.GSR_MAXLENGTH:
            response += end
            log(LOG_DEBUG, '>> {0[0]}:{0[1]}:'.format(addr), repr(response))
            sock.sendto(response, addr)
            response = start
        else:
            response += add
    if response != start:
        assert not response.endswith(end)
        response += end
        log(LOG_DEBUG, '>> {0[0]}:{0[1]}:'.format(addr), repr(response))
        sock.sendto(response, addr)

def filterpacket(data, addr):
    if not data.startswith('\xff\xff\xff\xff'):
        return 'no header'
    if addr[0] in config.addr_blacklist:
        return 'blacklisted'

try:
    if not config.disable_ipv4 and config.bindaddr:
        log(LOG_PRINT, 'IPv4: Listening on', config.bindaddr,
                       'ports', config.inPort, 'and', config.outPort)
        inSocks[AF_INET] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        inSocks[AF_INET].bind((config.bindaddr, config.inPort))
        outSocks[AF_INET] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        outSocks[AF_INET].bind((config.bindaddr, config.outPort))

    if not config.disable_ipv6 and config.bind6addr and has_ipv6:
        log(LOG_PRINT, 'IPv6: Listening on', config.bind6addr,
                       'ports', config.inPort, 'and', config.outPort)
        inSocks[AF_INET6] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        inSocks[AF_INET6].bind((config.bind6addr, config.inPort))
        outSocks[AF_INET6] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        outSocks[AF_INET6].bind((config.bind6addr, config.outPort))

    if not inSocks and not outSocks:
        log(LOG_ERROR, 'Error: Not listening on any sockets, aborting')
        raise SystemExit(1)

except sockerr, (errno, strerror):
    log(LOG_ERROR, 'Couldn\'t initialise sockets:', strerror)
    raise

while True:
    try:
        (ready, _, _) = select(inSocks.values() + outSocks.values(), [], [])
    except selecterror, (errno, strerror):
        if errno == EINTR:
            continue
        raise
    prune_timeouts(servers)
    for sock in inSocks.values():
        if sock in ready:
            (data, addr) = sock.recvfrom(2048)
            addrstr = '<< {0[0]}:{0[1]}:'.format(addr)
            res = filterpacket(data, addr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:]
            responses = [
                ('heartbeat', heartbeat),
                ('getservers', getservers),
                ('getserversExt', getservers)
            ]
            for (name, func) in responses:
                if data.startswith(name):
                    func(sock, addr, data)
                    break
            else:
                log(LOG_VERBOSE, addrstr, 'unrecognised content:', repr(data))
    for sock in outSocks.values():
        if sock in ready:
            (data, addr) = sock.recvfrom(2048)
            addrstr = '<< {0[0]}:{0[1]}:'.format(addr)
            res = filterpacket(data, addr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:]
            if addr not in pending.keys():
                log(LOG_VERBOSE, addrstr, 'rejected (unsolicited)')
                continue
            if pending[addr].respond(data) and pending[addr] not in servers:
                servers[addr] = pending[addr]
                log(LOG_VERBOSE, addrstr, 'getinfoResponse confirmed')
            del pending[addr]
