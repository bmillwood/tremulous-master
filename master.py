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

# Required imports
from errno import EINTR
from random import choice
from select import select, error as selecterror
from socket import (socket, error as sockerr, has_ipv6,
                   AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
from time import time

# Local imports
import config
from config import log, LOG_ERROR, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG
# inet_pton isn't defined on windows, so use our own
from utils import inet_pton

# Optional imports
try:
    from signal import signal, SIGHUP, SIG_IGN
    signal(SIGHUP, SIG_IGN)
except ImportError:
    pass

config.parse()

# dict: socks[address_family].family == address_family
inSocks, outSocks = {}, {}

# dicts of [addr] -> Server instance
# pending - have sent a heartbeat, but not yet responded to challenge
# servers - have sent at least one valid challenge response
# it is possible for a server to be in both lists
pending = {}
servers = {}

class Server(object):
    '''Data structure for tracking server timeouts and challenges'''
    def __init__(self, sock, addr):
        '''The init method does no work, aside from setting variables: it is
        assumed the heartbeat method will be called pretty soon afterwards'''
        self.addr = addr
        self.sock = outSocks[sock.family]
        self.lastactive = 0
        self.timeout = 0

    def __str__(self):
        '''Returns a string representing the host and port of this server'''
        return {
            AF_INET: '{0[0]}:{0[1]}',
            AF_INET6: '[{0[0]}]:{0[1]}'
        }[self.sock.family].format(self.addr)

    def set_timeout(self, value):
        '''Sets the time after which the server will be regarded as inactive.
        Will never shorten a server's lifespan'''
        self.timeout = max(self.timeout, value)

    def timed_out(self):
        '''Returns True if the server has been idle for longer than the times
        specified in the config module'''
        return time() > self.timeout

    def heartbeat(self, data):
        '''Sends a getinfo challenge and records the current time'''
        self.challenge = challenge()
        self.sock.sendto('\xff\xff\xff\xffgetinfo ' + self.challenge,
            self.addr)
        self.set_timeout(time() + config.CHALLENGE_TIMEOUT)
        log(LOG_VERBOSE, '>> {0[0]}:{0[1]}: getinfo'.format(self.addr))

    def respond(self, data):
        '''Reads the data incoming and selects an appropriate response'''
        if data.startswith('infoResponse'):
            return self.infoResponse(data)

    def infoResponse(self, data):
        '''Returns True if the info given is as complete as necessary and
        the challenge returned matches the challenge sent'''
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
        self.lastactive = time()
        self.set_timeout(self.lastactive + config.SERVER_TIMEOUT)
        log(LOG_DEBUG, 'Last active time updated for '
                       '{0[0]}:{0[1]}'.format(self.addr))
        return True

class Info(dict):
    '''A dict with an overridden str() method for converting to \\key\\value\\
    syntax, and a new parse() method for converting therefrom.'''
    def __init__(self, string = None, **kwargs):
        '''If any keyword arguments are given, add them; if a string is given,
        parse it.'''
        dict.__init__(self, **kwargs)
        if string:
            self.parse(string)

    def __str__(self):
        '''Converts self[key1] == value1, self[key2] == value2[, ...] to
        \\key1\\value1\\key2\\value2\\...'''
        # Blame #python for this one :)
        # the [['']]s inexpensively tell join() to put \\ at the start and end
        return '\\'.join(i for it in ([['']], self.iteritems(), [['']])
                           for t in it
                           for i in t)

    def parse(self, string):
        '''Converts \\key1\\value1\\key2\\value2\\... to self[key1] = value1,
        self[key2] = value2[, ...].
        Note that previous entries in self are not deleted!'''
        string = string.strip('\\')
        while True:
            bits = string.split('\\', 2)
            try:
                self[bits[0]] = bits[1]
                string = bits[2]
            except IndexError:
                break

def prune_timeouts(servers):
    '''Removes from the active server list any items whose timeout method
    returns true'''
    # list()ing this should prevent RuntimeError: dictionary changed size
    # during iteration
    for (addr, server) in list(servers.iteritems()):
        if server.timed_out():
            del servers[addr]
            log(LOG_VERBOSE, 'Server dropped due to {0}s inactivity: '
                             '{1[0]}:{1[1]}'.format(time() - server.lastactive,
                                                    server.addr))

def challenge():
    '''Returns a string of config.CHALLENGE_LENGTH characters, chosen from
    those greater than ' ' and less than or equal to '~' (i.e. isgraph)
    Semicolons, backslashes and quotes are precluded because the server won't
    put them in an infostring; forward slashes are not allowed because the
    server's parsing tools can recognise them as comments
    Percent symbols: these used to be disallowed, but subsequent to Tremulous
    SVN r1148 they should be okay. Any server older than that will translate
    them into '.' and therefore fail to match.'''
    valid = [c for c in map(chr, range(0x21, 0x7f)) if c not in '\\;\"/']
    return ''.join([choice(valid) for _ in range(config.CHALLENGE_LENGTH)])

def heartbeat(sock, addr, data):
    '''In response to an incoming heartbeat: call its heartbeat method, and
    add it to the pending challenge response list'''
    if (config.maxservers >= 0 and
            len(servers) + len(pending) >= config.maxservers):
        log(LOG_VERBOSE, 'Warning: max server count exceeded, '
                         'heartbeat from {0[0]}:{0[1]} ignored'.format(addr))
        return
    # fetch or create a server record
    s = servers[addr] if addr in servers.keys() else Server(sock, addr)
    log(LOG_VERBOSE, '<< ' + str(s), repr(data), sep = ':')
    s.heartbeat(data)
    pending[addr] = s

def getservers(sock, addr, data):
    tokens = data.split()
    ext = (tokens.pop(0) == 'getserversExt')
    if ext:
        if tokens.pop(0) != 'Tremulous':
            pass # this parameter doesn't seem to affect much?
    protocol = tokens.pop(0)
    empty, full = 'empty' in tokens, 'full' in tokens

    start = '\xff\xff\xff\xffgetservers{0}Response'.format(
                                      'Ext' if ext else '')
    response = start

    log(LOG_VERBOSE, '<<', str(Server(sock, addr)) + ':', repr(data))

    count = 0
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
        if count >= config.GSR_MAXSERVERS:
            response += '\\'
            log(LOG_DEBUG, '>> {0[0]}:{0[1]}:'.format(addr), repr(response))
            sock.sendto(response, addr)
            response = start
        else:
            response += add
            count += 1
    if response != start:
        assert not response.endswith(end)
        response += end
        log(LOG_DEBUG, '>> {0[0]}:{0[1]}:'.format(addr), repr(response))
        sock.sendto(response, addr)

def filterpacket(data, addr):
    '''Called on every incoming packet, checks if it should immediately be
    dropped, returning the reason as a string'''
    if not data.startswith('\xff\xff\xff\xff'):
        return 'no header'
    if addr[0] in config.addr_blacklist:
        return 'blacklisted'

try:
    # FIXME: this will probably give an error if inPort == outPort
    # this is possibly correct behaviour but should at least be caught
    # explicitly if so
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
        # select can be interrupted by a signal: if it wasn't a fatal signal,
        # we don't care
        if errno == EINTR:
            continue
        raise
    prune_timeouts(servers)
    for sock in inSocks.values():
        if sock in ready:
            # FIXME: 2048 magic number
            (data, addr) = sock.recvfrom(2048)
            # for logging
            addrstr = '<< {0[0]}:{0[1]}:'.format(addr)
            res = filterpacket(data, addr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:] # skip header
            responses = [
                # this looks like it should be a dict but since we use
                # startswith it wouldn't really improve matters
                ('heartbeat', heartbeat),
                ('getservers', getservers),
                ('getserversExt', getservers)
                # infoResponses will arrive on an outSock
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
            # for logging
            addrstr = '<< {0[0]}:{0[1]}:'.format(addr)
            res = filterpacket(data, addr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:] # skip header
            # the outSocks are for getinfo challenges, so any response should
            # be from a server already known to us
            if addr not in pending.keys():
                log(LOG_VERBOSE, addrstr, 'rejected (unsolicited)')
                continue
            # the respond method will do most of the work here: we just have to
            # add the server to the server list
            if pending[addr].respond(data) and pending[addr] not in servers:
                servers[addr] = pending[addr]
                log(LOG_VERBOSE, addrstr, 'getinfoResponse confirmed')
            del pending[addr]
