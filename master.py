#!/usr/bin/env python
###############################################################################
# master.py - a master server for Tremulous
# Copyright (c) 2009 Ben Millwood
#
# Thanks to Mathieu Olivier, who wrote much of the original master in C
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
""" # docstring TODO

# Required imports
from errno import EINTR
from itertools import chain
from random import choice
from select import select, error as selecterror
from socket import (socket, error as sockerr, has_ipv6,
                   AF_UNSPEC, AF_INET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
from sys import exit
from time import time

# Local imports
from config import config, ConfigError
from config import log, LOG_ERROR, LOG_PRINT, LOG_VERBOSE, LOG_DEBUG
# inet_pton isn't defined on windows, so use our own
from utils import inet_pton

try:
    config.parse()
except ConfigError as err:
    # Note that we don't know how much user config is loaded at this stage
    log(LOG_ERROR, err)
    exit(1)

# Optional imports
try:
    from signal import signal, SIGHUP, SIG_IGN
    signal(SIGHUP, SIG_IGN)
except ImportError:
    pass

if not config.no_db:
    try:
        from db import log_client, log_gamestat
    except ImportError:
        def nodb(*args):
            '''This function is defined and used when the db import is not
            available, to print a debug-level warning message'''
            log(LOG_DEBUG, 'No database available, not logged:', args)
        log_client = log_gamestat = nodb
        log(LOG_PRINT, 'Warning: no database available')
else:
    def disabled_db(*args):
        '''This function is defined and used when the database is disabled by
        configuration options'''
    log_client = log_gamestat = disabled_db

# dict: socks[address_family].family == address_family
inSocks, outSocks = dict(), dict()

# dict of [label][addr] -> Server instance
servers = dict((label, dict()) for label in
               chain(config.featured_servers.keys(), [None]))

class Addr(tuple):
    '''Data structure for storing socket addresses, that provides a parse
    method and a nice string representation'''
    def __new__(cls, addr = None, family = None):
        '''This is necessary because tuple is an immutable data type, so
        inheritance rules are a bit funny.'''
        # I have some idea I should be using super() here
        return tuple.__new__(cls, addr)

    def __init__(self, addr = None, family = None):
        '''Adds the host, port and family attributes to the addr tuple.
        If no arguments are given, does nothing (assumes you're going to call
        parse() or similar)'''
        if addr is not None:
            if family is None:
                raise TypeError('Must give Addr either zero arguments or two')
            self.host, self.port = addr[:2]
            self.family = family
        else:
            if family is not None:
                raise TypeError('Must give Addr either zero arguments or two')

    def parse(self, string):
        '''Initialise and return self with the given string'''
        af = valid_addr(string)
        self.__init__(stringtosockaddr(string, af), af)
        return self

    def __str__(self):
        '''If self.family is AF_INET or AF_INET6, this provides a standard
        representation of the host and port. Otherwise it falls back to the
        standard tuple.__str__ method.'''
        try:
            return {
                AF_INET: '{0[0]}:{0[1]}',
                AF_INET6: '[{0[0]}]:{0[1]}'
            }[self.family].format(self)
        except (AttributeError, IndexError, KeyError):
            return tuple.__str__(self)

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
        return '\\{0}\\'.format('\\'.join(i for t in self.iteritems()
                                            for i in t))

    def parse(self, input):
        '''Converts \\key1\\value1\\key2\\value2\\... to self[key1] = value1,
        self[key2] = value2[, ...].
        Note that previous entries in self are not deleted!'''
        input = input.strip('\\')
        while True:
            bits = input.split('\\', 2)
            try:
                self[bits[0]] = bits[1]
                input = bits[2]
            except IndexError:
                break

class Server(object):
    '''Data structure for tracking server timeouts and challenges'''
    def __init__(self, addr):
        '''The init method does no work, aside from setting variables: it is
        assumed the heartbeat method will be called pretty soon afterwards'''
        self.addr = addr
        self.sock = outSocks[addr.family]
        self.lastactive = 0
        self.timeout = 0

    def __nonzero__(self):
        '''Server has replied to a challenge'''
        return bool(self.lastactive)

    def __str__(self):
        '''Returns a string representing the host and port of this server'''
        return str(self.addr)

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
        packet = '\xff\xff\xff\xffgetinfo ' + self.challenge
        log(LOG_DEBUG, '>> {0}: {1!r}'.format(self, packet))
        self.sock.sendto(packet, self.addr)
        self.set_timeout(time() + config.CHALLENGE_TIMEOUT)

    def infoResponse(self, data):
        '''Returns True if the info given is as complete as necessary and
        the challenge returned matches the challenge sent'''
        addrstr = '<< {0}'.format(self)
        if not data.startswith('infoResponse'):
            log(LOG_VERBOSE, addrstr, 'unexpected packet on challenge socket, '
                                      'ignored')
            return False
        addrstr += ': infoResponse:'
        # find the beginning of the infostring
        for i, c in enumerate(data):
            if c in ' \\\n':
                break
        infostring = data[i + 1:]
        if not infostring:
            log(LOG_VERBOSE, addrstr, 'no infostring found')
            return False
        info = Info(infostring)
        try:
            if info['challenge'] != self.challenge:
                log(LOG_VERBOSE, addrstr, 'mismatched challenge: '
                    '{0!r} != {1!r}'.format(info['challenge'], self.challenge))
                return False
            self.protocol = info['protocol']
            self.empty = (info['clients'] == '0')
            self.full = (info['clients'] == info['sv_maxclients'])
        except KeyError as ex:
            log(LOG_VERBOSE, addrstr, 'info key missing:', ex)
            return False
        if self.lastactive:
            log(LOG_VERBOSE, addrstr, 'verified')
        else:
            log(LOG_VERBOSE, addrstr, 'verified, added to list '
                                      '({0})'.format(count_servers()))
        self.lastactive = time()
        self.set_timeout(self.lastactive + config.SERVER_TIMEOUT)
        return True

def find_featured(addr):
    # docstring TODO
    # just in case it's an Addr
    for (label, addrs) in config.featured_servers.iteritems():
        if addr in addrs.keys():
            return label

def prune_timeouts(slist = servers[None]):
    '''Removes from the list any items whose timeout method returns true'''
    # iteritems gives RuntimeError: dictionary changed size during iteration
    for (addr, server) in slist.items():
        if server.timed_out():
            del slist[addr]
            remstr = str(count_servers())
            if server.lastactive:
                log(LOG_VERBOSE, '{0} dropped due to {1}s inactivity '
                    '({2})'.format(server, time() - server.lastactive, remstr))
            else:
                log(LOG_VERBOSE, '{0} dropped: no response '
                    '({1})'.format(server, remstr))

def challenge():
    '''Returns a string of config.CHALLENGE_LENGTH characters, chosen from
    those greater than ' ' and less than or equal to '~' (i.e. isgraph)
    Semicolons, backslashes and quotes are precluded because the server won't
    put them in an infostring; forward slashes are not allowed because the
    server's parsing tools can recognise them as comments
    Percent symbols: these used to be disallowed, but subsequent to Tremulous
    SVN r1148 they should be okay. Any server older than that will translate
    them into '.' and therefore fail to match.
    For compatibility testing purposes, I've temporarily disallowed them again.
    '''
    valid = [c for c in map(chr, range(0x21, 0x7f)) if c not in '\\;%\"/']
    return ''.join([choice(valid) for _ in range(config.CHALLENGE_LENGTH)])

def count_servers(slist = servers):
    # docstring TODO
    return sum(map(len, servers.values()))

def gamestat(sock, addr, data):
    '''Delegates to log_gamestat, cutting the first token (that it asserts is
    'gamestat') from the data'''
    assert data.startswith('gamestat')
    log_gamestat(addr, data[len('gamestat'):].lstrip())

def getmotd(sock, addr, data):
    '''A client getmotd request: log the client information and then send the
    response'''
    addrstr = '<< {0}'.format(addr)
    try:
        _, infostr = data.split('\\', 1)
    except ValueError:
        infostr = ''
    info = Info(infostr)
    rinfo = Info()
    log_client(addr, info)

    try:
        rinfo['challenge'] = info['challenge']
    except KeyError:
        log(LOG_VERBOSE, addrstr, 'Challenge missing or invalid', sep = ': ')
    rinfo['motd'] = config.getmotd()
    if not rinfo['motd']:
        return

    response = '\xff\xff\xff\xffmotd {0}'.format(rinfo)
    log(LOG_DEBUG, '>> {0}: {1!r}'.format(addr, response))
    sock.sendto(response, addr)

def filterservers(slist, af, protocol, empty, full):
    '''Return those servers in slist that test true (have been verified) and:
    - whose protocol matches `protocol'
    - if `ext' is not set, are IPv4
    - if `empty' is not set, are not empty
    - if `full' is not set, are not full'''
    return [s for s in slist if s
            and af in (AF_UNSPEC, s.addr.family)
            and not s.timed_out()
            and s.protocol == protocol
            and (empty or not s.empty)
            and (full  or not s.full)]

def gsr_formataddr(addr):
    sep  = '\\' if addr.family == AF_INET else '/'
    host = inet_pton(addr.family, addr.host)
    port = chr(addr.port >> 8) + chr(addr.port & 0xff)
    return sep + host + port

def getservers(sock, addr, data):
    '''On a getservers or getserversExt, construct and send a response'''

    tokens = data.split()
    ext = (tokens.pop(0) == 'getserversExt')
    if ext:
        if tokens.pop(0) != 'Tremulous':
            log(LOG_VERBOSE, '<< {0}: ext but not Tremulous, '
                             'ignored'.format(addr))
            return
    protocol = tokens.pop(0)
    empty, full = 'empty' in tokens, 'full' in tokens
    if ext:
        family = (AF_INET  if 'ipv4' in tokens
             else AF_INET6 if 'ipv6' in tokens
             else AF_UNSPEC)
    else:
        family = AF_INET

    max = config.GSR_MAXSERVERS
    packets = {None: list()}
    for label in servers.keys():
        # dict of lists of lists
        if ext:
            packets[label] = list()
            filtered = filterservers(servers[label].values(),
                                     family, protocol, empty, full)
            while len(filtered) > 0:
                packets[label].append(filtered[:config.GSR_MAXSERVERS])
                filtered = filtered[config.GSR_MAXSERVERS:]
        else:
            filtered = filterservers(servers[label].values(),
                                     family, protocol, empty, full)
            if not packets[None]:
                packets[None].append(filtered[:config.GSR_MAXSERVERS])
                filtered = filtered[config.GSR_MAXSERVERS:]
            while len(filtered) > 0:
                space = config.GSR_MAXSERVERS - len(packets[None][-1])
                if space:
                    packets[None][-1].extend(filtered[:space])
                    filtered = filtered[space:]
                else:
                    packets[None].append(filtered[:config.GSR_MAXSERVERS])
                    filtered = filtered[config.GSR_MAXSERVERS:]

    start = '\xff\xff\xff\xffgetservers{0}Response'.format(
                                      'Ext' if ext else '')

    index = 1
    numpackets = sum(len(ps) for ps in packets.values())
    if numpackets == 0:
        # send an empty packet
        numpackets = 1
        packets[None] = [[]]
    for label, packs in packets.items():
        if label is None:
            label = ''
        for packet in packs:
            message = start
            if ext:
                message += '\0{0}\0{1}\0{2}'.format(index, numpackets, label)
            message += ''.join(gsr_formataddr(s.addr) for s in packet)
            log(LOG_DEBUG, '>> {0}: {1!r}'.format(addr, message))
            sock.sendto(message, addr)
            index += 1
    npstr = '1 packet' if numpackets == 1 else '{0} packets'.format(numpackets)
    log(LOG_VERBOSE, '>> {0}: getservers{1}Response: sent '
                     '{2}'.format(addr, 'Ext' if ext else '', npstr))

def heartbeat(sock, addr, data):
    '''In response to an incoming heartbeat: call its heartbeat method, and
    add it to the list'''
    if config.max_servers >= 0 and count_servers() >= config.max_servers:
        log(LOG_PRINT, 'Warning: max server count exceeded, '
                       'heartbeat from', addr, 'ignored')
        return
    # fetch or create a server record
    label = find_featured(addr)
    s = servers[label][addr] if addr in servers[label].keys() else Server(addr)
    s.heartbeat(data)
    servers[label][addr] = s

def filterpacket(data, addr):
    '''Called on every incoming packet, checks if it should immediately be
    dropped, returning the reason as a string'''
    if not data.startswith('\xff\xff\xff\xff'):
        return 'no header'
    if config.ignore(addr.host):
        return 'blacklisted'

try:
    if config.ipv4 and config.listen_addr:
        log(LOG_PRINT, 'IPv4: Listening on', config.listen_addr,
                       'ports', config.port, 'and', config.challengeport)
        inSocks[AF_INET] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        inSocks[AF_INET].bind((config.listen_addr, config.port))
        outSocks[AF_INET] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        outSocks[AF_INET].bind((config.listen_addr, config.challengeport))

    if config.ipv6 and config.listen6_addr:
        log(LOG_PRINT, 'IPv6: Listening on', config.listen6_addr,
                       'ports', config.port, 'and', config.challengeport)
        inSocks[AF_INET6] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        inSocks[AF_INET6].bind((config.listen6_addr, config.port))
        outSocks[AF_INET6] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        outSocks[AF_INET6].bind((config.listen6_addr, config.challengeport))

    if not inSocks and not outSocks:
        log(LOG_ERROR, 'Error: Not listening on any sockets, aborting')
        exit(1)

except sockerr as err:
    log(LOG_ERROR, 'Couldn\'t initialise sockets:', err.strerror)
    raise exit(1)

while True:
    try:
        ret = select(chain(inSocks.values(), outSocks.values()), [], [])
        ready = ret[0]
    except selecterror as err:
        # select can be interrupted by a signal: if it wasn't a fatal signal,
        # we don't care
        if err.errno == EINTR:
            continue
        raise
    except KeyboardInterrupt:
        exit('Interrupted')
    prune_timeouts()
    for sock in inSocks.values():
        if sock in ready:
            # FIXME: 2048 magic number
            (data, addr) = sock.recvfrom(2048)
            saddr = Addr(addr, sock.family)
            # for logging
            addrstr = '<< {0}:'.format(saddr)
            log(LOG_DEBUG, addrstr, repr(data))
            res = filterpacket(data, saddr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:] # skip header
            responses = [
                # this looks like it should be a dict but since we use
                # startswith it wouldn't really improve matters
                ('gamestat', gamestat),
                ('getmotd', getmotd),
                ('getservers', getservers),
                ('getserversExt', getservers),
                ('heartbeat', heartbeat),
                # infoResponses will arrive on an outSock
            ]
            for (name, func) in responses:
                if data.startswith(name):
                    func(sock, saddr, data)
                    break
            else:
                log(LOG_VERBOSE, addrstr, 'unrecognised content:', repr(data))
    for sock in outSocks.values():
        if sock in ready:
            (data, addr) = sock.recvfrom(2048)
            saddr = Addr(addr, sock.family)
            # for logging
            addrstr = '<< {0}:'.format(saddr)
            log(LOG_DEBUG, addrstr, repr(data))
            res = filterpacket(data, saddr)
            if res:
                log(LOG_VERBOSE, addrstr, 'rejected ({0})'.format(res))
                continue
            data = data[4:] # skip header
            # the outSocks are for getinfo challenges, so any response should
            # be from a server already known to us
            label = find_featured(addr)
            if label is None and addr not in servers[None].keys():
                log(LOG_VERBOSE, addrstr, 'rejected (unsolicited)')
                continue
            # this has got to be an infoResponse, right?
            servers[label][addr].infoResponse(data)
