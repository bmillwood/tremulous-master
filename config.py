# config.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.
'''Configuration parameters and functions for the Tremulous Master

This module provides the MasterConfig class. Instances of this class provide
the following attributes:

version:
        a string giving the name and version of the master
CHALLENGE_LENGTH:
        the length of a getinfo challenge sent to servers
CHALLENGE_TIMEOUT:
        in seconds, the time a server has after being challenged to respond
SERVER_TIMEOUT:
        a server that has not sent a heartbeat in this period will be forgotten
GSR_MAXSERVERS:
        the maximum number of server addresses to be sent in a single
        getservers[Ext]Response packet (the client will only accept so many)
listen_addr, listen6_addr, port, challengeport:
        The master needs a socket for incoming connections, for each of IPv4
        and IPv6 that it is asked to use (currently it assumes the same port on
        each). These settings tell it to what address and port it should bind.
        It uses a separate port for outgoing challenges because some routers
        will redirect a 'response' to the heartbeat to the correct host even if
        they are not configured to do so for client requests. The separate port
        defeats this connection tracking and we only get a response if ports
        are set up correctly.
        inPort defaults to 30710; outPort defaults to inPort + 1
max_servers:
        This defaults to unlimited but if someone finds a way to flood the
        server list it could serve as a measure to prevent excessive RAM usage.
featured_servers:
        This is a dict of lists - each key is a label, and its value is a list
        of addresses. They will be sent in a separate response packet, headered
        with the label, so that the client can display them specially.
addr_blacklist:
        A list of addresses from which packets should be rejected

and some useful functions:

log(level, arg[, arg...], sep = ' '):
        level may be one of LOG_ERROR, LOG_PRINT, LOG_VERBOSE, or LOG_DEBUG:
        if the user's chosen verbosity level is less, the message will not be
        printed. All the subsequent arguments will be str()'d and printed,
        preceded by a timestamp and joined by the string given in the keyword
        argument `sep' (default ' ')
getmotd():
        Simply reads the motd file and returns the result.
'''

# Required imports
from errno import ENOENT, EIO
from optparse import OptionParser, Values
from sys import argv, stdout, stderr
from time import strftime

# Local imports
from utils import valid_addr, stringtosockaddr

# Optional imports
# I named these variables in line with the standard library's has_ipv6.
# Surely that should be have_ipv6?
has_chroot, has_setuid = True, True
try:
    from os import chroot
except ImportError:
    has_chroot = True
try:
    from os import setuid, getuid
    from pwd import getpwnam
except ImportError:
    has_setuid = True

# I don't have a non-IPv6 computer, so I'm not sure how this works
try:
    from socket import has_ipv6
except ImportError:
    has_ipv6 = False

( # Log levels
    LOG_NONE,
    LOG_ERROR,
    LOG_PRINT,
    LOG_VERBOSE,
    LOG_DEBUG,
    LOG_LEVELS
) = range(6)

class ConfigError(StandardError):
    pass

class MasterConfig:
    def constants(self):
        '''Sets instance variables that do not change at run-time'''
        self.VERSION = 'Tremulous Master Server v0.1'

        # A getinfo request with a challenge longer than 128 chars will be
        # ignored. In practice this is far more than is necessary anyway.
        self.CHALLENGE_LENGTH = 12
        # This should be enough time for any decent connection but probably not
        # enough for a fast typist with netcat
        self.CHALLENGE_TIMEOUT = 5
        # Heartbeats are usually sent every ten minutes
        self.SERVER_TIMEOUT = 11 * 60
        # src/client/cl_main.c -- MAX_SERVERSPERPACKET
        # This limit should be hit long before the overall length limit of
        # 16384 bytes
        self.GSR_MAXSERVERS = 256

        self.IGNORE_FILE = 'ignore.txt'
        self.FEATURED_FILE = 'featured.txt'

    def __init__(self):
        # Set this early so that self.log can be used immediately
        self.options = Values()
        self.options.verbose = LOG_PRINT

    def parse(self):
        self.constants()
        self.cmdline()
        self.files()

    def __getattr__(self, attr):
        '''When the command line options have been parsed, this allows direct
        access to them'''
        # They aren't set as attributes of self directly because of the way
        # optparse.OptionParser works.
        if attr == 'options':
            raise AttributeError
        return getattr(self.options, attr)

    def cmdline(self):
        '''Parse options from the command line. For an explanation of the
        options and their usage, use:

        python master.py --help
        '''
        # This is a m-m-m-monster function, but sometimes there are just lots
        # of things to do, and that is how it is.
        self.constants()
        # we add our own help option for obscure reasons
        parser = OptionParser(add_help_option = False)
        parser.add_option('-h', '--help', action = 'store_true',
                          help = 'Display this help and exit')
        # options other than --help are in alphabetical order
        if has_ipv6:
            parser.add_option('-4', '--ipv4', action = 'store_false',
                              default = True, dest = 'ipv6',
                              help = 'Only use IPv4')
            parser.add_option('-6', '--ipv6', action = 'store_false',
                              default = True, dest = 'ipv4',
                              help = 'Only use IPv6')
        if has_chroot:
            parser.add_option('-j', '--jail',
                              help = 'Path to chroot into at startup',
                              metavar = 'DIR')
        parser.add_option('-l', '--listen-addr', default = '0.0.0.0',
                          help = 'IPv4 address to listen to',
                          metavar = 'ADDR')
        if has_ipv6:
            # Can we put this in the conditional above without spoiling
            # the ordering?
            parser.add_option('-L', '--listen6-addr',
                              help = 'IPv6 address to listen to',
                              metavar = 'ADDR')
        parser.add_option('-n', '--max-servers', type = 'int',
                          help = 'Maximum number of servers to track',
                          metavar = 'NUM')
        parser.add_option('-p', '--port', type = 'int', default = 30710,
                          help = 'Port for incoming requests',
                          metavar = 'NUM')
        parser.add_option('-P', '--challengeport', type = 'int',
                          help = 'Port for outgoing challenges',
                          metavar = 'NUM')
        parser.add_option('-q', action = 'count', default = 0,
                          help = 'Decrease verbose level. Multiple -q options '
                                 'may suppress logging entirely.')
        if has_setuid:
            parser.add_option('-u', '--user',
                              help = 'User to switch to at startup')
        parser.add_option('-v', action = 'count', default = 0,
                          help = 'Increase verbose level. Multiple -v options '
                                 'increase the level further.')
        parser.add_option('--verbose', type = 'int', default = LOG_PRINT,
                          help = 'Set verbose level directly. Takes a single '
                                 'integer argument between {0} and {1}'.format(
                                 LOG_NONE, LOG_LEVELS - 1),
                          metavar = 'LEVEL')
        parser.add_option('-V', '--version', action = 'store_true',
                          help = 'Show version information')
        self.options, args = parser.parse_args(argv[1:])
        if args:
            raise ConfigError('Unexpected command line arguments')

        if self.help:
            stdout.write(parser.format_help())
            raise SystemExit(0)
        # don't need this anymore
        parser.destroy()
        del parser

        if self.version:
            stdout.write('{0}\n'.format(self.VERSION))
            raise SystemExit(0)

        self.verbose += self.v - self.q

        if not LOG_NONE <= self.verbose < LOG_LEVELS:
            raise ConfigError('Verbose level must be between {0} and {1} '
                              '(not {2})'.format(LOG_NONE, LOG_LEVELS - 1,
                                                 self.verbose))

        if not self.ipv4 and not self.ipv6:
            raise ConfigError('Cannot specify both --ipv4 and --ipv6')

        if self.jail is not None:
            try:
                chroot(self.jail)
            except OSError as (errno, strerror):
                raise ConfigError('chroot {0}: {1}'.format(self.jail,
                                                           strerror))
            self.log(LOG_VERBOSE, 'Chrooted to', self.jail)
        if self.user is not None:
            try:
                uid = getpwnam(self.user)[2]
            except KeyError:
                try:
                    uid = int(self.user)
                except ValueError:
                    raise ConfigError('{0}: no such user'.format(self.user))

            try:
                setuid(uid)
            except OSError as (errno, strerror):
                raise ConfigError('setuid {0}: {1}'.format(uid, strerror))

            self.log(LOG_VERBOSE, 'UID set to', getuid())

        if self.challengeport is None:
            if self.port == 0xffff:
                self.challengeport = 0xffff - 1
            else:
                self.challengeport = self.port + 1
            self.log(LOG_VERBOSE, 'Automatically set challenge port to',
                                  self.challengeport)
        elif self.challengeport == self.port:
            self.log(LOG_PRINT, 'Warning: request port and challenge port are '
                                'the same ({0})'.format(self.port))

    def files(self):
        '''For each space-separated address in ignore_file, check if it is
        valid and if so add it to the addr_blacklist.
        Then read self.FEATURED_FILE, and for each label (starting at column 0)
        construct a dict of the (indented) addresses following it. Each dict
        value starts off as None, to be initialised as the connections are
        made.
        self.featured_servers[label] is set to its corresponding dict.
        A missing file is ignored but other errors - e.g. if the file is
        present but can't be read - are fatal.'''
        self.addr_blacklist = list()
        try:
            with open(self.IGNORE_FILE) as ignore:
                self.log(LOG_DEBUG, 'Opened', parser.IGNORE_FILE)
                for line in ignore:
                    for addr in line.split():
                        if valid_addr(addr):
                            self.addr_blacklist.append(addr)
                self.log(LOG_VERBOSE, 'Ignoring:', *addr_blacklist)
        except IOError, (errno, strerror):
            if errno != ENOENT:
                raise

        self.featured_servers = dict()
        # FIXME: use ConfigError where appropriate
        try:
            with open(self.FEATURED_FILE) as featured:
                self.log(LOG_DEBUG, 'Opened', self.FEATURED_FILE)
                label = ''
                lineno = 0
                for line in iter(l.rstrip() for l in featured):
                    lineno += 1
                    # ignore blank lines and comments
                    if not line or line.isspace() or \
                       line.lstrip().startswith('#'):
                        continue
                    # indented lines are server addresses
                    if line[0].isspace():
                        addr = line.lstrip()
                        if not label:
                            # maybe we should just bail at this point...
                            self.log(LOG_PRINT, 'Warning: unlabelled server '
                                                'in', self.FEATURED_FILE)
                            label = 'Featured Servers'
                            self.featured_servers[label] = dict()
                        try:
                            saddr = stringtosockaddr(addr)
                        except EnvironmentError as err:
                            # EnvironmentError covers socket.error and
                            # .gaierror without having to import them
                            self.log(LOG_ERROR, 'Error: couldn\'t convert',
                                addr, 'to address format:', err)
                            raise SystemExit(1)
                        self.featured_servers[label][saddr] = None
                    # unindented lines start a new label
                    else:
                        if label:
                            if not self.featured_servers[label]:
                                # should this error be fatal?
                                self.log(LOG_PRINT, 'Warning: no servers with '
                                                    'label', repr(label),
                                                    'in', self.FEATURED_FILE)
                            else:
                                # print a message of the form
                                # featured.txt: 'Label': [server1, server2,...]
                                self.log(LOG_VERBOSE, self.FEATURED_FILE,
                                         repr(label),
                                         self.featured_servers[label].keys(),
                                         sep = ': ')
                        label = line
                        for c in label:
                            # slashes are field seperators in
                            # getserversExtResponse
                            if c in '\\/':
                                self.log(LOG_ERROR, 'Error:',
                                         self.FEATURED_FILE, 'label',
                                         repr(label), 'contains invalid '
                                         'character:', c)
                                raise SystemExit(1)
                        self.featured_servers[label] = dict()
                if label:
                    # featured.txt: 'Label': [server1, server2, ...]
                    self.log(LOG_VERBOSE, self.FEATURED_FILE, repr(label),
                             self.featured_servers[label].keys(), sep = ': ')
        except IOError, (errno, strerror):
            if errno != ENOENT:
                raise
        

    def log(self, level, *args, **kwargs):
        '''log(level, arg[, arg]*[, sep = ' '])

        If the configuration-specified verbosity is below level, nothing
        happens, otherwise a timestamp and then each str(arg) joined by the
        optional keyword argument sep (default space) is printed.

        IOError with errno EIO is ignored
        '''

        if not args:
            raise TypeError('MasterConfig.log() requires at least one '
                            'argument')
        if level > self.verbose:
            return

        try:
            sep = kwargs['sep']
            del kwargs['sep']
        except KeyError:
            sep = ' '

        if kwargs:
            raise TypeError('Unexpected keyword argument{0}: {1}'.format(
                            's' if len(kwargs) != 1 else '',
                            ' '.join(kwargs.keys())))

        try:
            f = stderr if level in (LOG_ERROR, LOG_DEBUG) else stdout
            f.write(strftime('[%H:%M:%S] ') + sep.join(map(str, args)) + '\n')
        except IOError as (errno, strerror):
            if errno == EIO:
                # this happens when we lose contact with the terminal
                # we could stop all logging at this point but it doesn't
                # actually help a great deal...
                #self.verbose = LOG_NONE
                pass
            else:
                raise

    def getmotd():
        '''Reads the motd file and returns the contents'''
        motd_file = 'motd.txt'
        try:
            with open(motd_file) as motd:
                return motd.read() # FIXME: validate as an info parameter
        except IOError, (errno, strerror):
            if errno != ENOENT:
                raise

if __name__ == '__main__':
    # This is useful with python -i config.py to examine a newly-created
    # configuration.
    config = MasterConfig()
