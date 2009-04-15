# config.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.
'''Configuration parameters and functions for the Tremulous Master

At import, this module defines the following parameters:

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

and some useful functions:

log(level, arg[, arg...], sep = ' '):
        level may be one of LOG_ERROR, LOG_PRINT, LOG_VERBOSE, or LOG_DEBUG:
        if the user's chosen verbosity level is less, the message will not be
        printed. All the subsequent arguments will be str()'d and printed,
        preceded by a timestamp and joined by the string given in the keyword
        argument `sep' (default ' ')

After its parse() function is called, it uses the command line options and some
configuration files to set the following module variables:

bindaddr, bind6addr, inPort, outPort:
        The master needs a socket for incoming connections, for each of IPv4
        and IPv6 that it is asked to use (currently it assumes the same port on
        each). These settings tell it to what address and port it should bind.
        It uses a separate port for outgoing challenges because some routers
        will redirect a 'response' to the heartbeat to the correct host even if
        they are not configured to do so for client requests. The separate port
        defeats this connection tracking and we only get a response if ports
        are set up correctly.
        inPort defaults to 30710; outPort defaults to inPort + 1
maxservers:
        This defaults to unlimited but if someone finds a way to flood the
        server list it could serve as a measure to prevent excessive RAM usage.
addr_blacklist:
        A list of addresses from which packets should be rejected, read from
        ignore.txt, one per line.
'''

# Constants
version = 'Tremulous Master Server v0.1'

# A getinfo request with a challenge longer than 128 chars will be ignored.
# In practice this is far more than is necessary anyway.
CHALLENGE_LENGTH = 12
# This should be enough time for any decent connection but probably not enough
# for a fast typist with netcat
CHALLENGE_TIMEOUT = 5
# Heartbeats are usually sent every ten minutes
SERVER_TIMEOUT = 11 * 60
# src/client/cl_main.c -- MAX_SERVERSPERPACKET
# This limit should be hit long before the overall length limit of 16384 bytes
GSR_MAXSERVERS = 256

# Required imports
from errno import ENOENT, EIO
from getopt import getopt, GetoptError
from sys import argv, stdout, stderr
from time import strftime

# Local imports
from utils import inet_pton

# Optional imports
no_chroot, no_setuid = True, True
try:
    from os import chroot
    no_chroot = False
except ImportError, ex:
    pass
try:
    from os import setuid, getuid
    from pwd import getpwnam
    no_setuid = False
except ImportError, ex:
    pass

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

loglevel = LOG_DEBUG

def log(level, *args, **kwargs):
    '''log(level, arg[, arg]*[, sep = ' ']) - if the configuration-specified
    loglevel is above level, nothing happens, otherwise a timestamp and then
    each str(arg) joined by the optional keyword argument sep (default space)
    is printed. If this results in an IOError with errno EIO, it's assumed we
    lost contact with the terminal and the exception is caught; otherwise it
    is reraised.'''
    global loglevel

    if not args:
        raise TypeError('No log message provided')
    if level > loglevel:
        return

    if 'sep' in kwargs.keys():
        sep = kwargs['sep']
        del kwargs['sep']
    else:
        sep = ' '

    if kwargs:
        raise TypeError('Unexpected keyword argument{0}: {1}'.format(
                        's' if len(kwargs) != 1 else '',
                        ' '.join(kwargs.keys())))

    try:
        f = stderr if level in (LOG_ERROR, LOG_DEBUG) else stdout
        f.write(strftime('[%H:%M:%S] ') + sep.join(map(str, args)) + '\n')
    except IOError, (errno, strerror):
        if errno == EIO:
            # this happens when we lose contact with the terminal
            # we could stop all logging at this point but it doesn't actually
            # help a great deal...
            #loglevel = LOG_NONE
            pass
        else:
            raise

# used by the -4 and -6 options
disable_ipv4 = False
disable_ipv6 = not has_ipv6

# These are the configuration variables - their use is explained in the
# module's docstring
bindaddr = ''
bind6addr = ''
inPort = 30710
outPort = 30711
maxservers = -1
addr_blacklist = []

# Options which can be parsed out of the command line
# Every short option must currently have a corresponding long option.
# This is a somewhat silly limitation that replaces the more natural syntax
# -vvv for verbosity with -v 3
# General option FIXMEs:
# - Is ValueError really appropriate for every situation?
options = [
    ('4', 'ipv4', 'Only use IPv4'),
    ('6', 'ipv6', 'Only use IPv6'),
    ('h', 'help', 'Display this help'),
    ('j:', 'jail=<dir>', 'Path to chroot into at startup'),
    ('l:', 'listen-addr=<addr>', 'IPv4 address to listen to'),
    ('L:', 'listen6-addr=<addr>', 'IPv6 address to listen to'),
    ('n:', 'max-servers=<num>', 'Maximum number of servers to track'),
    ('p:', 'port=<num>', 'Port to listen on'),
    ('P:', 'challengeport=<num>', 'Port to send challenges on'),
    ('u:', 'user=<name>', 'User to switch to at startup'),
    ('v:', 'verbose=level', 'Log level (0-3)'),
    ('V', 'version', 'Print version information')
]

# Remove optional features that cannot be enabled (because the import for their
# associated function failed, for example)
disables = {
    'j': no_chroot,
    'u': no_setuid,
    '4': not has_ipv6,
    '6': not has_ipv6
}
for k in disables.keys():
    # This is a little messy. We assemble a string of short option characters
    # (without the :) and use the index of the disabled feature in the string
    # to find its index in the options list.
    shortopts = ''.join([opt[0][0] for (opt, _, _) in options])
    if disables[k]:
        del options[shortopts.index(k)]
        log(LOG_DEBUG, 'Disabled option -{0}'.format(k))

def print_help(f = stdout):
    '''Prints a formatted string of options, long options, and their help
    string to the specified file, defaulting to stderr.'''
    # This function is a mess that uses zip() altogether too much
    # First split the list of tuples into three lists:
    opts, longopts, helps = zip(*options)
    # Then format the options into a more readable form:
    opts = ['-{0},'.format(s.rstrip(':')) for s in opts]
    longopts = ['--{0} '.format(s) for s in longopts]
    # Assemble a list of the lengths of each option, for formatting purposes
    lens = [(len(opt), len(longopt)) for (opt, longopt) in zip(opts, longopts)]
    # vars is just a convenient measure to make our str.format call a little
    # more concise
    vars = dict()
    # Find the maximum length of each kind of option
    vars['optlen'], vars['longlen'] = map(max, zip(*lens))
    f.write('Available options:\n')
    for option in zip(opts, longopts, helps):
        vars['opt'], vars['longopt'], vars['help'] = option
        f.write(' {opt:{optlen}} {longopt:{longlen}} {help}\n'.format(**vars))

def print_version(f = stdout):
    '''Writes the version string to the specified file [stderr], followed by a
    newline'''
    f.write(version + '\n')

def opt_ipv4(arg = None):
    '''Disables IPv6, or raises ValueError if IPv4 is already disabled'''
    global disable_ipv6
    if disable_ipv4:
        raise ValueError('Must not specify both IPv4 and IPv6 options')
    disable_ipv6 = True
    log(LOG_VERBOSE, 'IPv6 disabled')

def opt_ipv6(arg = None):
    '''Disables IPv4, or raises ValueError if IPv6 is already disabled'''
    global disable_ipv4
    if disable_ipv6:
        raise ValueError('Must not specify both IPv4 and IPv6 options')
    disable_ipv4 = True
    log(LOG_VERBOSE, 'IPv4 disabled')

def opt_help(arg = None):
    '''Prints the version and help to stdout'''
    print_version()
    print_help()

def opt_jail(arg):
    '''Attempts to chroot into the given directory, exits with status code 1 in
    the event of failure'''
    try:
        chroot(arg)
        log(LOG_VERBOSE, 'Successfully chrooted to', arg)
    except OSError, (errno, strerror):
        raise ValueError('chroot {0}: {1}'.format(arg, strerror))

def opt_listenaddr(arg):
    '''Sets the IPv4 bind address to the given argument. Invalid addresses
    won't be caught until the program tries to bind them.
    Therefore specifying --bind-addr=banana! -6 is not an error.'''
    # perhaps it should be?
    global bindaddr
    bindaddr = arg

def opt_listen6addr(arg):
    '''Sets the IPv6 bind address to the given argument. Invalid addresses
    won't be caught until the program tries to bind them.
    Therefore specifying --bind6-addr=banana! -4 is not an error.'''
    global bind6addr
    bind6addr = arg

def opt_maxservers(arg):
    '''Tries to set the max servers option to the given argument converted to
    an integer. If conversion fails, logs an error and exits with code 1'''
    global maxservers
    try:
        maxservers = int(arg)
    except ValueError:
        raise ValueError('Max servers option must be numeric: ' + arg)

challengeport_set = False

def opt_port(arg):
    '''Tries to set the port number for incoming connections to the given
    argument, exiting with code 1 and an error message if the argument couldn't
    be converted to a valid port number. If the challenge port has not been
    explicitly set, and the specified port + 1 is also a valid port, we set the
    challenge port to that as well. If it has been explicitly set to the same
    as the incoming port, we print a warning, but accept it.'''
    global inPort, outPort
    try:
        inPort = int(arg)
        if inPort & ~0xffff:
            raise ValueError
    except ValueError:
        raise ValueError('Invalid port number: ' + arg)
    if not challengeport_set and inPort < 0xffff:
        outPort = inPort + 1
    elif inPort == outPort:
        log(LOG_PRINT, 'Warning: the challenge port should not be the same as '
                       'the listen port ({0})'.format(outPort))
    log(LOG_VERBOSE, 'Listen port set to', inPort)

def opt_challengeport(arg):
    '''Tries to set the port number for challenges to the given argument,
    exiting with code 1 and an error message if the argument couldn't be
    converted to a valid port number. If this setting makes the listen port
    equal to the challenge port, print a warning.'''
    # FIXME: what about --challengeport=30710 --port=30711 in that order
    global outPort, challengeport_set
    try:
        outPort = int(arg)
        if outPort & ~0xffff:
            raise ValueError
        challengeport_set = True
    except ValueError:
        raise ValueError('Invalid challenge port number: ' + arg)
    if inPort == outPort:
        log(LOG_PRINT, 'Warning: the challenge port should not be the same as '
                       'the listen port ({0})'.format(inPort))
    log(LOG_VERBOSE, 'Challenge port set to', outPort)

def opt_user(arg):
    '''Tries to setuid to the given argument, first as a user name then as an
    explicit UID.'''
    try:
        uid = getpwnam(arg)[2]
    except KeyError:
        try:
            uid = int(arg)
        except ValueError:
            raise ValueError('{0}: user name not found'.format(arg))

    try:
        setuid(uid)
        log(LOG_VERBOSE, 'UID is now', getuid())
    except OSError, (errno, strerror):
        raise ValueError('setuid {0}: {1}'.format(uid, strerror))

def opt_verbose(arg):
    '''Sets the log level to the specified argument, raising ValueError if it
    is not >= LOG_NONE and < LOG_LEVELS'''
    global loglevel
    try:
        loglevel = int(arg)
        if not LOG_NONE <= loglevel < LOG_LEVELS:
            raise ValueError
    except ValueError:
        raise ValueError('Verbose level must be between {0} and {1}'.format(
                         LOG_NONE, LOG_LEVELS - 1))

def opt_version(arg = None):
    '''Just print the version string and exit with code 0'''
    print_version()
    raise SystemExit(0)

def parse_cmdline():
    '''Parses the command line options, calling the relevant opt_ function for
    each one'''
    try:
        opts, longopts, help = zip(*options)
        def loptstrip(s):
            # just a bit too complex for a lambda
            bits = s.split('=')
            return bits[0] + ('=' if len(bits) > 1 else '')
        opts, args = getopt(argv[1:], ''.join(opts), map(loptstrip, longopts))
        if args:
            log(LOG_ERROR, 'Error: Excessive arguments:', *map(repr, args))
            raise SystemExit(1)
    except GetoptError, ex:
        log(LOG_ERROR, 'Error:', ex)
        log(LOG_ERROR, 'Try:', argv[0], '--help')
        raise SystemExit(1)
    # prioritise --help
    try:
        specified = zip(*opts)[0]
        if '-h' in specified or '--help' in specified:
            opt_help()
            raise SystemExit(0)
        if '-v' in specified or '--version' in specified:
            opt_version()
            raise SystemExit(0)
    except IndexError:
        pass
    for (opt, val) in opts:
        if not opt.startswith('--'):
            # convert short options to long options
            for option in options:
                if opt.lstrip('-') == option[0].rstrip(':'):
                    opt = option[1]
                    break
            else:
                # should never happen
                assert False, 'Corresponding long option to {0} '\
                              'not found'.format(opt)
        # strip hyphens (which are not allowed in function names)
        opt = filter(lambda c: c != '-', opt.split('=')[0])
        # probably this would be better as an explicit name->func mapping
        try:
            globals()['opt_{0}'.format(opt)](val)
        except ValueError, ex:
            log(LOG_ERROR, 'Error:', ex)
            log(LOG_ERROR, 'Try:', argv[0], '--help')
            raise SystemExit(1)

def parse_cfgs():
    '''For each blank-separated address in ignore.txt, check if it is valid and
    if so add it to the addr_blacklist.
    A missing ignore.txt is ignored but other errors - e.g. if ignore.txt is
    present but can't be read - are fatal.'''
    try:
        with open("ignore.txt") as ignore:
            for line in ignore:
                for addr in line.split():
                    try:
                        inet_pton(addr)
                    except EnvironmentError:
                        pass
                    else:
                        addr_blacklist.append(addr)
    except IOError, (errno, strerror):
        if errno != ENOENT:
            raise

def parse():
    '''Delegation to parse_cfgs and parse_cmdline.'''
    # It seems natural to let the command line override config settings, so it
    # should parse config then command line.
    # It seems natural to allow config files to be specified on the command
    # line, so we should parse command line then config.
    # hmm...
    parse_cfgs()
    parse_cmdline()
