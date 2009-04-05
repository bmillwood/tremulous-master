# config.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.

from errno import ENOENT, EIO
from getopt import getopt, GetoptError
from sys import argv, platform, stdout, stderr
from time import strftime

# optional imports
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

version = 'Tremulous Master Server v0.1'

def intable(arg, base = 10):
    '''Tests whether arg can be inted'''
    # this should probably go into another file
    try:
        int(arg, base)
        return True
    except:
        return False

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

disable_ipv4 = False
disable_ipv6 = not has_ipv6

bindaddr = ''
bind6addr = ''
inPort = 30710
# If we use the same port for challenges as we receive heartbeats on, some
# improperly configured NAT implementations will recognise the challenge as
# part of the same connection and will therefore get the port translation
# right, even though they wouldn't for a client.
# Therefore, we use a different port to ensure the master doesn't get
# special treatment.
outPort = 30711

# what's the point of this option?
maxservers = -1

# these correspond to values defined in tremulous source, changing them may
# cause incompatibilities
CHALLENGE_LENGTH = 12
CHALLENGE_TIMEOUT = 5
SERVER_TIMEOUT = 11 * 60
GSR_MAXLENGTH = 1400

addr_blacklist = []

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

# remove optional features that aren't enabled
disables = {
    'j': no_chroot,
    'u': no_setuid,
    '4': not has_ipv6,
    '6': not has_ipv6
}
for k in disables.keys():
    shortopts = ''.join([opt[0][0] for (opt, _, _) in options])
    if disables[k]:
        del options[shortopts.index(k)]
        log(LOG_DEBUG, 'Disabled option -{0}'.format(k))

def print_help(f = stderr):
    opts, longopts, helps = zip(*options)
    opts = map(lambda s: '-{0},'.format(s.rstrip(':')), opts)
    longopts = map(lambda s: '--{0} '.format(s.rstrip('=')), longopts)
    lens = [(len(opt), len(longopt)) for (opt, longopt) in zip(opts, longopts)]
    vars = dict()
    vars['optlen'], vars['longlen'] = map(max, zip(*lens))
    f.write('Available options:\n')
    for option in zip(opts, longopts, helps):
        vars['opt'], vars['longopt'], vars['help'] = option
        f.write(' {opt:{optlen}} {longopt:{longlen}} {help}\n'.format(**vars))

def print_version(f = stderr):
    f.write(version + '\n')

def opt_ipv4(arg):
    global disable_ipv6
    if disable_ipv4:
        raise ValueError('Must not specify both IPv4 and IPv6 options')
    disable_ipv6 = True
    log(LOG_VERBOSE, 'IPv6 disabled')

def opt_ipv6(arg):
    global disable_ipv4
    if disable_ipv6:
        raise ValueError('Must not specify both IPv4 and IPv6 options')
    disable_ipv4 = True
    log(LOG_VERBOSE, 'IPv4 disabled')

def opt_help(arg):
    print_version()
    print_help()
    raise SystemExit(0)

def opt_jail(arg):
    try:
        chroot(arg)
        log(LOG_VERBOSE, 'Successfully chrooted to', arg)
    except OSError, (errno, strerror):
        log(LOG_ERROR, 'chroot {0}: {1}'.format(arg, strerror))
        raise SystemExit(1)

def opt_listenaddr(arg):
    global bindaddr
    bindaddr = arg

def opt_listen6addr(arg):
    global bind6addr
    bind6addr = arg

def opt_maxservers(arg):
    global maxservers
    if not intable(arg):
        log(LOG_ERROR, 'Error: max-servers option must be numeric:', arg)
        raise SystemExit(1)
    maxservers = int(arg)

challengeport_set = False

def opt_port(arg):
    global inPort, outPort
    try:
        inPort = int(arg)
        if inPort & ~0xffff:
            raise ValueError
    except ValueError:
        log(LOG_ERROR, 'Invalid port number:', arg)
        raise SystemExit(1)
    if not challengeport_set and inPort < 0xffff:
        outPort = inPort + 1
    elif inPort == outPort:
        log(LOG_PRINT, 'Warning: the challenge port should not be the same as '
                       'the listen port ({0})'.format(outPort))
    log(LOG_VERBOSE, 'Listen port set to', inPort)

def opt_challengeport(arg):
    global outPort, challengeport_set
    try:
        outPort = int(arg)
        if outPort & ~0xffff:
            raise ValueError
        challengeport_set = True
    except ValueError:
        log(LOG_ERROR, 'Invalid challenge port number:', arg)
        raise SystemExit(1)
    if inPort == outPort:
        log(LOG_PRINT, 'Warning: the challenge port should not be the same as '
                       'the listen port ({0})'.format(inPort))
    log(LOG_VERBOSE, 'Challenge port set to', outPort)

def opt_user(arg):
    try:
        uid = getpwnam(arg)[2]
    except KeyError:
        if intable(arg):
            uid = int(arg)
        else:
            log(LOG_ERROR, '{0}: name not found'.format(arg))
            raise SystemExit(1)

    try:
        setuid(uid)
        log(LOG_VERBOSE, 'UID is now', getuid())
    except OSError, (errno, strerror):
        log(LOG_ERROR, 'setuid {0}: {1}'.format(uid, strerror))
        raise SystemExit(1)

def opt_verbose(arg):
    global loglevel
    loglevel = int(arg)
    if not LOG_NONE <= loglevel < LOG_LEVELS:
        raise ValueError('Verbose level must be between {0} and {1}'.format(
                         LOG_NONE, LOG_LEVELS - 1))

def opt_version(arg):
    print_version()
    raise SystemExit(0)

def parse_cmdline():
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
        print_help()
        raise SystemExit(1)
    for (opt, val) in opts:
        # convert short options to long options
        if not opt.startswith('--'):
            for option in options:
                if opt.lstrip('-') == option[0].rstrip(':'):
                    opt = option[1]
                    break
            else:
                # should never happen
                assert False, 'Corresponding long option to {0} '\
                              'not found'.format(opt)
        opt = filter(lambda c: c != '-', opt.split('=')[0])
        # possibly this would be better as an explicit name->func mapping
        try:
            globals()['opt_{0}'.format(opt)](val)
        except ValueError, ex:
            log(LOG_ERROR, 'Error:', ex)
            raise SystemExit(1)

def valid_addr(addr):
    if '.' in addr:
        # assume IPv4
        ip, port = addr.split(':')
        if not intable(port) or int(port) & ~0xffff:
            return False
        bytes = ip.split('.')
        if len(bytes) != 4:
            return False
        for byte in bytes:
            if not intable(byte) or int(byte) & ~0xff:
                return False
        return True
    else:
        # assume IPv6
        try:
            # check for :: appearing twice
            addr[addr.index('::'):].index('::', 2)
            return False
        except ValueError:
            pass
        pieces = addr.split(':')
        if len(pieces) > 8:
            return False
        for piece in pieces:
            if not intable(piece, 16) or int(piece, 16) & ~0xffff:
                return False

def parse_cfgs():
    try:
        with open("ignore.txt") as ignore:
            for line in ignore:
                for addr in line.split():
                    if valid_addr(addr):
                        addr_blacklist.append(addr)
    except IOError, (errno, strerror):
        if errno != ENOENT:
            raise

def parse():
    parse_cfgs()
    parse_cmdline()
