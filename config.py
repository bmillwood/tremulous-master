# config.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.

bindaddr = '127.1'
bind6addr = '::1'
inPort = 30710
# If we use the same port for challenges as we receive heartbeats on, some
# improperly configured NAT implementations will recognise the challenge as
# part of the same connection and will therefore get the port translation
# right, even though they wouldn't for a client.
# Therefore, we use a different port to ensure the master doesn't get
# special treatment.
outPort = 30711

CHALLENGE_LENGTH = 12
CHALLENGE_TIMEOUT = 5
SERVER_TIMEOUT = 11 * 60
GSR_MAXLENGTH = 1400

addr_blacklist = []
