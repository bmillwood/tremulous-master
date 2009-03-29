# config.py
# Copyright (c) Ben Millwood 2009
# This file is part of the Tremulous Master server.

bindaddr = '0.0.0.0'
bind6addr = '::'
inPort = 30710
# If we use the same port for challenges as we receive heartbeats on, some
# improperly configured NAT implementations will recognise the challenge as
# part of the same connection and will therefore get the port translation
# right, even though they wouldn't for a client.
# Therefore, we use a different port to ensure the master doesn't get
# special treatment.
outPort = 30711

CHALLENGE_LENGTH = 12
