from socket import AF_INET, AF_INET6, error as sockerr

try:
    # I'm guessing the builtin inet_pton will be faster, but if it's not
    # available we'll just have to use mine
    from socket import inet_pton
except ImportError:
    def inet_pton(af, ip):
        '''inet_pton(af, ip) -> packed IP address string

        Convert an IP address from string format to a packed string suitable
        for use with low-level network functions.'''
        if af == AF_INET:
            try:
                return ''.join(chr(int(b)) for b in ip.split('.'))
            except ValueError:
                raise sockerr('illegal IP address string passed to inet_pton')
        elif af == AF_INET6:
            bits = ip.split('::')
            if len(bits) > 2:
                raise sockerr('illegal IP address string passed to inet_pton')
            try:
                if len(bits) == 2:
                    # The filter(bool) replaces [''] with [] in the case that
                    # :: begins or ends a string (so bits[i] would be empty)
                    lead, trail = [filter(bool, s.split(':')) for s in bits]
                    full = [int(s, 16) for s in lead]
                    full += [0 for _ in range(8 - len(lead) - len(trail))]
                    full += [int(s, 16) for s in trail]
                else:
                    full = [int(s, 16) for s in ip.split(':')]
            except ValueError:
                raise sockerr('illegal IP address string passed to inet_pton')
            return ''.join([chr(b >> 8) + chr(b & 0xff) for b in full])
        else:
            # I don't know why 97, I'm just copying the observed behaviour of
            # my system's inet_pton
            raise sockerr(97, 'Address family not supported by protocol')
