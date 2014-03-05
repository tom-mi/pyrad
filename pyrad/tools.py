# tools.py
#
# Utility functions
import struct
import six

def EncodeString(str):
    if len(str) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    if isinstance(str, six.text_type):
        return str.encode('utf-8')
    else:
        return str


def EncodeOctets(str):
    if len(str) > 253:
        raise ValueError('Can only encode strings of <= 253 characters')
    return str


def EncodeAddress(addr):
    if not isinstance(addr, six.string_types):
        raise TypeError('Address has to be a string')
    (a, b, c, d) = map(int, addr.split('.'))
    return struct.pack('BBBB', a, b, c, d)


def EncodeIPv6Prefix(prefix):
    try:
        import ipaddress
    except ImportError:
        raise Exception('ipaddress module is required for IPv6Prefix support')
    if not isinstance(prefix, ipaddress.IPv6Network):
        raise TypeError('IPv6Prefix has to be a ipaddress.IPv6Network')
    octets = (prefix.prefixlen - 1) // 8 + 1
    return (struct.pack('BB', 0, prefix.prefixlen) +
            prefix.network_address.packed[0:octets])


def EncodeInteger(num, fmt='!I'):
    if not isinstance(num, six.integer_types):
        raise TypeError('Can not encode non-integer as integer')
    return struct.pack(fmt, num)


def EncodeDate(num):
    if not isinstance(num, int):
        raise TypeError('Can not encode non-integer as date')
    return struct.pack('!I', num)


def DecodeString(str):
    return str.decode('utf-8')


def DecodeOctets(str):
    return str


def DecodeAddress(addr):
    return '.'.join(map(str, struct.unpack('BBBB', addr)))

def DecodeIPv6Prefix(value):
    try:
        import ipaddress
    except ImportError:
        raise Exception('ipaddress module is required for IPv6Prefix support')
    _, prefixlen = struct.unpack('BB', value[0:2])
    assert prefixlen <= 128
    if len(value[2:]) % 2 == 1:  # pad last incomplete block with zero
        value += chr(0)
    fmt = '!' + ('H' * (len(value[2:]) / 2))
    blocks = ['0'] * 8
    for index, block in enumerate(struct.unpack(fmt, value[2:])):
        blocks[index] = six.u('{:x}').format(block)
    prefix = six.u(':').join(blocks)
    return ipaddress.IPv6Network(six.u('{}/{}').format(prefix, prefixlen))

def DecodeInteger(num, fmt='!I'):
    return (struct.unpack(fmt, num))[0]


def DecodeDate(num):
    return (struct.unpack('!I', num))[0]


def DecodeTaggedAttr(datatype, value):
    # NOTE: According to RFC 2865, if the first byte (the tunnel tag field) is
    # NOTE: not between 0..32, it SHOULD be interpreted as first byte of the
    # NOTE: following string (for string fields) or ignored (for tunnel
    # NOTE: password field). This behavior is not yet implemented.
    (tag,) = struct.unpack('B', value[0:1])
    if (tag <= 0x1F):
        value = value[1:]
        if datatype == 'integer':
            # Tagged integer fields have only 3 octets => pad with one octet.
            # See RFC 2865 for details.
            value = six.b('\x00') + value
            assert len(value) == 4
        return (tag, value)
    else:
        msg = ('Tunnel-Tag must be a value between 0..32. Exceptions for '
               'string fields (see RFC 2865) are not yet implemented.')
        raise ValueError(msg)


def EncodeTaggedAttr(datatype, tag, value):
    if datatype == 'integer':
        # Tagged integer fields have only 3 octets => pad with one octet.
        # See RFC 2865 for details.
        value = value[1:]
        assert len(value) == 3
    return EncodeInteger(tag, 'B') + value


def EncodeAttr(datatype, value):
    if datatype == 'string':
        return EncodeString(value)
    elif datatype == 'octets':
        return EncodeOctets(value)
    elif datatype == 'ipaddr':
        return EncodeAddress(value)
    elif datatype == 'integer':
        return EncodeInteger(value)
    elif datatype == 'integer64':
        return EncodeInteger(value, '!Q')
    elif datatype == 'signed':
        return EncodeInteger(value, '!i')
    elif datatype == 'short':
        return EncodeInteger(value, '!H')
    elif datatype == 'byte':
        return EncodeInteger(value, 'B')
    elif datatype == 'date':
        return EncodeDate(value)
    elif datatype == 'ipv6prefix':
        return EncodeIPv6Prefix(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)


def DecodeAttr(datatype, value):
    if datatype == 'string':
        return DecodeString(value)
    elif datatype == 'octets':
        return DecodeOctets(value)
    elif datatype == 'ipaddr':
        return DecodeAddress(value)
    elif datatype == 'integer':
        return DecodeInteger(value)
    elif datatype == 'integer64':
        return DecodeInteger(value, '!Q')
    elif datatype == 'signed':
        return DecodeInteger(value, '!i')
    elif datatype == 'short':
        return DecodeInteger(value, '!H')
    elif datatype == 'byte':
        return DecodeInteger(value, 'B')
    elif datatype == 'date':
        return DecodeDate(value)
    elif datatype == 'ipv6prefix':
        return DecodeIPv6Prefix(value)
    else:
        raise ValueError('Unknown attribute type %s' % datatype)


def XorBytes(bytes1, bytes2):
    '''Xor two bytestrings.'''
    assert len(bytes1) == len(bytes2)
    result = six.b('')
    if six.PY3:
        for b1, b2 in zip(bytes1, bytes2):
            result += bytes((b1 ^ b2,))
    else:
        for b1, b2 in zip(bytes1, bytes2):
            result += chr(ord(b1) ^ ord(b2))
    return result
