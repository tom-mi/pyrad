import unittest
import six
from pyrad import tools

try:
    import ipaddress
except ImportError:
    ipaddress = None


class EncodingTests(unittest.TestCase):
    def testStringEncoding(self):
        self.assertRaises(ValueError, tools.EncodeString, 'x' * 254)
        self.assertEqual(
                tools.EncodeString('1234567890'),
                six.b('1234567890'))

    def testInvalidStringEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeString, 1)

    def testAddressEncoding(self):
        self.assertRaises(ValueError, tools.EncodeAddress, '123')
        self.assertEqual(
                tools.EncodeAddress('192.168.0.255'),
                six.b('\xc0\xa8\x00\xff'))

    def testInvalidAddressEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeAddress, 1)

    def testIntegerEncoding(self):
        self.assertEqual(tools.EncodeInteger(0x01020304),
                six.b('\x01\x02\x03\x04'))

    def testUnsignedIntegerEncoding(self):
        self.assertEqual(tools.EncodeInteger(0xFFFFFFFF),
                six.b('\xff\xff\xff\xff'))

    def testInvalidIntegerEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeInteger, '1')

    def testDateEncoding(self):
        self.assertEqual(tools.EncodeDate(0x01020304),
                six.b('\x01\x02\x03\x04'))

    def testInvalidDataEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeDate, '1')

    def testStringDecoding(self):
        self.assertEqual(
                tools.DecodeString(six.b('1234567890')),
                '1234567890')

    def testAddressDecoding(self):
        self.assertEqual(
                tools.DecodeAddress(six.b('\xc0\xa8\x00\xff')),
                '192.168.0.255')

    def testIntegerDecoding(self):
        self.assertEqual(
                tools.DecodeInteger(six.b('\x01\x02\x03\x04')),
                0x01020304)

    @unittest.skipUnless(ipaddress, 'Requires ipaddress module.')
    def testIPv6PrefixDecoding(self):
        self.assertEqual(
            tools.DecodeIPv6Prefix(
                six.b('\x00\x40\x20\x01\x0d\xb8\x3c\x4d\x00\x15')),
            ipaddress.IPv6Network(six.u('2001:db8:3c4d:15::/64')))
        self.assertEqual(
            tools.DecodeIPv6Prefix(
                six.b('\x00\x38\x20\x01\x0d\xb8\x3c\x4d\x15')),
            ipaddress.IPv6Network(six.u('2001:db8:3c4d:1500::/56')))
        self.assertEqual(
            tools.DecodeIPv6Prefix(
                six.b('\x00\x80\x20\x01\x0d\xb8\x85\xa3\x08\xd3'
                      '\x13\x19\x8a\x2e\x03\x70\x73\x48')),
            ipaddress.IPv6Network(
                six.u('2001:db8:85a3:8d3:1319:8a2e:370:7348/128')))

    @unittest.skipUnless(ipaddress, 'Requires ipaddress module.')
    def testIPv6PrefixEncoding(self):
        self.assertEqual(
            tools.EncodeIPv6Prefix(
                ipaddress.IPv6Network(six.u('2001:db8:3c4d:15::/64'))),
            six.b('\x00\x40\x20\x01\x0d\xb8\x3c\x4d\x00\x15'))
        self.assertEqual(
            tools.EncodeIPv6Prefix(
                ipaddress.IPv6Network(six.u('2001:db8:3c4d:1500::/56'))),
            six.b('\x00\x38\x20\x01\x0d\xb8\x3c\x4d\x15'))
        self.assertEqual(
            tools.EncodeIPv6Prefix(
                ipaddress.IPv6Network(
                    six.u('2001:db8:85a3:8d3:1319:8a2e:370:7348/128'))),
            six.b('\x00\x80\x20\x01\x0d\xb8\x85\xa3\x08\xd3'
                  '\x13\x19\x8a\x2e\x03\x70\x73\x48'))

    def testDateDecoding(self):
        self.assertEqual(
                tools.DecodeDate(six.b('\x01\x02\x03\x04')),
                0x01020304)

    def testUnknownTypeEncoding(self):
        self.assertRaises(ValueError, tools.EncodeAttr, 'unknown', None)

    def testUnknownTypeDecoding(self):
        self.assertRaises(ValueError, tools.DecodeAttr, 'unknown', None)

    def testDecodeTaggedAttr(self):
        self.assertEqual(
            tools.DecodeTaggedAttr('octets', six.b('\x00123')),
            (0, six.b('123')))
        self.assertEqual(
            tools.DecodeTaggedAttr('octets', six.b('\x01\x02\x03')),
            (1, six.b('\x02\x03')))
        self.assertEqual(
            tools.DecodeTaggedAttr('octets', six.b('\x1F\x02\x03')),
            (31, six.b('\x02\x03')))
        # Invalid tunnel tag (>32)
        self.assertRaises(ValueError, tools.DecodeTaggedAttr,
                          'octets', six.b('\x20\x02\x03'))

    def testDecodeTaggedAttrInt(self):
        # Test for correct handling of tagged integers (tag + 3 octets)
        self.assertEqual(
            tools.DecodeTaggedAttr('integer', six.b('\x01\x02\x03\x04')),
            (1, six.b('\x00\x02\x03\x04')))

    def testEncodeTaggedAttr(self):
        self.assertEqual(
            tools.EncodeTaggedAttr('octets', 1, six.b('123')),
            six.b('\x01123'))
        self.assertEqual(
            tools.EncodeTaggedAttr('octets', 31, six.b('\x07\x08')),
            six.b('\x1F\x07\x08'))
        self.assertEqual(
            tools.EncodeTaggedAttr('octets', 0, six.b('\x02\x03\x05')),
            six.b('\x00\x02\x03\x05'))

    def testEncodeFunction(self):
        self.assertEqual(
                tools.EncodeAttr('string', six.u('string')),
                six.b('string'))
        self.assertEqual(
                tools.EncodeAttr('octets', six.b('string')),
                six.b('string'))
        self.assertEqual(
                tools.EncodeAttr('ipaddr', '192.168.0.255'),
                six.b('\xc0\xa8\x00\xff'))
        self.assertEqual(
                tools.EncodeAttr('integer', 0x01020304),
                six.b('\x01\x02\x03\x04'))
        self.assertEqual(
                tools.EncodeAttr('date', 0x01020304),
                six.b('\x01\x02\x03\x04'))
        self.assertEqual(
                tools.EncodeAttr('integer64', 0x0102030405060708),
                six.b('\x01\x02\x03\x04\x05\x06\x07\x08'))

    @unittest.skipUnless(ipaddress, 'Requires ipaddress module.')
    def testEncodeFunctionIP(self):
        self.assertEqual(
            tools.EncodeAttr(
                'ipv6prefix',
                ipaddress.IPv6Network(six.u('2001:db8:1234::/48'))),
            six.b('\x00\x30\x20\x01\x0d\xb8\x12\x34'))

    def testDecodeFunction(self):
        self.assertEqual(
                tools.DecodeAttr('string', six.b('string')),
                six.u('string'))
        self.assertEqual(
                tools.EncodeAttr('octets', six.b('string')),
                six.b('string'))
        self.assertEqual(
                tools.DecodeAttr('ipaddr', six.b('\xc0\xa8\x00\xff')),
                '192.168.0.255')
        self.assertEqual(
                tools.DecodeAttr('integer', six.b('\x01\x02\x03\x04')),
                0x01020304)
        self.assertEqual(
                tools.DecodeAttr('date', six.b('\x01\x02\x03\x04')),
                0x01020304)
        self.assertEqual(
                tools.DecodeAttr('integer64',
                                 six.b('\x01\x02\x03\x04\x05\x06\x07\x08')),
                0x0102030405060708)

    @unittest.skipUnless(ipaddress, 'Requires ipaddress module.')
    def testDecodeFunctionIP(self):
        self.assertEqual(
            tools.DecodeAttr(
                'ipv6prefix', six.b('\x00\x30\x20\x01\x0d\xb8\x12\x34')),
            ipaddress.IPv6Network(six.u('2001:db8:1234::/48')))
