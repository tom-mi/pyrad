from __future__ import absolute_import
import mock
import os
import unittest
import random
import six
from pyrad import packet
from pyrad.tests import home
from pyrad.dictionary import Dictionary


class UtilityTests(unittest.TestCase):
    def testGenerateID(self):
        id = packet.CreateID()
        self.failUnless(isinstance(id, int))
        newid = packet.CreateID()
        self.assertNotEqual(id, newid)


class PacketConstructionTests(unittest.TestCase):
    klass = packet.Packet

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'simple'))

    def testBasicConstructor(self):
        pkt = self.klass()
        self.failUnless(isinstance(pkt.code, int))
        self.failUnless(isinstance(pkt.id, int))
        self.failUnless(isinstance(pkt.secret, six.binary_type))

    def testNamedConstructor(self):
        pkt = self.klass(code=26, id=38, secret=six.b('secret'),
                authenticator=six.b('authenticator'),
                dict='fakedict')
        self.assertEqual(pkt.code, 26)
        self.assertEqual(pkt.id, 38)
        self.assertEqual(pkt.secret, six.b('secret'))
        self.assertEqual(pkt.authenticator, six.b('authenticator'))
        self.assertEqual(pkt.dict, 'fakedict')

    def testConstructWithDictionary(self):
        pkt = self.klass(dict=self.dict)
        self.failUnless(pkt.dict is self.dict)

    def testConstructorIgnoredParameters(self):
        marker = []
        pkt = self.klass(fd=marker)
        self.failIf(getattr(pkt, 'fd', None) is marker)

    def testSecretMustBeBytestring(self):
        self.assertRaises(TypeError, self.klass, secret=six.u('secret'))

    def testConstructorWithAttributes(self):
        pkt = self.klass(dict=self.dict, Test_String='this works')
        self.assertEqual(pkt['Test-String'], ['this works'])

    def testConstructorWithMultiValueAttribute(self):
        pkt = self.klass(dict=self.dict, Test_String=['a', 'list'])
        self.assertEqual(pkt['Test-String'], ['a', 'list'])


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.Packet(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(Test_Integer=10)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testAttributeAccess(self):
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet['Test-Integer'], [10])
        self.assertEqual(self.packet[3], [six.b('\x00\x00\x00\x0a')])

        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet['Test-String'], ['dummy'])
        self.assertEqual(self.packet[1], [six.b('dummy')])

    def testAttributeValueAccess(self):
        self.packet['Test-Integer'] = 'Three'
        self.assertEqual(self.packet['Test-Integer'], ['Three'])
        self.assertEqual(self.packet[3], [six.b('\x00\x00\x00\x03')])

    def testVendorAttributeAccess(self):
        self.packet['Simplon-Number'] = 10
        self.assertEqual(self.packet['Simplon-Number'], [10])
        self.assertEqual(self.packet[(16, 1)], [six.b('\x00\x00\x00\x0a')])

        self.packet['Simplon-Number'] = 'Four'
        self.assertEqual(self.packet['Simplon-Number'], ['Four'])
        self.assertEqual(self.packet[(16, 1)], [six.b('\x00\x00\x00\x04')])

    def testRawAttributeAccess(self):
        marker = [six.b('')]
        self.packet[1] = marker
        self.failUnless(self.packet[1] is marker)
        self.packet[(16, 1)] = marker
        self.failUnless(self.packet[(16, 1)] is marker)

    def testHasKey(self):
        self.assertEqual(self.packet.has_key('Test-String'), False)
        self.assertEqual('Test-String' in self.packet, False)
        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet.has_key('Test-String'), True)
        self.assertEqual(self.packet.has_key(1), True)
        self.assertEqual(1 in self.packet, True)

    def testHasKeyWithUnknownKey(self):
        self.assertEqual(self.packet.has_key('Unknown-Attribute'), False)
        self.assertEqual('Unknown-Attribute' in self.packet, False)

    def testDelItem(self):
        self.packet['Test-String'] = 'dummy'
        del self.packet['Test-String']
        self.assertEqual(self.packet.has_key('Test-String'), False)
        self.packet['Test-String'] = 'dummy'
        del self.packet[1]
        self.assertEqual(self.packet.has_key('Test-String'), False)

    def testKeys(self):
        self.assertEqual(self.packet.keys(), [])
        self.packet['Test-String'] = 'dummy'
        self.assertEqual(self.packet.keys(), ['Test-String'])
        self.packet['Test-Integer'] = 10
        self.assertEqual(self.packet.keys(), ['Test-String', 'Test-Integer'])
        dict.__setitem__(self.packet, 12345, None)
        self.assertEqual(self.packet.keys(),
                        ['Test-String', 'Test-Integer', 12345])

    def testCreateAuthenticator(self):
        a = packet.Packet.CreateAuthenticator()
        self.failUnless(isinstance(a, six.binary_type))
        self.assertEqual(len(a), 16)

        b = packet.Packet.CreateAuthenticator()
        self.assertNotEqual(a, b)

    def testGenerateID(self):
        id = self.packet.CreateID()
        self.failUnless(isinstance(id, int))
        newid = self.packet.CreateID()
        self.assertNotEqual(id, newid)

    def testReplyPacket(self):
        reply = self.packet.ReplyPacket()
        self.assertEqual(reply,
                six.b('\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c'
                      '\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7'))

    def testVerifyReply(self):
        reply = self.packet.CreateReply()
        self.assertEqual(self.packet.VerifyReply(reply), True)

        reply.id += 1
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.id = self.packet.id

        reply.secret = six.b('different')
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.secret = self.packet.secret

        reply.authenticator = six.b('X') * 16
        self.assertEqual(self.packet.VerifyReply(reply), False)
        reply.authenticator = self.packet.authenticator

    def testPktEncodeAttribute(self):
        encode = self.packet._PktEncodeAttribute

        # Encode a normal attribute
        self.assertEqual(
                encode(1, six.b('value')),
                six.b('\x01\x07value'))
        # Encode a vendor attribute
        self.assertEqual(
                encode((1, 2), six.b('value')),
                six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value'))

    def testPktEncodeAttributes(self):
        self.packet[1] = [six.b('value')]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                six.b('\x01\x07value'))

        self.packet.clear()
        self.packet[(1, 2)] = [six.b('value')]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value'))

        self.packet.clear()
        self.packet[1] = [six.b('one'), six.b('two'), six.b('three')]
        self.assertEqual(self.packet._PktEncodeAttributes(),
                six.b('\x01\x05one\x01\x05two\x01\x07three'))

        self.packet.clear()
        self.packet[1] = [six.b('value')]
        self.packet[(1, 2)] = [six.b('value')]
        self.assertEqual(
                self.packet._PktEncodeAttributes(),
                six.b('\x1a\x0d\x00\x00\x00\x01\x02\x07value\x01\x07value'))

    def testPktEncodeVendorAttributeWithFormat(self):
        # Vendor Foo (0x11 = 17) has format=4,0
        self.packet.clear()
        self.packet[(17, 0xdeadbeef)] = [six.b('new-value')]
        self.assertEqual(
            self.packet._PktEncodeAttributes(),
            six.b('\x1a\x13\x00\x00\x00\x11\xDE\xAD\xBE\xEFnew-value'))

        # Vendor Bar (0x12 = 18) has format=1,2
        self.packet.clear()
        self.packet[(18, 1)] = [six.b('\x00\x00\x00\x42')]
        self.assertEqual(
            self.packet._PktEncodeAttributes(),
            six.b('\x1a\x0D\x00\x00\x00\x12\x01\x00\x07\x00\x00\x00\x42'))

    def testPktDecodeVendorAttribute(self):
        decode = self.packet._PktDecodeVendorAttribute

        # Non-RFC2865 recommended form
        self.assertEqual(decode(six.b('')), (26, six.b('')))
        self.assertEqual(decode(six.b('12345')), (26, six.b('12345')))

        # Almost RFC2865 recommended form: bad length value
        self.assertEqual(
                decode(six.b('\x00\x00\x00\x01\x02\x06value')),
                (26, six.b('\x00\x00\x00\x01\x02\x06value')))

        # Proper RFC2865 recommended form
        self.assertEqual(
                decode(six.b('\x00\x00\x00\x01\x02\x07value')),
                ((1, 2), six.b('value')))

    def testPktDecodeVendorAttributeWithFormat(self):
        decode = self.packet._PktDecodeVendorAttribute

        # Vendor Foo (0x11 = 17) has format=4,0
        self.assertEqual(
            decode(six.b('\x00\x00\x00\x11\xDE\xAD\xBE\xEFspecial-value')),
                ((17, 0xdeadbeef), six.b('special-value')))

        # Vendor Bar (0x12 = 18) has format=1,2
        self.assertEqual(
            decode(six.b('\x00\x00\x00\x12\x01\x00\x07\x00\x00\x00\x42')),
            ((18, 1), six.b('\x00\x00\x00\x42')))

    def testDecodePacketWithEmptyPacket(self):
        try:
            self.packet.DecodePacket(six.b(''))
        except packet.PacketError as e:
            self.failUnless('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithInvalidLength(self):
        try:
            self.packet.DecodePacket(six.b('\x00\x00\x00\x001234567890123456'))
        except packet.PacketError as e:
            self.failUnless('invalid length' in str(e))
        else:
            self.fail()

    def testDecodePacketWithTooBigPacket(self):
        try:
            self.packet.DecodePacket(six.b('\x00\x00\x24\x00') + (0x2400 - 4) * six.b('X'))
        except packet.PacketError as e:
            self.failUnless('too long' in str(e))
        else:
            self.fail()

    def testDecodePacketWithPartialAttributes(self):
        try:
            self.packet.DecodePacket(
                    six.b('\x01\x02\x00\x151234567890123456\x00'))
        except packet.PacketError as e:
            self.failUnless('header is corrupt' in str(e))
        else:
            self.fail()

    def testDecodePacketWithoutAttributes(self):
        self.packet.DecodePacket(six.b('\x01\x02\x00\x141234567890123456'))
        self.assertEqual(self.packet.code, 1)
        self.assertEqual(self.packet.id, 2)
        self.assertEqual(self.packet.authenticator, six.b('1234567890123456'))
        self.assertEqual(self.packet.keys(), [])

    def testDecodePacketWithBadAttribute(self):
        try:
            self.packet.DecodePacket(
                    six.b('\x01\x02\x00\x161234567890123456\x00\x01'))
        except packet.PacketError as e:
            self.failUnless('too small' in str(e))
        else:
            self.fail()

    def testDecodePacketWithEmptyAttribute(self):
        self.packet.DecodePacket(
                six.b('\x01\x02\x00\x161234567890123456\x00\x02'))
        self.assertEqual(self.packet[0], [six.b('')])

    def testDecodePacketWithAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1b1234567890123456\x00\x07value'))
        self.assertEqual(self.packet[0], [six.b('value')])

    def testDecodePacketWithMultiValuedAttribute(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1e1234567890123456\x00\x05one\x00\x05two'))
        self.assertEqual(self.packet[0], [six.b('one'), six.b('two')])

    def testDecodePacketWithTwoAttributes(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1e1234567890123456\x00\x05one\x01\x05two'))
        self.assertEqual(self.packet[0], [six.b('one')])
        self.assertEqual(self.packet[1], [six.b('two')])

    def testDecodePacketWithVendorAttribute(self):
        self.packet.DecodePacket(
                six.b('\x01\x02\x00\x1b1234567890123456\x1a\x07value'))
        self.assertEqual(self.packet[26], [six.b('value')])

    def testEncodeKeyValues(self):
        self.assertEqual(self.packet._EncodeKeyValues(1, '1234'), (1, '1234'))

    def testEncodeKey(self):
        self.assertEqual(self.packet._EncodeKey(1), 1)

    def testAddAttribute(self):
        self.packet.AddAttribute(1, 1)
        self.assertEqual(dict.__getitem__(self.packet, 1), [1])
        self.packet.AddAttribute(1, 1)
        self.assertEqual(dict.__getitem__(self.packet, 1), [1, 1])

    def testTunnelAttributeInt(self):
        # The tunnel tag is written in the first octet of the int, meaning
        # there are only 3 octets remaining for the value itself.
        self.packet['Test-Tunnel-Int'] = (1, 5)
        self.assertEqual(self.packet['Test-Tunnel-Int'], [(1, 5)])
        self.assertEqual(self.packet[5], [six.b('\x01\x00\x00\x05')])

    def testTunnelAttributeEncodeNoTag(self):
        self.packet['Test-Tunnel-Int'] = 5
        self.assertEqual(self.packet['Test-Tunnel-Int'], [(0, 5)])
        self.assertEqual(self.packet[5], [six.b('\x00\x00\x00\x05')])

    def testTunnelAttributeDecodeNoTag(self):
        self.packet.DecodePacket(
            six.b('\x01\x02\x00\x1a1234567890123456\x05\x06\x20\x00\x00\x00'))
        self.assertRaises(ValueError, self.packet.__getitem__,
                          'Test-Tunnel-Int')

    def testTunnelAttributeBackward(self):
        self.packet['Test-Tunnel-Int'] = (1, 1)
        self.assertEqual(self.packet['Test-Tunnel-Int'], [(1, 'One')])

    def testTunnelAttributeForward(self):
        self.packet['Test-Tunnel-Int'] = (1, 'Zero')
        self.assertEqual(self.packet[5], [six.b('\x01\x00\x00\x00')])
        self.assertEqual(self.packet['Test-Tunnel-Int'], [(1, 'Zero')])


class AuthPacketConstructionTests(PacketConstructionTests):
    klass = packet.AuthPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.AccessRequest)


class AuthPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(Test_Integer=10)
        self.assertEqual(reply.code, packet.AccessAccept)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testCreateReject(self):
        reply = self.packet.CreateReply(
            code=packet.AccessReject, Test_Integer=10)
        self.assertEqual(reply.code, packet.AccessReject)

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
                six.b('\x01\x00\x00\x1401234567890ABCDE'))

    def testRequestPacketCreatesAuthenticator(self):
        self.packet.authenticator = None
        self.packet.RequestPacket()
        self.failUnless(self.packet.authenticator is not None)

    def testRequestPacketCreatesID(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.failUnless(self.packet.id is not None)

    def testPwCryptEmptyPassword(self):
        self.assertEqual(self.packet.PwCrypt(''), six.b(''))

    def testPwCryptPassword(self):
        self.assertEqual(self.packet.PwCrypt('Simplon'),
                six.b('\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01'))

    def testTunnelPwCrypt(self):
        self.assertEqual(
            self.packet.TunnelPwCrypt(six.b('\x80\x01'), 'test'),
            six.b('\x80\x01:i\x0bw\x84Ys!\x99X\x8f\xde\x80n\x14\xc2'))
        self.assertEqual(
            self.packet.TunnelPwCrypt(six.b('\x80\x02'), 'verylongpassword'),
            six.b('\x80\x02\xdcb\xe9\x84\x01bf\x8f\x05G\xfe\xb4\x07\xe0(A'
                  '\x9ej\xcc\xb0:c\xe4\x9e\xad\r\xb79\xe8\xa2E~'))
        self.assertEqual(
            self.packet.TunnelPwCrypt(six.b('\x80\x03'),
                six.b('b\x01narytest')),
            six.b('\x80\x03\x12(\xaeK\xc6[gq\x1ea\xd7700$\xdc'))

    def testTunnelPwDecrypt(self):
        self.assertEqual(
            self.packet.TunnelPwDecrypt(
                six.b('\x80\x01:i\x0bw\x84Ys!\x99X\x8f\xde\x80n\x14\xc2')),
            six.u('test'))
        self.assertEqual(
            self.packet.TunnelPwDecrypt(
            six.b('\x80\x02\xdcb\xe9\x84\x01bf\x8f\x05G\xfe\xb4\x07\xe0(A'
                  '\x9ej\xcc\xb0:c\xe4\x9e\xad\r\xb79\xe8\xa2E~')),
            six.u('verylongpassword'))
        self.assertEqual(
            self.packet.TunnelPwDecrypt(
                six.b('\x80\x03\x12(\xaeK\xc6[gq\x1ea\xd7700$\xdc')),
            six.u('b\x01narytest'))

    def testPwCryptSetsAuthenticator(self):
        self.packet.authenticator = None
        self.packet.PwCrypt(six.u(''))
        self.failUnless(self.packet.authenticator is not None)

    def testPwDecryptEmptyPassword(self):
        self.assertEqual(self.packet.PwDecrypt(six.b('')), six.u(''))

    def testPwDecryptPassword(self):
        self.assertEqual(self.packet.PwDecrypt(
                six.b('\xd3U;\xb23\r\x11\xba\x07\xe3\xa8*\xa8x\x14\x01')),
                six.u('Simplon'))


class AuthPacketPasswordTest(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)
        self.packet['Test-Password'] = self.packet.PwCrypt('test')

    def testPasswordAttribute(self):
        self.assertEqual(
            self.packet['Test-Password'],
            [b'\xf4Y%\xb6_b\x7f\xba\x07\xe3\xa8*\xa8x\x14\x01'])


class AuthPacketAutoCryptTest(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.pkt = packet.AuthPacket(dict=self.dict, auto_crypt=True,
                                     secret=six.b('secret'),
                                     authenticator=six.b('01234567890ABCDEF'))

    def testConstructPassword(self):
        pkt = packet.AuthPacket(dict=self.dict, auto_crypt=True,
                                secret=six.b('secret'),
                                authenticator=six.b('01234567890ABCDEF'),
                                Test_Password=six.u('test'))
        self.assertEqual(pkt['Test-Password'], [six.u('test')])
        # Raw access to attribute does not decrypt
        self.assertEqual(
            pkt[4],
            [six.b('\xf4Y%\xb6_b\x7f\xba\x07\xe3\xa8*\xa8x\x14\x01')])

    def testSetPassword(self):
        self.pkt['Test-Password'] = six.u('test')
        self.assertEqual(self.pkt['Test-Password'], [six.u('test')])
        # Raw access to attribute does not decrypt
        self.assertEqual(
            self.pkt[4],
            [six.b('\xf4Y%\xb6_b\x7f\xba\x07\xe3\xa8*\xa8x\x14\x01')])

    def testSetRawPassword(self):
        self.pkt[4] = [six.b('\xf4Y%\xb6_b\x7f\xba\x07\xe3\xa8*\xa8x\x14\x01')]
        self.assertEqual(self.pkt['Test-Password'], [six.u('test')])

    def testAcctPacketEncryptionFailure(self):
        '''Accounting Packets are not supposed to use encryption.'''
        pkt = packet.AcctPacket(dict=self.dict, auto_crypt=True,
                                secret=six.b('secret'),
                                authenticator=six.b('01234567890ABCDEF'))
        with self.assertRaises(ValueError):
            # Encode
            pkt['Test-Password'] = six.u('test')
        pkt[4] = [six.b('0000')]  # Set raw password field
        with self.assertRaises(ValueError):
            # Decode
            pkt['Test-Password']

    def testTunnelPwDecryption(self):
        reply = self.pkt.CreateReply()
        # Set raw value
        reply[7] = \
            [six.b('\x01') + self.pkt.TunnelPwCrypt(six.b('\x80\x01'), 'test')]
        self.assertEqual(reply['Test-Tunnel-Pwd'], [(1, six.u('test'))])

    def testTunnelPwEncryption(self):
        reply = self.pkt.CreateReply()
        # Set value
        with mock.patch.object(packet.AuthPacket, 'CreateSalt') as mock_salt:
            mock_salt.return_value = six.b('\x80\x04')
            reply['Test-Tunnel-Pwd'] = (1, six.u('test'))
            mock_salt.assert_called_with()
        self.assertEqual(reply[7],
            [six.b('\x01\x80\x04<aId_\x81l!\xf6w\xbbF\x96\x0c]6')])

        # Auto-Decrypt
        self.assertEqual(reply['Test-Tunnel-Pwd'], [(1, six.u('test'))])


class TunnelPasswordTest(unittest.TestCase):
    '''Tests regarding encrypted tunnel passwords (RFC 2868).'''

    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AuthPacket(id=0, secret=six.b('secret'),
            authenticator=six.b('01234567890ABCDEF'), dict=self.dict)
        self.packet['Test-Tunnel-Pwd'] = \
            (1, self.packet.TunnelPwCrypt(six.b('\x80\x01'), 'test'))

    def testEncryptedAttribute(self):
        '''Return encrypted tunnel password as bytestring.'''
        self.assertEqual(self.packet['Test-Tunnel-Pwd'],
            [(1, six.b('\x80\x01:i\x0bw\x84Ys!\x99X\x8f\xde\x80n\x14\xc2'))])


class AcctPacketConstructionTests(PacketConstructionTests):
    klass = packet.AcctPacket

    def testConstructorDefaults(self):
        pkt = self.klass()
        self.assertEqual(pkt.code, packet.AccountingRequest)

    def testConstructorRawPacket(self):
        raw = six.b('\x00\x00\x00\x14\xb0\x5e\x4b\xfb\xcc\x1c' \
                    '\x8c\x8e\xc4\x72\xac\xea\x87\x45\x63\xa7')
        pkt = self.klass(packet=raw)
        self.assertEqual(pkt.raw_packet, raw)


class AcctPacketTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(home, 'tests', 'data')
        self.dict = Dictionary(os.path.join(self.path, 'full'))
        self.packet = packet.AcctPacket(id=0, secret=six.b('secret'),
                authenticator=six.b('01234567890ABCDEF'), dict=self.dict)

    def testCreateReply(self):
        reply = self.packet.CreateReply(Test_Integer=10)
        self.assertEqual(reply.code, packet.AccountingResponse)
        self.assertEqual(reply.id, self.packet.id)
        self.assertEqual(reply.secret, self.packet.secret)
        self.assertEqual(reply.authenticator, self.packet.authenticator)
        self.assertEqual(reply['Test-Integer'], [10])

    def testVerifyAcctRequest(self):
        rawpacket = self.packet.RequestPacket()
        pkt = packet.AcctPacket(secret=six.b('secret'), packet=rawpacket)
        self.assertEqual(pkt.VerifyAcctRequest(), True)

        pkt.secret = six.b('different')
        self.assertEqual(pkt.VerifyAcctRequest(), False)
        pkt.secret = six.b('secret')

        pkt.raw_packet = six.b('X') + pkt.raw_packet[1:]
        self.assertEqual(pkt.VerifyAcctRequest(), False)

    def testRequestPacket(self):
        self.assertEqual(self.packet.RequestPacket(),
            six.b('\x04\x00\x00\x14\x95\xdf\x90\xccbn\xfb\x15G!\x13\xea\xfa>6\x0f'))

    def testRequestPacketSetsId(self):
        self.packet.id = None
        self.packet.RequestPacket()
        self.failUnless(self.packet.id is not None)
