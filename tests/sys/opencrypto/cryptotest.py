#!/usr/local/bin/python2
#
# Copyright (c) 2014 The FreeBSD Foundation
# All rights reserved.
#
# This software was developed by John-Mark Gurney under
# the sponsorship from the FreeBSD Foundation.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

from __future__ import print_function
import errno
import cryptodev
import itertools
import os
import struct
import unittest
from cryptodev import *
from glob import iglob

katdir = '/usr/local/share/nist-kat'

def katg(base, glob):
    assert os.path.exists(katdir), "Please 'pkg install nist-kat'"
    if not os.path.exists(os.path.join(katdir, base)):
        raise unittest.SkipTest("Missing %s test vectors" % (base))
    return iglob(os.path.join(katdir, base, glob))

aesmodules = [ 'cryptosoft0', 'aesni0', 'ccr0', 'ccp0' ]
desmodules = [ 'cryptosoft0', ]
shamodules = [ 'cryptosoft0', 'aesni0', 'ccr0', 'ccp0' ]

def GenTestCase(cname):
    try:
        crid = cryptodev.Crypto.findcrid(cname)
    except IOError:
        return None

    class GendCryptoTestCase(unittest.TestCase):
        ###############
        ##### AES #####
        ###############
        @unittest.skipIf(cname not in aesmodules, 'skipping AES-XTS on %s' % (cname))
        def test_xts(self):
            for i in katg('XTSTestVectors/format tweak value input - data unit seq no', '*.rsp'):
                self.runXTS(i, cryptodev.CRYPTO_AES_XTS)

        @unittest.skipIf(cname not in aesmodules, 'skipping AES-CBC on %s' % (cname))
        def test_cbc(self):
            for i in katg('KAT_AES', 'CBC[GKV]*.rsp'):
                self.runCBC(i)

        @unittest.skipIf(cname not in aesmodules, 'skipping AES-CCM on %s' % (cname))
        def test_ccm(self):
            for i in katg('ccmtestvectors', 'V*.rsp'):
                self.runCCMEncrypt(i)

            for i in katg('ccmtestvectors', 'D*.rsp'):
                self.runCCMDecrypt(i)

        @unittest.skipIf(cname not in aesmodules, 'skipping AES-GCM on %s' % (cname))
        def test_gcm(self):
            for i in katg('gcmtestvectors', 'gcmEncrypt*'):
                self.runGCM(i, 'ENCRYPT')

            for i in katg('gcmtestvectors', 'gcmDecrypt*'):
                self.runGCM(i, 'DECRYPT')

        _gmacsizes = { 32: cryptodev.CRYPTO_AES_256_NIST_GMAC,
            24: cryptodev.CRYPTO_AES_192_NIST_GMAC,
            16: cryptodev.CRYPTO_AES_128_NIST_GMAC,
        }
        def runGCM(self, fname, mode):
            curfun = None
            if mode == 'ENCRYPT':
                swapptct = False
                curfun = Crypto.encrypt
            elif mode == 'DECRYPT':
                swapptct = True
                curfun = Crypto.decrypt
            else:
                raise RuntimeError('unknown mode: %r' % repr(mode))

            for bogusmode, lines in cryptodev.KATParser(fname,
                [ 'Count', 'Key', 'IV', 'CT', 'AAD', 'Tag', 'PT', ]):
                for data in lines:
                    curcnt = int(data['Count'])
                    cipherkey = data['Key'].decode('hex')
                    iv = data['IV'].decode('hex')
                    aad = data['AAD'].decode('hex')
                    tag = data['Tag'].decode('hex')
                    if 'FAIL' not in data:
                        pt = data['PT'].decode('hex')
                    ct = data['CT'].decode('hex')

                    if len(iv) != 12:
                        # XXX - isn't supported
                        continue

                    try:
                        c = Crypto(cryptodev.CRYPTO_AES_NIST_GCM_16,
                            cipherkey,
                            mac=self._gmacsizes[len(cipherkey)],
                            mackey=cipherkey, crid=crid,
                            maclen=16)
                    except EnvironmentError as e:
                        # Can't test algorithms the driver does not support.
                        if e.errno != errno.EOPNOTSUPP:
                            raise
                        continue

                    if mode == 'ENCRYPT':
                        try:
                            rct, rtag = c.encrypt(pt, iv, aad)
                        except EnvironmentError as e:
                            # Can't test inputs the driver does not support.
                            if e.errno != errno.EINVAL:
                                raise
                            continue
                        rtag = rtag[:len(tag)]
                        data['rct'] = rct.encode('hex')
                        data['rtag'] = rtag.encode('hex')
                        self.assertEqual(rct, ct, repr(data))
                        self.assertEqual(rtag, tag, repr(data))
                    else:
                        if len(tag) != 16:
                            continue
                        args = (ct, iv, aad, tag)
                        if 'FAIL' in data:
                            self.assertRaises(IOError,
                                c.decrypt, *args)
                        else:
                            try:
                                rpt, rtag = c.decrypt(*args)
                            except EnvironmentError as e:
                                # Can't test inputs the driver does not support.
                                if e.errno != errno.EINVAL:
                                    raise
                                continue
                            data['rpt'] = rpt.encode('hex')
                            data['rtag'] = rtag.encode('hex')
                            self.assertEqual(rpt, pt,
                                repr(data))

        def runCBC(self, fname):
            curfun = None
            for mode, lines in cryptodev.KATParser(fname,
                [ 'COUNT', 'KEY', 'IV', 'PLAINTEXT', 'CIPHERTEXT', ]):
                if mode == 'ENCRYPT':
                    swapptct = False
                    curfun = Crypto.encrypt
                elif mode == 'DECRYPT':
                    swapptct = True
                    curfun = Crypto.decrypt
                else:
                    raise RuntimeError('unknown mode: %r' % repr(mode))

                for data in lines:
                    curcnt = int(data['COUNT'])
                    cipherkey = data['KEY'].decode('hex')
                    iv = data['IV'].decode('hex')
                    pt = data['PLAINTEXT'].decode('hex')
                    ct = data['CIPHERTEXT'].decode('hex')

                    if swapptct:
                        pt, ct = ct, pt
                    # run the fun
                    c = Crypto(cryptodev.CRYPTO_AES_CBC, cipherkey, crid=crid)
                    r = curfun(c, pt, iv)
                    self.assertEqual(r, ct)

        def runXTS(self, fname, meth):
            curfun = None
            for mode, lines in cryptodev.KATParser(fname,
                [ 'COUNT', 'DataUnitLen', 'Key', 'DataUnitSeqNumber', 'PT',
                'CT' ]):
                if mode == 'ENCRYPT':
                    swapptct = False
                    curfun = Crypto.encrypt
                elif mode == 'DECRYPT':
                    swapptct = True
                    curfun = Crypto.decrypt
                else:
                    raise RuntimeError('unknown mode: %r' % repr(mode))

                for data in lines:
                    curcnt = int(data['COUNT'])
                    nbits = int(data['DataUnitLen'])
                    cipherkey = data['Key'].decode('hex')
                    iv = struct.pack('QQ', int(data['DataUnitSeqNumber']), 0)
                    pt = data['PT'].decode('hex')
                    ct = data['CT'].decode('hex')

                    if nbits % 128 != 0:
                        # XXX - mark as skipped
                        continue
                    if swapptct:
                        pt, ct = ct, pt
                    # run the fun
                    try:
                        c = Crypto(meth, cipherkey, crid=crid)
                        r = curfun(c, pt, iv)
                    except EnvironmentError as e:
                        # Can't test hashes the driver does not support.
                        if e.errno != errno.EOPNOTSUPP:
                            raise
                        continue
                    self.assertEqual(r, ct)

        def runCCMEncrypt(self, fname):
            for data in cryptodev.KATCCMParser(fname):
                Nlen = int(data['Nlen'])
                if Nlen != 12:
                    # OCF only supports 12 byte IVs
                    continue
                key = data['Key'].decode('hex')
                nonce = data['Nonce'].decode('hex')
                Alen = int(data['Alen'])
                if Alen != 0:
                    aad = data['Adata'].decode('hex')
                else:
                    aad = None
                payload = data['Payload'].decode('hex')
                ct = data['CT'].decode('hex')

                try:
                    c = Crypto(crid=crid,
                        cipher=cryptodev.CRYPTO_AES_CCM_16,
                        key=key,
                        mac=cryptodev.CRYPTO_AES_CCM_CBC_MAC,
                        mackey=key, maclen=16)
                    r, tag = Crypto.encrypt(c, payload,
                        nonce, aad)
                except EnvironmentError as e:
                    if e.errno != errno.EOPNOTSUPP:
                        raise
                    continue

                out = r + tag
                self.assertEqual(out, ct,
                    "Count " + data['Count'] + " Actual: " + \
                    repr(out.encode("hex")) + " Expected: " + \
                    repr(data) + " on " + cname)

        def runCCMDecrypt(self, fname):
            # XXX: Note that all of the current CCM
            # decryption test vectors use IV and tag sizes
            # that aren't supported by OCF none of the
            # tests are actually ran.
            for data in cryptodev.KATCCMParser(fname):
                Nlen = int(data['Nlen'])
                if Nlen != 12:
                    # OCF only supports 12 byte IVs
                    continue
                Tlen = int(data['Tlen'])
                if Tlen != 16:
                    # OCF only supports 16 byte tags
                    continue
                key = data['Key'].decode('hex')
                nonce = data['Nonce'].decode('hex')
                Alen = int(data['Alen'])
                if Alen != 0:
                    aad = data['Adata'].decode('hex')
                else:
                    aad = None
                ct = data['CT'].decode('hex')
                tag = ct[-16:]
                ct = ct[:-16]

                try:
                    c = Crypto(crid=crid,
                        cipher=cryptodev.CRYPTO_AES_CCM_16,
                        key=key,
                        mac=cryptodev.CRYPTO_AES_CCM_CBC_MAC,
                        mackey=key, maclen=16)
                except EnvironmentError as e:
                    if e.errno != errno.EOPNOTSUPP:
                        raise
                    continue

                if data['Result'] == 'Fail':
                    self.assertRaises(IOError,
                        c.decrypt, payload, nonce, aad, tag)
                else:
                    r = Crypto.decrypt(c, payload, nonce,
                        aad, tag)

                    payload = data['Payload'].decode('hex')
                    plen = int(data('Plen'))
                    payload = payload[:plen]
                    self.assertEqual(r, payload,
                        "Count " + data['Count'] + \
                        " Actual: " + repr(r.encode("hex")) + \
                        " Expected: " + repr(data) + \
                        " on " + cname)

        ###############
        ##### DES #####
        ###############
        @unittest.skipIf(cname not in desmodules, 'skipping DES on %s' % (cname))
        def test_tdes(self):
            for i in katg('KAT_TDES', 'TCBC[a-z]*.rsp'):
                self.runTDES(i)

        def runTDES(self, fname):
            curfun = None
            for mode, lines in cryptodev.KATParser(fname,
                [ 'COUNT', 'KEYs', 'IV', 'PLAINTEXT', 'CIPHERTEXT', ]):
                if mode == 'ENCRYPT':
                    swapptct = False
                    curfun = Crypto.encrypt
                elif mode == 'DECRYPT':
                    swapptct = True
                    curfun = Crypto.decrypt
                else:
                    raise RuntimeError('unknown mode: %r' % repr(mode))

                for data in lines:
                    curcnt = int(data['COUNT'])
                    key = data['KEYs'] * 3
                    cipherkey = key.decode('hex')
                    iv = data['IV'].decode('hex')
                    pt = data['PLAINTEXT'].decode('hex')
                    ct = data['CIPHERTEXT'].decode('hex')

                    if swapptct:
                        pt, ct = ct, pt
                    # run the fun
                    c = Crypto(cryptodev.CRYPTO_3DES_CBC, cipherkey, crid=crid)
                    r = curfun(c, pt, iv)
                    self.assertEqual(r, ct)

        ###############
        ##### SHA #####
        ###############
        @unittest.skipIf(cname not in shamodules, 'skipping SHA on %s' % str(cname))
        def test_sha(self):
            for i in katg('shabytetestvectors', 'SHA*Msg.rsp'):
                self.runSHA(i)

        def runSHA(self, fname):
            # Skip SHA512_(224|256) tests
            if fname.find('SHA512_') != -1:
                return

            for hashlength, lines in cryptodev.KATParser(fname,
                [ 'Len', 'Msg', 'MD' ]):
                # E.g., hashlength will be "L=20" (bytes)
                hashlen = int(hashlength.split("=")[1])

                if hashlen == 20:
                    alg = cryptodev.CRYPTO_SHA1
                elif hashlen == 28:
                    alg = cryptodev.CRYPTO_SHA2_224
                elif hashlen == 32:
                    alg = cryptodev.CRYPTO_SHA2_256
                elif hashlen == 48:
                    alg = cryptodev.CRYPTO_SHA2_384
                elif hashlen == 64:
                    alg = cryptodev.CRYPTO_SHA2_512
                else:
                    # Skip unsupported hashes
                    # Slurp remaining input in section
                    for data in lines:
                        continue
                    continue

                for data in lines:
                    msg = data['Msg'].decode('hex')
                    msg = msg[:int(data['Len'])]
                    md = data['MD'].decode('hex')

                    try:
                        c = Crypto(mac=alg, crid=crid,
                            maclen=hashlen)
                    except EnvironmentError as e:
                        # Can't test hashes the driver does not support.
                        if e.errno != errno.EOPNOTSUPP:
                            raise
                        continue

                    _, r = c.encrypt(msg, iv="")

                    self.assertEqual(r, md, "Actual: " + \
                        repr(r.encode("hex")) + " Expected: " + repr(data) + " on " + cname)

        @unittest.skipIf(cname not in shamodules, 'skipping SHA-HMAC on %s' % str(cname))
        def test_sha1hmac(self):
            for i in katg('hmactestvectors', 'HMAC.rsp'):
                self.runSHA1HMAC(i)

        def runSHA1HMAC(self, fname):
            for hashlength, lines in cryptodev.KATParser(fname,
                [ 'Count', 'Klen', 'Tlen', 'Key', 'Msg', 'Mac' ]):
                # E.g., hashlength will be "L=20" (bytes)
                hashlen = int(hashlength.split("=")[1])

                blocksize = None
                if hashlen == 20:
                    alg = cryptodev.CRYPTO_SHA1_HMAC
                    blocksize = 64
                elif hashlen == 28:
                    alg = cryptodev.CRYPTO_SHA2_224_HMAC
                    blocksize = 64
                elif hashlen == 32:
                    alg = cryptodev.CRYPTO_SHA2_256_HMAC
                    blocksize = 64
                elif hashlen == 48:
                    alg = cryptodev.CRYPTO_SHA2_384_HMAC
                    blocksize = 128
                elif hashlen == 64:
                    alg = cryptodev.CRYPTO_SHA2_512_HMAC
                    blocksize = 128
                else:
                    # Skip unsupported hashes
                    # Slurp remaining input in section
                    for data in lines:
                        continue
                    continue

                for data in lines:
                    key = data['Key'].decode('hex')
                    msg = data['Msg'].decode('hex')
                    mac = data['Mac'].decode('hex')
                    tlen = int(data['Tlen'])

                    if len(key) > blocksize:
                        continue

                    try:
                        c = Crypto(mac=alg, mackey=key,
                            crid=crid, maclen=hashlen)
                    except EnvironmentError as e:
                        # Can't test hashes the driver does not support.
                        if e.errno != errno.EOPNOTSUPP:
                            raise
                        continue

                    _, r = c.encrypt(msg, iv="")

                    self.assertEqual(r[:tlen], mac, "Actual: " + \
                        repr(r.encode("hex")) + " Expected: " + repr(data))

    return GendCryptoTestCase

cryptosoft = GenTestCase('cryptosoft0')
aesni = GenTestCase('aesni0')
ccr = GenTestCase('ccr0')
ccp = GenTestCase('ccp0')

if __name__ == '__main__':
    unittest.main()
