"""Мінімальні тести коректності. Запуск: python -m unittest -v tests/test_roundtrip.py"""
import os, sys, tempfile, unittest, secrets
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_aes import MODES, IntegrityError
from key_manager import KeyManager, KeyPolicyError, WrongPasswordError
from tamper_demo import tamper

PWD = 'Test-Password-123'


def rd(path):
    with open(path, 'rb') as f:
        return f.read()


class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.src = os.path.join(self.d, 'plain.bin')
        with open(self.src, 'wb') as f:
            f.write(secrets.token_bytes(3 * 1024 * 1024 + 5))   # не кратно блоку
        self.km = KeyManager(os.path.join(self.d, 'ks.json'))
        self.meta = self.km.new_key('t', PWD)
        _, self.k, self.mk = self.km.derive_keypair('t', PWD)

    def tearDown(self):
        self.tmp.cleanup()

    def p(self, name):
        return os.path.join(self.d, name)

    def test_roundtrip_all_modes(self):
        for mode, m in MODES.items():
            with self.subTest(mode=mode):
                m['encrypt'](self.src, self.p('e'), self.k, self.mk)
                m['decrypt'](self.p('e'), self.p('d'), self.k, self.mk)
                self.assertEqual(rd(self.src), rd(self.p('d')))

    def test_random_iv_nonce(self):
        for mode, m in MODES.items():
            with self.subTest(mode=mode):
                m['encrypt'](self.src, self.p('e1'), self.k, self.mk)
                m['encrypt'](self.src, self.p('e2'), self.k, self.mk)
                self.assertNotEqual(rd(self.p('e1')), rd(self.p('e2')))

    def test_tamper_detected(self):
        for mode, m in MODES.items():
            targets = ['ciphertext', 'tag', 'header'] + (['iv'] if mode == 'cbc' else [])
            for t in targets:
                with self.subTest(mode=mode, target=t):
                    m['encrypt'](self.src, self.p('e'), self.k, self.mk)
                    bad = tamper(self.p('e'), t, self.p('bad'), quiet=True)
                    with self.assertRaises(Exception):
                        m['decrypt'](bad, self.p('d2'), self.k, self.mk)
                    self.assertFalse(os.path.exists(self.p('d2')))   # вихідний файл не створено

    def test_aad_mismatch(self):
        m = MODES['gcm']
        m['encrypt'](self.src, self.p('e'), self.k, aad=b'user=alice')
        with self.assertRaises(IntegrityError):
            m['decrypt'](self.p('e'), self.p('d'), self.k, aad=b'user=bob')

    def test_wrong_password(self):
        with self.assertRaises(WrongPasswordError):
            self.km.derive_keypair('t', 'Wrong-Password-1')

    def test_key_policy(self):
        with self.assertRaises(KeyPolicyError):
            self.km.new_key('t', PWD)                 # повторна мітка
        with self.assertRaises(KeyPolicyError):
            self.km.new_key('short', 'short')         # короткий пароль
        with self.assertRaises(KeyPolicyError):
            self.km.new_key('bits', PWD, key_bits=100)
        self.km.revoke(label='t')
        with self.assertRaises(KeyPolicyError):
            self.km.check_can_encrypt(self.meta)      # відкликаний ключ

    def test_key_lengths(self):
        for bits in (128, 192, 256):
            with self.subTest(bits=bits):
                self.km.new_key(f'k{bits}', PWD, key_bits=bits)
                _, k, _ = self.km.derive_keypair(f'k{bits}', PWD)
                self.assertEqual(len(k) * 8, bits)


if __name__ == '__main__':
    unittest.main()
