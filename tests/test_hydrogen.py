import sys
import unittest
import hydrogen

UINT32_MAX = (2**32) - 1
UINT16_MAX = (2**16) - 1

TEST_CONTEXT = "EXAMPLES"
TEST_DATA = "abcdefghijklmnopqrstuvwxyz"


class HydrogenTest(unittest.TestCase):
    def test_init(self):
        # hydrogen.init()

        hydrogen.init()

    def test_version(self):
        # hydrogen.version

        self.assertIsInstance(hydrogen.version, tuple)
        self.assertIsInstance(hydrogen.version[0], int)
        self.assertIsInstance(hydrogen.version[1], int)

    def test_random_u32(self):
        # hydrogen.random_u32()

        for _ in range(UINT16_MAX):
            r = hydrogen.random_u32()

            self.assertIsInstance(r, int)
            self.assertTrue(0 <= r <= UINT32_MAX)

    def test_random_uniform(self):
        # hydrogen.random_uniform(upper_bound)

        for upper_bound in range(0, UINT32_MAX, UINT16_MAX):
            r = hydrogen.random_uniform(upper_bound)

            self.assertIsInstance(r, int)
            self.assertTrue(0 <= r <= upper_bound)

    def test_random_buf(self):
        # hydrogen.random_buf(len)

        for l in range(1024):
            r = hydrogen.random_buf(l)

            self.assertEqual(l, len(r))
            self.assertIsInstance(r, bytes)

    def test_random_ratchet(self):
        # hydrogen.random_ratchet()

        hydrogen.random_ratchet()

    def test_random_reseed(self):
        # hydrogen.random_reseed()

        hydrogen.random_reseed()

    def test_hash_hash(self):
        # hydrogen.hash_hash(context, data, key=None[, hash_size])

        # no key

        h = hydrogen.hash_hash(TEST_CONTEXT, TEST_DATA)

        self.assertIsInstance(h, bytes)
        self.assertEqual(hydrogen.hash_BYTES, len(h))

        # with key

        key = hydrogen.hash_keygen()

        h = hydrogen.hash_hash(TEST_CONTEXT, TEST_DATA, key)

        self.assertIsInstance(h, bytes)
        self.assertEqual(hydrogen.hash_BYTES, len(h))

    def test_hash_keygen(self):
        # hydrogen.hash_keygen()

        key = hydrogen.hash_keygen()

        self.assertIsInstance(key, bytes)
        self.assertEqual(hydrogen.hash_KEYBYTES, len(key))

    def test_kdf_keygen(self):
        # hydrogen.kdf_keygen()

        key = hydrogen.kdf_keygen()

        self.assertIsInstance(key, bytes)
        self.assertEqual(hydrogen.kdf_KEYBYTES, len(key))

    def test_kdf_derive_from_key(self):
        # hydrogen.kdf_derive_from_key(context, master_key, subkey_id[, subkey_len])

        master = hydrogen.kdf_keygen()

        for i in range(256):
            skey = hydrogen.kdf_derive_from_key(TEST_CONTEXT, master, i)

            self.assertIsInstance(skey, bytes)
            self.assertEqual(hydrogen.kdf_KEYBYTES, len(skey))

    def test_sign_keygen(self):
        # hydrogen.sign_keygen()

        pub, pri = hydrogen.sign_keygen()

        self.assertNotEqual(pub, pri)
        self.assertIsInstance(pub, bytes)
        self.assertIsInstance(pri, bytes)

    def test_secretbox_keygen(self):
        # hydrogen.secretbox_keygen()

        key = hydrogen.secretbox_keygen()

        self.assertIsInstance(key, bytes)
        self.assertEqual(hydrogen.secretbox_KEYBYTES, len(key))

    def test_secretbox_encrypt(self):
        # hydrogen.secretbox_encrypt(context, key, msg[, msg_id])

        key = hydrogen.secretbox_keygen()

        cipher0 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)
        cipher1 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA, 1)

        self.assertNotEqual(cipher0, cipher1)
        self.assertIsInstance(cipher0, bytes)
        self.assertIsInstance(cipher1, bytes)

    def test_secretbox_decrypt(self):
        # hydrogen.secretbox_decrypt(context, key, ciphertext[, msg_id])

        key = hydrogen.secretbox_keygen()

        cipher0 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)
        cipher1 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA, 1)

        msg0 = hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher0)
        msg1 = hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher1, 1)

        self.assertEqual(msg0, msg1)
        self.assertIsInstance(msg0, bytes)
        self.assertEqual(len(TEST_DATA), len(msg0))
        self.assertIsInstance(msg1, bytes)
        self.assertEqual(len(TEST_DATA), len(msg1))
        self.assertEqual(msg0, TEST_DATA.encode("utf-8"))

        with self.assertRaises(RuntimeError) as _:
            hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher0, 1)

        with self.assertRaises(RuntimeError) as _:
            hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher1)

    def test_secretbox_probe_create(self):
        # hydrogen.secretbox_probe_create(context, key, ciphertext)

        key = hydrogen.secretbox_keygen()

        cipher = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)

        probe = hydrogen.secretbox_probe_create(TEST_CONTEXT, key, cipher)

        self.assertIsInstance(probe, bytes)
        self.assertTrue(bool(probe))

    def test_secretbox_probe_verify(self):
        # hydrogen.secretbox_probe_verify(context, key, ciphertext, probe)

        key = hydrogen.secretbox_keygen()

        cipher = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)

        probe = hydrogen.secretbox_probe_create(TEST_CONTEXT, key, cipher)

        verified = hydrogen.secretbox_probe_verify(TEST_CONTEXT, key, cipher, probe)

        self.assertIsInstance(verified, bool)
        self.assertTrue(verified)

    def test_Hash(self):
        # hydrogen.Hash(context, key=None)
        # .update(data)
        # .final([hash_size])

        # no key

        h = hydrogen.Hash(TEST_CONTEXT, None)
        for _ in range(256):
            h.update(TEST_DATA)
        f = h.final()

        self.assertIsInstance(f, bytes)
        self.assertEqual(hydrogen.hash_BYTES, len(f))

        # with key

        key = hydrogen.hash_keygen()

        h = hydrogen.Hash(TEST_CONTEXT, key)
        for _ in range(256):
            h.update(TEST_DATA)
        f = h.final()

        self.assertIsInstance(f, bytes)
        self.assertEqual(hydrogen.hash_BYTES, len(f))

    def test_Sign(self):
        # hydrogen.Sign(context)
        # .update(data)
        # .final_create(key)
        # .final_verify(signature, key)

        pub, pri = hydrogen.sign_keygen()

        s = hydrogen.Sign(TEST_CONTEXT)
        for _ in range(256):
            s.update(TEST_DATA)
        signature = s.final_create(pri)

        self.assertIsInstance(signature, bytes)

        s = hydrogen.Sign(TEST_CONTEXT)
        for _ in range(256):
            s.update(TEST_DATA)
        verified = s.final_verify(pub, signature)

        self.assertIsInstance(verified, bool)
        self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
