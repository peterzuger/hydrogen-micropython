import sys
import unittest
import hydrogen

UINT32_MAX = (2 ** 32) - 1
UINT16_MAX = (2 ** 16) - 1

TEST_CONTEXT = "EXAMPLES"
TEST_DATA = "abcdefghijklmnopqrstuvwxyz"


class HydrogenTest(unittest.TestCase):
    def test_random_u32(self):
        # random_u32()

        for _ in range(UINT16_MAX):
            r = hydrogen.random_u32()

            self.assertTrue(0 <= r <= UINT32_MAX)
            self.assertIsInstance(r, int)

    def test_random_uniform(self):
        # random_uniform(upper_bound)

        for upper_bound in range(0, UINT32_MAX, UINT16_MAX):
            r = hydrogen.random_uniform(upper_bound)

            self.assertTrue(0 <= r <= upper_bound)
            self.assertIsInstance(r, int)

    def test_random_buf(self):
        # random_buf(len)

        for l in range(1024):
            r = hydrogen.random_buf(l)

            self.assertEqual(l, len(r))
            self.assertIsInstance(r, bytes)

    def test_random_ratchet(self):
        # random_ratchet()

        hydrogen.random_ratchet()

    def test_random_reseed(self):
        # random_reseed()

        hydrogen.random_reseed()

    def test_hash_hash(self):
        # hydrogen.hash_hash(context, data, key=None[, hash_size])

        # no key

        h = hydrogen.hash_hash(TEST_CONTEXT, TEST_DATA)

        self.assertEqual(hydrogen.hash_BYTES, len(h))
        self.assertIsInstance(h, bytes)

        # with key

        key = hydrogen.hash_keygen()

        h = hydrogen.hash_hash(TEST_CONTEXT, TEST_DATA, key)

        self.assertEqual(hydrogen.hash_BYTES, len(h))
        self.assertIsInstance(h, bytes)

    def test_hash_keygen(self):
        # hash_keygen()

        key = hydrogen.hash_keygen()

        self.assertEqual(hydrogen.hash_BYTES, len(key))
        self.assertIsInstance(key, bytes)

    def test_kdf_keygen(self):
        # kdf_keygen()

        key = hydrogen.kdf_keygen()

        self.assertEqual(hydrogen.kdf_KEYBYTES, len(key))
        self.assertIsInstance(key, bytes)

    def test_kdf_derive_from_key(self):
        # kdf_derive_from_key(context, master_key, subkey_id[, subkey_len])

        master = hydrogen.kdf_keygen()

        for i in range(256):
            skey = hydrogen.kdf_derive_from_key(TEST_CONTEXT, master, i)

            self.assertEqual(hydrogen.kdf_KEYBYTES, len(skey))
            self.assertIsInstance(skey, bytes)

    def test_sign_keygen(self):
        # sign_keygen()

        pub, pri = hydrogen.sign_keygen()

        self.assertNotEqual(pub, pri)
        self.assertIsInstance(pub, bytes)
        self.assertIsInstance(pri, bytes)

    def test_secretbox_keygen(self):
        # secretbox_keygen()

        key = hydrogen.secretbox_keygen()

        self.assertEqual(hydrogen.secretbox_KEYBYTES, len(key))
        self.assertIsInstance(key, bytes)

    def test_secretbox_encrypt(self):
        # secretbox_encrypt(context, key, msg[, msg_id])

        key = hydrogen.secretbox_keygen()

        cipher0 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)
        cipher1 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA, 1)

        self.assertNotEqual(cipher0, cipher1)
        self.assertIsInstance(cipher0, bytes)
        self.assertIsInstance(cipher1, bytes)

    def test_secretbox_decrypt(self):
        # secretbox_decrypt(context, key, ciphertext[, msg_id])

        key = hydrogen.secretbox_keygen()

        cipher0 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)
        cipher1 = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA, 1)

        msg0 = hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher0)
        msg1 = hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher1, 1)

        self.assertEqual(msg0, msg1)
        self.assertEqual(msg0, TEST_DATA.encode("utf-8"))
        self.assertIsInstance(msg0, bytes)
        self.assertIsInstance(msg1, bytes)

        with self.assertRaises(RuntimeError) as _:
            hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher0, 1)

        with self.assertRaises(RuntimeError) as _:
            hydrogen.secretbox_decrypt(TEST_CONTEXT, key, cipher1)

    def test_secretbox_probe_create(self):
        # secretbox_probe_create(context, key, ciphertext)

        key = hydrogen.secretbox_keygen()

        cipher = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)

        probe = hydrogen.secretbox_probe_create(TEST_CONTEXT, key, cipher)

        self.assertTrue(bool(probe))
        self.assertIsInstance(probe, bytes)

    def test_secretbox_probe_verify(self):
        # secretbox_decrypt(context, key, ciphertext, probe)

        key = hydrogen.secretbox_keygen()

        cipher = hydrogen.secretbox_encrypt(TEST_CONTEXT, key, TEST_DATA)

        probe = hydrogen.secretbox_probe_create(TEST_CONTEXT, key, cipher)

        verified = hydrogen.secretbox_probe_verify(TEST_CONTEXT, key, cipher, probe)

        self.assertIsInstance(verified, bool)
        self.assertTrue(verified)

    def test_hash(self):
        # Hash(context, key=None)
        # .update(data)
        # .final([hash_size])

        # no key

        h = hydrogen.Hash(TEST_CONTEXT, None)
        for _ in range(256):
            h.update(TEST_DATA)
        f = h.final()

        self.assertEqual(hydrogen.hash_BYTES, len(f))
        self.assertIsInstance(f, bytes)

        # with key

        key = hydrogen.hash_keygen()

        h = hydrogen.Hash(TEST_CONTEXT, key)
        for _ in range(256):
            h.update(TEST_DATA)
        f = h.final()

        self.assertEqual(hydrogen.hash_BYTES, len(f))
        self.assertIsInstance(f, bytes)

    def test_Sign(self):
        # Sign(context)
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
        verified = s.final_verify(signature, pub)

        self.assertIsInstance(verified, bool)
        self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
