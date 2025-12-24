import unittest
import os
import json
import shutil
from sftss import generate_rsa_keypair, rsa_encrypt_int, rsa_decrypt_int, int_to_bytes, int_from_bytes, xor_bytes, generate_random_xor_key, sha256_hex

class TestSFTSS(unittest.TestCase):
    def test_rsa_key_generation(self):
        """Test that RSA key generation always produces valid keys."""
        for _ in range(5):  # Run fewer times as large prime generation is slower
            n, e, d = generate_rsa_keypair()
            self.assertIsNotNone(n)
            self.assertIsNotNone(e)
            self.assertIsNotNone(d)
            self.assertTrue(n > 0)
            self.assertTrue(e > 0)
            self.assertTrue(d > 0)
            
            # Test encryption/decryption with generated keys
            msg = 12345
            if msg >= n: continue # Skip if n is too small for this msg (unlikely with 100-400 primes but possible)
            
            c = rsa_encrypt_int(msg, e, n)
            m = rsa_decrypt_int(c, d, n)
            self.assertEqual(msg, m, f"RSA failed for n={n}, e={e}, d={d}")

    def test_xor_encryption(self):
        """Test XOR encryption and decryption."""
        data = b"Hello World"
        key = generate_random_xor_key(len(data))
        encrypted = xor_bytes(data, key)
        decrypted = xor_bytes(encrypted, key)
        self.assertEqual(data, decrypted)

    def test_full_flow_simulation(self):
        """Simulate the full encryption/decryption flow."""
        # 1. Generate keys for a receiver
        n, e, d = generate_rsa_keypair()
        
        # 2. Sender encrypts file (simulated)
        data = b"Secret File Content"
        xor_key = generate_random_xor_key()
        ciphertext = xor_bytes(data, xor_key)
        
        # Encrypt XOR key with RSA
        enc_key_int = rsa_encrypt_int(int_from_bytes(xor_key), e, n)
        enc_key_bytes = int_to_bytes(enc_key_int)
        
        # 3. Receiver decrypts
        dec_key_int = rsa_decrypt_int(int_from_bytes(enc_key_bytes), d, n)
        dec_xor_key = int_to_bytes(dec_key_int, length=16)
        
        decrypted_data = xor_bytes(ciphertext, dec_xor_key)
        self.assertEqual(data, decrypted_data)

if __name__ == '__main__':
    unittest.main()
