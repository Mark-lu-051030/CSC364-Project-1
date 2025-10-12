# This is the starter test file for CSC 364 - Foundations of Computer Security 
# Project 1 - Secure Messaging System
# 
# In order to execute this file, you need to run the commands below to install
# the 'cryptography' python library:
#
# python3 -m venv path/to/venv
# source path/to/venv/bin/activate
# python3 -m pip install cryptography
#
# To run this file:
# python3 test_secure_chat_starter.py
#
# Notes for Students
# - You will need to make the establish_session, send, and receive methods
#   functional for the tests to pass.
# - The test_forward_secrecy_hint() is just a placeholder hint for an extension.

import unittest
from secure_chat_starter import (
    generate_ecdh_key_pair,
    derive_shared_secret,
    hkdf_expand,
    encrypt_message,
    decrypt_message,
    ratchet_key,
    Party,
)

class TestSecureChatStarter(unittest.TestCase):
    def test_ecdh_shared_secret_matches(self):
        priv_a, pub_a = generate_ecdh_key_pair()
        priv_b, pub_b = generate_ecdh_key_pair()

        shared_a = derive_shared_secret(priv_a, pub_b)
        shared_b = derive_shared_secret(priv_b, pub_a)

        key_a = hkdf_expand(shared_a)
        key_b = hkdf_expand(shared_b)

        self.assertEqual(key_a, key_b)

    def test_encrypt_decrypt_round_trip(self):
        priv_a, pub_a = generate_ecdh_key_pair()
        priv_b, pub_b = generate_ecdh_key_pair()
        shared = derive_shared_secret(priv_a, pub_b)
        key = hkdf_expand(shared)

        plaintext = "Test message"
        encrypted = encrypt_message(key, plaintext)
        decrypted = decrypt_message(key, encrypted)

        self.assertEqual(decrypted, plaintext)

    # TODO: add more tests (at least 5)

if __name__ == "__main__":
    unittest.main()
