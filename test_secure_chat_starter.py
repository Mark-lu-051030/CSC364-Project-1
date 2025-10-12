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
from cryptography.exceptions import InvalidTag
import os
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
    def test_replay_fails_after_ratchet(self):
        # Old ciphertext should fail after receiver ratchets forward
        alice = Party("Alice")
        bob = Party("Bob")
        alice_pub = alice.get_public_bytes()
        bob_pub = bob.get_public_bytes()
        alice.establish_session(bob_pub, role="initiator")
        bob.establish_session(alice_pub, role="responder")

        first = alice.send("first")
        self.assertEqual(bob.receive(first), "first")

        second = alice.send("second")
        self.assertEqual(bob.receive(second), "second")

        with self.assertRaises(InvalidTag):
            bob.receive(first)


    def test_nonce_fresh_each_encrypt(self):
        # Two encryptions under the same key should produce different nonces
        priv_a, pub_b = generate_ecdh_key_pair()
        shared = derive_shared_secret(priv_a, pub_b)
        k = hkdf_expand(shared)

        e1 = encrypt_message(k, "one")
        e2 = encrypt_message(k, "two")
        self.assertNotEqual(e1["nonce"], e2["nonce"])


    def test_tamper_detection_ciphertext(self):
        # Flip a bit in ciphertext -> GCM should detect and raise
        priv_a, pub_b = generate_ecdh_key_pair()
        shared = derive_shared_secret(priv_a, pub_b)
        k = hkdf_expand(shared)

        enc = encrypt_message(k, "secret")
        blob = bytes.fromhex(enc["ciphertext"])
        tampered = bytearray(blob)
        tampered[0] ^= 0x01
        enc["ciphertext"] = bytes(tampered).hex()

        with self.assertRaises(InvalidTag):
            decrypt_message(k, enc)


    def test_bidirectional_independent_chains(self):
        # Alice->Bob twice, then Bob->Alice; all succeed with correct ordering
        alice = Party("Alice")
        bob = Party("Bob")
        alice_pub = alice.get_public_bytes()
        bob_pub = bob.get_public_bytes()
        alice.establish_session(bob_pub, role="initiator")
        bob.establish_session(alice_pub, role="responder")

        enc1 = alice.send("A1")
        self.assertEqual(bob.receive(enc1), "A1")

        enc2 = alice.send("A2")
        self.assertEqual(bob.receive(enc2), "A2")

        enc3 = bob.send("B1")
        self.assertEqual(alice.receive(enc3), "B1")


    def test_wrong_key_fails(self):
        # Decrypting with an unrelated key should fail
        priv1, pub1 = generate_ecdh_key_pair()
        priv2, pub2 = generate_ecdh_key_pair()
        shared1 = derive_shared_secret(priv1, pub2)
        shared2 = derive_shared_secret(priv2, pub1)

        k1 = hkdf_expand(shared1)
        k_wrong = hkdf_expand(os.urandom(48))

        enc = encrypt_message(k1, "msg")
        with self.assertRaises(InvalidTag):
            decrypt_message(k_wrong, enc)

if __name__ == "__main__":
    unittest.main()
