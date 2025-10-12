# This is the starter file for CSC 364 - Foundations of Computer Security 
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
# python3 secure_chat_starter.py
#

import os
import json
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------
# Key Generation and Utilities
# ------------------------------

# Use the ECDH key exchange
def generate_ecdh_key_pair():
    """
    TODO: Generates an ephemeral ECDH key pair.
          generate private key with ec.SECP384R1()
    """
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Serializes a public key to PEM format for sharing.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """
    Deserializes a PEM-formatted public key.
    """
    return serialization.load_pem_public_key(pem_bytes)

def derive_shared_secret(private_key, peer_public_key):
    """
    TODO: Computes the ECDH shared secret between private and peer public key.
    """
    return shared_secret

def hkdf_expand(secret, info=b'secure chat'):
    """
    TODO: Derives a 256-bit symmetric key from a shared secret using HKDF.
          You should use SHA256 algorithm
          with length = 32
          with salt = None
          with info = info
    """
    return symmetric_key

def ratchet_key(old_key):
    """
    TODO: Derives a new session key from the previous key (symmetric ratcheting) 
          using hkdf_expand function with info 'ratchet-step'
    """
    return new_session_key

# ------------------------------
# Encryption and Decryption
# ------------------------------

def encrypt_message(key, plaintext):
    """
    TODO: Encrypts a plaintext string using AES-GCM.
    Returns a dict with nonce and ciphertext (both hex-encoded).
    """
    nonce = os.urandom(12)  # 96-bit nonce
    return {'nonce': nonce.hex(), 'ciphertext': ciphertext.hex()}

def decrypt_message(key, message):
    """
    TODO: Decrypts a message dictionary using AES-GCM.
    Raises an exception if decryption or authentication fails.
    """
    pass

# ------------------------------
# Party Class with Ratcheting
# ------------------------------
class Party:
    """
    Represents one chat participant (e.g., Alice or Bob),
    holding an ephemeral ECDH key pair and a ratcheting session key.
    """
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = generate_ecdh_key_pair()
        self.sending_key = None
        self.receiving_key = None

    def get_public_bytes(self):
        """
        TODO: Returns the PEM-encoded public key to send to the peer.
        """
        pass

    def establish_session(self, peer_pub_bytes, role='initiator'):
        # TODO: derive session key from peer_public_key
        pass

    def send(self, plaintext):
        """
        TODO: Ratchet the sending key first, then encrypt.
        """
        pass

    def receive(self, msg):
        """
        TODO: Ratchet receiving key before decryption, then decrypt.
        """
        pass

# --- Demo usage ---
def simulate_chat():
    """
    Simulates a secure chat between Alice and Bob with key ratcheting.
    """

    # TODO: Step 1: Create Alice and Bob as two parties
    # TODO: Step 2: Key Exchange
    # Each party exchanges public keys and derives a shared session key

    print("Session key established.\n")

    # Step 3: Alice sends a message to Bob
    msg1 = "Hello Bob!"
    encrypted_msg1 = alice.send(msg1)
    print(f"Alice sends: {json.dumps(encrypted_msg1)}")

    # Bob receives and decrypts; his key is also ratcheted
    print(f"Bob receives: {bob.receive(encrypted_msg1)}\n")

    # Step 4: Alice sends another message
    msg2 = "New ratcheted message!"
    encrypted_msg2 = alice.send(msg2)
    print(f"Alice sends: {json.dumps(encrypted_msg2)}")
    print(f"Bob receives: {bob.receive(encrypted_msg2)}\n")

    # Step 5: Bob replies
    msg3 = "Hello Alice!"
    encrypted_msg3 = bob.send(msg3)
    print(f"Bob sends: {json.dumps(encrypted_msg3)}")
    print(f"Alice receives: {alice.receive(encrypted_msg3)}\n")

# Entry point
if __name__ == "__main__":
    simulate_chat()
