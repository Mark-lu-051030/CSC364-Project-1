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
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
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
    public_key = deserialize_public_key(peer_public_key) if isinstance(peer_public_key, bytes) else peer_public_key
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    return shared_secret

def hkdf_expand(secret, info=b'secure chat'):
    """
    TODO: Derives a 256-bit symmetric key from a shared secret using HKDF.
          You should use SHA256 algorithm
          with length = 32
          with salt = None
          with info = info
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    symmetric_key = hkdf.derive(secret)
    return symmetric_key

def ratchet_key(old_key):
    """
    TODO: Derives a new session key from the previous key (symmetric ratcheting) 
          using hkdf_expand function with info 'ratchet-step'
    """
    new_session_key = hkdf_expand(old_key, info=b'ratchet-step')
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
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return {'nonce': nonce.hex(), 'ciphertext': ciphertext.hex()}

def decrypt_message(key, message):
    """
    TODO: Decrypts a message dictionary using AES-GCM.
    Raises an exception if decryption or authentication fails.
    """
    nonce = bytes.fromhex(message['nonce'])
    ciphertext = bytes.fromhex(message['ciphertext'])
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

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
        return serialize_public_key(self.public_key)

    def establish_session(self, peer_pub_bytes, role='initiator'):
        # TODO: derive session key from peer_public_key
        peer_pub = deserialize_public_key(peer_pub_bytes)
        shared = derive_shared_secret(self.private_key, peer_pub)

        base = hkdf_expand(shared, info=b'handshake')
        send_i = hkdf_expand(base, info=b'send-i')
        send_r = hkdf_expand(base, info=b'send-r')

        if role == 'initiator':
            self.sending_key = send_i
            self.receiving_key = send_r
        else:
            self.sending_key = send_r
            self.receiving_key = send_i

    def send(self, plaintext):
        """
        TODO: Ratchet the sending key first, then encrypt.
        """
        if self.sending_key is None:
            raise RuntimeError("Session not established; call establish_session() first.")
        self.sending_key = ratchet_key(self.sending_key)
        msg = encrypt_message(self.sending_key, plaintext)
        msg['from'] = self.name
        return msg

    def receive(self, msg):
        """
        TODO: Ratchet receiving key before decryption, then decrypt.
        """
        if self.receiving_key is None:
            raise RuntimeError("Session not established; call establish_session() first.")
        self.receiving_key = ratchet_key(self.receiving_key)
        return decrypt_message(self.receiving_key, msg)

# --- Demo usage ---
def simulate_chat():
    """
    Simulates a secure chat between Alice and Bob with key ratcheting.
    """

    # TODO: Step 1: Create Alice and Bob as two parties
    # TODO: Step 2: Key Exchange
    # Each party exchanges public keys and derives a shared session key
    alice = Party('Alice')
    bob = Party('Bob')

    alice_pub = alice.get_public_bytes()
    bob_pub = bob.get_public_bytes()
    print(f"Alice's public key: {alice_pub.decode()}")
    print(f"Bob's public key: {bob_pub.decode()}")

    alice.establish_session(bob_pub, role='initiator')
    bob.establish_session(alice_pub, role='responder')

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
