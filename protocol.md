## Documentation

### Description of my protocol flow

Two parties, Alice and Bob
1. Each party creates an EC key pair on a common curve
2. Each side sends its PEM-encoded public key to the other
3. Each side computes Z = ECDH(my_priv, peer_pub)
4. Handshake KDF, base = HKDF(Z, salt=None, info="handshake")
5. Initiator sets (sending=send_i, receiving=send_r). Responder does the opposite.
    - send_i = HKDF(base, info="send-i") (initiator’s sending chain seed)
    - send_r = HKDF(base, info="send-r") (responder’s sending chain seed)
6. Per-message send:
    - Ratchet: sending = HKDF(sending, info="ratchet-step")
    - Encrypt: AES-GCM(key=sending, nonce=random(12), aad=None)
7. Per-message receive:
    - Ratchet: receiving = HKDF(receiving, info="ratchet-step")
    - Decrypt: AES-GCM(key=receiving, nonce,ciphertext,aad=None)

### The cryptographic primitives used

- ECDH on a NIST curve to establish a shared secret Z
- HKDF-SHA256 for key derivation and ratcheting:
    - base = HKDF(Z, salt=None, info="handshake")
    - Directional seeds: HKDF(base, info="send-i"), HKDF(base, info="send-r")
    - Per-message ratchet: HKDF(old_key, info="ratchet-step")
- AES-GCM for authenticated encryption:
    - Key length of 32 bytes from HKDF
    - Nonce of random 96 bits per message 

### How forward secrecy is achieved

Before every message, the sender and the receiver advance a one-way HKDF chain to derive a fresh message key. Because HKDF is one-way, newer per-message key does not does reveal older per-message keys. This means that if an attacker compromises the current session state, they cannot decrypt earlier messages. 
This provides forward secrecy for past messages within a session.

### Discussion of the security goals: confidentiality, integrity, and forward secrecy

- Confidentiality: AES-GCM encrypts the plaintext with a key that changes every message. Without the correct per-message key, ciphertexts reveal nothing meaningful.

- Integrity: AES-GCM includes an authentication tag. Any tampering with nonce or ciphertext causes decryption to fail.

- Forward secrecy: Per-message keys are derived by advancing a one-way HKDF chain. Previously used keys are not derivable from later keys, so previously sent messages remain protected even if a later per-message key leaks.

### Limitations or assumptions (e.g., no authentication, simple in-memory simulation)
- The design rotates keys with HKDF only; it does not mix in new ECDH values per message. This means it has forward secrecy for past messages but not for future.
- State is stored only in memory; if either side restarts, the session cannot resume securely.
- The system expects messages to arrive in order. Out-of-order or dropped messages can desynchronize the ratchet.
- Nonces are random 96-bit values; reusing a nonce with the same key would break GCM security. Random generation is secure for limited message counts, but it would be safer top use a deterministic counter for larger amounts of message.
