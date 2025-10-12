# 🛡️ Assignment: Secure Messaging with Forward Secrecy

## 📚 Overview

In this assignment, you will implement a **secure messaging application** between two parties using modern cryptographic techniques inspired by protocols like **Signal** and **TLS**. A secure messaging system is a cryptographic protocol that enables two (or more) parties to exchange messages over an insecure channel so that confidentiality, integrity, and (often) authenticity are guaranteed. The Signal protocol is a modern, open-source cryptographic protocol that provides end-to-end encrypted messaging with strong privacy guarantees. It is the foundation for apps such as Signal, WhatsApp, Facebook Messenger (Secret Conversations), Google Messages (RCS E2EE), and others.

Your application will support:

- **Key exchange** using Elliptic-Curve Diffie–Hellman (ECDH)
- **Authenticated encryption** using Advanced Encryption Standard – Galois/Counter Mode (AES-GCM)
- **Forward secrecy** via ephemeral key ratcheting

This assignment is designed to give you hands-on experience with practical cryptography and to deepen your understanding of secure communications protocols.

---

## 🎯 Learning Objectives

By completing this assignment, you will:

- Understand the use of **Elliptic-Curve Diffie–Hellman (ECDH)** for key exchange
- Apply **HMAC-based Key Derivation Function (HKDF)** to derive symmetric session keys
- Use **AES-GCM** for authenticated encryption (confidentiality + integrity)
- Demonstrate **forward secrecy** by rotating ephemeral key material
- Document and explain the cryptographic protocol flow

---

## 📦 Starter Code

You are provided with a skeleton Python file: `secure_chat_starter.py` and `test_secure_chat_starter.py`

It includes:

- Basic key generation and exchange functions
- Serialization utilities
- A minimal class-based simulation of two chat participants
- An encryption scheme using AES-GCM

---

## 🛠️ Your Tasks

### ✅ 1. Understand and Complete Key Exchange

- Read and implement the `generate_ecdh_key_pair`, `derive_shared_secret`, and `hkdf_expand` functions.
- Use ECDH to securely agree on a shared secret between two parties (Alice and Bob).
- Derive a session key from the shared secret using HKDF.

### ✅ 2. Implement Authenticated Encryption

- Use **AES-GCM** to encrypt and authenticate messages between parties.
- Encrypt outgoing messages with the current session key.
- Decrypt incoming messages and verify their integrity.

Note that AES-GCM requires a fresh nonce for each message under the same key. The code handles this correctly, but it’s worth explicitly stating why this matters. Even a brief note in the README can reinforce this. It could also be helpful to mention different nonce-generation strategies (random vs. counters).

### ✅ 3. Add Forward Secrecy

Forward Secrecy means that compromise of long-term keys does not reveal past session keys or past plaintexts.

- Implement **ephemeral key rotation**:
  - After each message, regenerate ephemeral ECDH keys.
  - Derive a new session key from the new shared secret.
- Demonstrate in your simulation that prior session keys are no longer used once keys are rotated.

The project currently uses an HKDF-based ratchet, rather than rotating ECDH key pairs. This is okay in our simplified setup, but we should clarify in the spec that both approaches are acceptable and provide a brief explanation of the trade-off. Full ECDH rotation (as in Signal’s double ratchet) offers stronger security, while HKDF ratcheting is easier to implement and still achieves forward secrecy.

### ✅ 4. Add Unit Tests

- Add at least 5 additional unit tests to `test_secure_chat_starter.py`

### ✅ 5. Document the Protocol

Write a markdown file `protocol.md` including:

- A description of your protocol flow
- The cryptographic primitives used
- How forward secrecy is achieved
- A discussion of the **security goals**: confidentiality, integrity, and forward secrecy
- Limitations or assumptions (e.g., no authentication, simple in-memory simulation)

---

## 📤 Submission Instructions

You should submit:

1. `secure_chat_starter.py` – your main implementation file  
2. `test_secure_chat_starter.py` – your main test file  
3. `protocol.md` – your documentation of the protocol 
4. A short transcript or screenshot of your working chat simulation (e.g., via `simulate_chat()`)

---

## 🧪 Example Output

```
Session key established.

Alice sends: {"nonce": "231b2f7826fb5a036d2f68df", "ciphertext": "ff4d0a255a926689786c960d3673b5c80e1cc9b616835858b34a"}
Bob receives: Hello Bob!

Alice sends: {"nonce": "3904b3be96d604af6d0e3bc0", "ciphertext": "1b808f51bf1cae4fa21d72f8d5710a710b81899c6e25eb03436452e211282848997635c908d7"}
Bob receives: New ratcheted message!

Bob sends: {"nonce": "47c16ab940d4fb7d2e426f52", "ciphertext": "b679de0d1ab42f2051b71f70f4a8153aa50c8e4858d6a402191d8cfe"}
Alice receives: Hello Alice!
```

---

## 🧾 Grading Criteria

| Criteria                                  | Points |
|-------------------------------------------|--------|
| Key generation and exchange (ECDH)        | 20     |
| AES-GCM encryption/decryption             | 20     |
| Forward secrecy implementation            | 20     |
| Protocol documentation                    | 20     |
| Correct simulation of message exchange    | 10     |
| Code style and clarity                    | 10     |

---

## 📎 Resources

- [Elliptic Curve Cryptography (NIST Guide)](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
- [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [`cryptography` Python library docs](https://cryptography.io/en/latest/)
- [Signal Protocol Overview](https://signal.org/docs/)

