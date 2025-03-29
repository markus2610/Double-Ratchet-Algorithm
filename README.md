# 🔐 Double Ratchet Algorithm (Python Demo)

This project is a simple educational implementation of the **Double Ratchet Algorithm**, inspired by Signal Protocol, using Python 3.11+, `cryptography`, and `pycryptodome`.

It demonstrates secure key exchange via **X3DH** and message encryption/decryption using a symmetric ratchet mechanism.

---

## 📚 Original Source

This implementation is based on the excellent article and code sample by **nfil.dev**:  
👉 [https://nfil.dev/coding/encryption/python/double-ratchet-example/](https://nfil.dev/coding/encryption/python/double-ratchet-example/)

---

## 📦 Requirements

- Python 3.11+ (Homebrew or system Python is fine)
- macOS/Linux/Windows
- Virtual environment (recommended)

### 🔧 Python Libraries

Install dependencies:

```bash
pip install cryptography pycryptodome
```

Or use the provided `venv` (if applicable).

---

## ▶️ How to Run

1. **Clone or download the script**:
    - `double_ratchet.py`

2. **(Recommended) Set up a virtual environment**:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install cryptography pycryptodome
    ```

3. **Run the script**:

    ```bash
    python double_ratchet.py
    ```

You should see console output showing shared keys, symmetric ratchet keys, and encrypted/decrypted messages between Alice and Bob.

---

## 📚 What It Demonstrates

- X3DH (Extended Triple Diffie-Hellman) key agreement
- Symmetric key ratcheting
- Encrypted messaging with AES-CBC and PKCS#7 padding
- Use of HKDF for key derivation
- State evolution with every message

---

## 🧠 Educational Purpose

This is a simplified educational version. For real-world secure messaging, use vetted libraries like [libsignal](https://github.com/signalapp/libsignal).

