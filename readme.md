# AES Visualization & Debugging Tool

**Live Demo:** [aes.ridao.ar](https://aes.ridao.ar)

A simple **AES-128** visualization tool to see **key expansion** and **encryption rounds** step by step.

## Features

- **Key Expansion** (AES-128): Shows round keys, including Rcon, S-box, and XOR steps.
- **Encryption Rounds**:
    - Round 0: AddRoundKey
    - Rounds 1–9: SubBytes → ShiftRows → MixColumns → AddRoundKey
    - Round 10: SubBytes → ShiftRows → AddRoundKey
- **No Padding, ECB Mode** by default (plaintext must be exactly 16 bytes).
- **Comparison** with CryptoJS for verification.

## Installation & Setup

```bash
git clone https://github.com/yourusername/aes-visualization.git
cd aes-visualization
npm install
npm run dev
# Then open http://localhost:3000
```

## Usage

1. Enter **plaintext** and **key** (hex or text).
2. Choose **AES mode** (ECB, CBC, CTR) and **padding** (PKCS#7, ANSI X.923, or None).
3. Click **Encrypt** to see step-by-step AES operations.
4. Click **Key Expansion** to view each round key.

## Usage

1. Enter **plaintext** and **key** (hex or text).
2. Choose **AES mode** (ECB, CBC, CTR) and **padding** (PKCS#7, ANSI X.923, or None).
3. Click **Encrypt** to see step-by-step AES operations.
4. Click **Key Expansion** to view each round key.

## Example: "Hello, AES!" (No Padding, ECB)

- **Plaintext**: 11 bytes + 5 zeros → 16 bytes
- **Key (hex)**: `07 0e a6 e5 c4 da 1a 15 8d 78 15 e2 48 b1 e1 a4`
- **Final Ciphertext** (Hex): `625fee822733b8eae1aada3dc31a272f`
- **Final Ciphertext** (Base64): `625fee822733b8eae1aada3dc31a272f`
-  **Final Ciphertext** (Binary): `0110001001011111111011101000001000100111001100111011100011101010111000011010101011011010`

## About 01410 Cryptography 1 at DTU

- Covers **block ciphers** (AES), **RSA**, **discrete logarithm**, **LWE**, and more.
- This tool is **unofficial** and purely for **educational** use.

## Authors

- [Alfonso Ridao](https://alfonso.ridao.ar)
- For support, email alfonso@ridao.ar.


## 🚀 About Me
I'm a time traveler
