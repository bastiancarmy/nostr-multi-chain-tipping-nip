# Nostr Private Key Derivation Script

## Overview

This Python script decodes a Nostr private key provided in `nsec` format (Bech32-encoded) and derives several related cryptographic values and addresses:

- Private key in hexadecimal format.
- Compressed public key in hexadecimal format (using secp256k1 curve).
- Public key hash (RIPEMD-160 of SHA-256, aka hash160) in hexadecimal format.
- Bitcoin Cash (BCH) P2PKH address in CashAddr format.
- Ethereum (ETH) address with checksum.

The script includes a pure Python implementation of Bech32 encoding/decoding for handling `nsec` and CashAddr formats. It uses the ECDSA library for public key derivation and standard hashlib for hashing operations.

**Note:** This script handles sensitive private keys. Use it only in secure environments and never share your private keys.

## Requirements

- Python 3.6 or higher.
- The `ecdsa` library (install via `pip install ecdsa` within the virtual environment).

No other external dependencies are required, as hashlib and enum are part of the Python standard library.

## Installation

1. Ensure Python 3.6 or higher is installed on your system.
2. Create a virtual environment:
   ```
   python -m venv nostr_env
   ```
3. Activate the virtual environment:
   - On Windows:
     ```
     nostr_env\Scripts\activate
     ```
   - On Unix or MacOS:
     ```
     source nostr_env/bin/activate
     ```
4. Install the required library:
   ```
   pip install ecdsa
   ```
5. Save the script to a file, e.g., `nostr_key_deriver.py`.

## Usage

1. Activate the virtual environment (if not already activated):
   - On Windows:
     ```
     nostr_env\Scripts\activate
     ```
   - On Unix or MacOS:
     ```
     source nostr_env/bin/activate
     ```
2. Open the script in a text editor.
3. Modify the `nsec` variable to your desired Nostr private key (e.g., `nsec1...`).
4. Run the script from the command line:
   ```
   python nostr_key_deriver.py
   ```
5. The script will print the derived values to the console.

The script is self-contained and runs as a standalone program. It does not accept command-line arguments; all configuration is done by editing the `nsec` variable directly in the code.

After use, you can deactivate the virtual environment with:
```
deactivate
```

## Example

Using the sample `nsec` provided in the script (`nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5`), running the script produces the following output:

```
Private key hex from nsec: 67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa
Compressed public key hex: 027e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e
Public key hash (hash160) hex: 410790829cb31dff0bc2a7ecf7eb4e36982f5033
Derived BCH Address: bitcoincash:qpqs0yyznje3mlctc2n7ealtfcmfst6sxv0atfxq
Derived ETH Address: 0x62B047eeBd4F8d75242A285ed33c7e88656b5efc
```

## Script Details

- **Bech32 Implementation:** A reference pure-Python Bech32 encoder/decoder supporting both BECH32 and BECH32M encodings.
- **Key Derivation:** Uses ECDSA on the secp256k1 curve to derive the public key from the private key.
- **BCH Address:** Constructs a P2PKH CashAddr (prefix: `bitcoincash`) with version byte 0.
- **ETH Address:** Derives from the uncompressed public key using Keccak-256 (SHA3-256), takes the last 20 bytes, and applies checksum casing.

If you encounter any issues or need modifications, ensure your Python environment has the required library installed.