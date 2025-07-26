# Nostr to BCH/CashTokens Integration POC (JavaScript)

This repository contains a proof-of-concept (POC) JavaScript script that demonstrates how to derive various cryptographic keys and addresses from a Nostr private key (nsec). The primary focus is on showcasing the compatibility between Nostr keys (based on secp256k1) and Bitcoin Cash (BCH) ecosystems. This includes deriving BCH addresses in both legacy (Base58Check) and modern (CashAddr) formats, Ethereum addresses, and constructing a basic BCH transaction that pays to the npub-derived CashAddr. Additionally, it provides a sample for including CashTokens (fungible tokens) in transaction outputs.

The script illustrates how Nostr users could potentially receive BCH payments or tips directly to addresses derived from their npub, using the same private key (nsec) for signing transactions. This could pave the way for integrations in Nostr clients with BCH wallets, but it is strictly a POC—strictly evaluate security risks (e.g., key reuse across chains) before any production use.

**Important Warnings:**
- This is a POC with dummy data and a simplified transaction. The generated transaction is **not broadcastable** on any network (testnet or mainnet) due to placeholder UTXOs and a basic sighash calculation.
- Key reuse (deriving BCH/ETH from Nostr nsec) increases risk if the nsec is compromised, as it exposes funds across chains. For real-world use, consider BIP-39 mnemonics with BIP-44 derivation paths for multi-chain support.
- No funds should be sent to derived addresses in this POC without verifying control via a proper wallet.
- The signing uses a placeholder sighash preimage. For accurate BCH signing, implement proper sighash serialization as per BCH specifications.

## Features Demonstrated

- Decode Nostr nsec to raw private key bytes using Bech32.
- Derive compressed/uncompressed public keys and x-only pubkey for npub.
- Encode npub from the derived public key.
- Compute hash160 (SHA256 + RIPEMD160) for pubkeyhash addresses.
- Generate legacy Base58Check address (compatible with BTC/BCH).
- Generate BCH CashAddr using a custom implementation (handles unique HRP expansion and checksum).
- Derive Ethereum address via Keccak-256 with checksum.
- Construct sample CashToken data for fungible tokens (e.g., for tipping with tokens).
- Build an unsigned BCH transaction using `@bitauth/libauth`, sign it (with placeholder sighash), and output the signed hex.

## CashAddr Derivation Formula

The script derives the BCH CashAddr from the public key hash (PKH) using the following steps:

1. **Compute PKH**: `hash160(compressedPub) = RIPEMD160(SHA256(compressedPub))`, where `compressedPub` is the 33-byte compressed public key.

2. **Payload Preparation**: Prefix with version byte (0 for P2PKH): `payload = [0, ...pkh]` (21 bytes total).

3. **Convert to 5-bit Words**: `data5 = convertbits(payload, 8, 5, true)`, where `convertbits` accumulates bits and pads if necessary.

4. **HRP Expansion**: For HRP='bitcoincash', expand to lower 5 bits of each char code: `expanded = [charCode & 31 for char in hrp] + [0]`.

5. **Checksum Calculation**:
   - Values = expanded HRP + data5 + [0]*8
   - Polymod: Initialize c=1n, then for each d in values:
     - c0 = c >> 35n
     - c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d)
     - XOR with generators if bits set: if c0 & 1n: ^= 0x98f2bc8e61n; &2n: 0x79b76d99e2n; &4n: 0xf33e5fb3c4n; &8n: 0xae2eabe2a8n; &16n: 0x1e4f43e470n
   - Final mod = polymod ^ 1n
   - Checksum = [(mod >> (5n * (7n - i))) & 31n for i=0 to 7]

6. **Encode**: `address = 'bitcoincash:' + [CHARSET[d] for d in (data5 + checksum)]`, where CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".

This custom implementation ensures compatibility with CashAddr's unique checksum and HRP rules.

### Sources for CashAddr Derivation Formula

The formula is based on the official Bitcoin Cash specifications. Key references include:

- [Bitcoin Cash CashAddr Specification](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md) - The primary source detailing the encoding, checksum, and polymod algorithm.
- [Bitcoin Cash Protocol Reference: CashAddr Encoding](https://reference.cash/protocol/blockchain/encoding/cashaddr) - Provides additional explanations and examples for the CashAddr format.

## Dependencies

The script relies on the following libraries:
- `@bitauth/libauth`: For BCH transaction building and CashAddr utilities.
- `@noble/secp256k1`: For ECDSA key derivation and signing.
- `@noble/hashes`: For cryptographic hashes and HMAC (required by `@noble/secp256k1`).
- `crypto`: Node.js built-in for SHA256, RIPEMD160, etc.
- `ethereum-cryptography`: For Keccak-256 in ETH address derivation.

## Installation

This project uses Yarn for package management. Ensure you have Yarn installed (run `npm install -g yarn` if needed, or use your package manager).

1. Clone the repository:
   ```
   git clone https://github.com/your-username/pay-to-npub.git
   cd pay-to-npub
   ```

2. Change into the project directory (important: the script and package.json are here):
   ```
   cd pay-to-npub
   ```

3. Install dependencies using Yarn:
   ```
   yarn install
   ```
   This will install all required packages from the `package.json` file.

If you encounter any issues with dependencies (e.g., version conflicts), you can add them individually:
```
yarn add @bitauth/libauth @noble/secp256k1 @noble/hashes ethereum-cryptography
```
(Note: `crypto` is a Node.js built-in and does not need installation.)

## Usage

### Running the Script

The main POC script is `pay-to-npub.js`. It uses a hardcoded sample Nostr nsec for demonstration. Ensure you are in the `pay-to-npub` directory, then run:

```
yarn node pay-to-npub.js
```

- **Output**: The script will print derived keys, addresses, and a signed transaction hex to the console.
- **Customization**: Edit the `nsec` variable in the script to use your own Nostr private key (for testing only—never share real nsecs). You can also modify the dummy UTXO or transaction amounts.
- **Expected Runtime**: Less than 1 second on a standard machine.

Example console output excerpt:
```
Private key hex from nsec: <hex-string>
Compressed public key hex: <hex-string>
X-only public key hex (for npub): <hex-string>
Nostr npub: npub1...
Public key hash (hash160) hex: <hex-string>
BTC/BCH (legacy) address: 1...
BCH CashAddr address: bitcoincash:q...
ETH address: 0x...
Sample CashToken data for output (hex): <hex-string>
Signed TX Hex: <long-hex-string>
```

## Development Journey and Known Limitations

This script was developed iteratively to address challenges in cross-ecosystem compatibility:

- **Bech32/CashAddr Encoding**: Nostr uses standard Bech32, but CashAddr required custom HRP expansion (lower 5 bits only) and a 40-bit checksum with BCH-specific polymod. Fixed with dedicated functions.
- **Transaction Building**: Used `@bitauth/libauth` for unsigned tx creation. Ensured empty `unlockingBytecode` for inputs and proper bytecode extraction from CashAddr.
- **Signing**: Implements DER encoding for signatures. Currently uses a simplified sighash (double SHA256 of encoded tx)—implement proper BCH sighash (includes outpoints hash, sequence hash, etc.).
- **CashTokens**: Sample data is provided but not integrated into the tx outputs. In a real tx, prepend token data to the output value field.
- **Dummy Data**: UTXOs and txids are placeholders. For testnet, integrate a BCH explorer API to fetch real UTXOs.
- **Broadcast**: Not implemented here. Use a BCH node or service like rest.bitcoin.com for testnet broadcasting.

For full BCH signing, replace the placeholder with `generateSigningSerializationBch` from libauth, providing a sha256 implementation (e.g., using Node's `crypto`).

## Security Considerations

- **Key Exposure**: Deriving addresses from nsec links Nostr identity to BCH/ETH funds. Use hardware wallets or separate seeds for production.
- **Deterministic Signing**: `@noble/secp256k1` uses RFC6979 to avoid nonce reuse vulnerabilities.
- **Testnet Recommended**: Experiment on BCH testnet (faucets available) before mainnet.
- **Auditing**: This is unaudited code—review or use established libraries like Electron Cash for real wallets.
- **Nostr Integration Risks**: If building a Nostr client plugin, add user warnings about cross-chain key reuse and require explicit confirmations.

## Next Steps for Expansion

- **Testnet Integration**: Add API calls to fetch real testnet UTXOs (e.g., via `@psf/bch-js` or explorer APIs).
- **Proper Sighash**: Implement full BCH sighash for valid signatures.
- **CashTokens Full Support**: Extend outputs to include token data and adjust value encoding.
- **Nostr Wallet Plugin**: Integrate with Nostr clients (e.g., via NIP-07) for seamless tipping.
- **HD Derivation**: Use BIP-44 paths for address generation to avoid direct nsec reuse.

Contributions are welcome! Open an issue for bugs or feature requests, or submit a PR.

## License

MIT