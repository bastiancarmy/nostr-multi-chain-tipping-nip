# Nostr to BCH/CashTokens Integration POC (JavaScript)

This repository contains a proof-of-concept (POC) JavaScript script that demonstrates how to derive various cryptographic keys and addresses from a Nostr private key (nsec). The primary focus is on showing the compatibility between Nostr keys and Bitcoin Cash (BCH) ecosystems, including deriving BCH addresses (legacy and CashAddr formats), Ethereum addresses, and constructing a basic unsigned-then-signed BCH transaction that pays to the derived CashAddr. It also includes a sample for CashTokens data in transaction outputs.

The script serves as building blocks for integrating Nostr keys with BCH-compatible chains, enabling seamless payments or tipping using the same seed (nsec) for both Nostr and BCH wallets. This could be extended for nostr client wallet integrations, but security considerations (e.g., deterministic wallet risks) must be evaluated before production use.

## Purpose

- Derive Nostr npub from nsec.
- Derive compressed and uncompressed public keys.
- Compute hash160 for pubkeyhash addresses.
- Generate legacy Base58Check BCH/BTC address.
- Generate BCH CashAddr (with custom Bech32-like encoding to handle CashAddr specifics).
- Derive Ethereum address using Keccak-256.
- Demonstrate sample CashToken data for fungible tokens in a BCH output.
- Construct a dummy BCH transaction, sign it (with placeholder sighash), and output the signed hex.

This POC highlights that the same nsec can control corresponding BCH and ETH addresses, potentially allowing nostr users to receive BCH payments directly to their npub-derived addresses.

**Note:** The transaction uses a dummy UTXO and simplified sighash calculation—it's not broadcastable yet. For testnet, real UTXOs and proper sighash (using libauth's `generateSigningSerializationBch`) are needed.

## Dependencies

Install via npm:

```bash
npm install @bitauth/libauth @noble/secp256k1 @noble/hashes crypto ethereum-cryptography
```

- `@bitauth/libauth`: For BCH transaction building, CashAddr to locking bytecode conversion.
- `@noble/secp256k1`: For ECDSA signing and public key derivation.
- `@noble/hashes`: For HMAC-SHA256 setup required by noble-secp256k1.
- `crypto`: Node.js built-in for hashes (SHA256, RIPEMD160).
- `ethereum-cryptography`: For Keccak-256 in ETH address derivation.

## Script Overview (`pay-to-npub.js`)

The script processes a sample Nostr nsec and performs the following steps:

1. **Decode nsec to Private Key Bytes**: Uses custom Bech32 decoding to extract the 32-byte private key.

2. **Derive Public Keys**:
   - Compressed (33 bytes) and uncompressed (65 bytes) public keys using secp256k1.
   - X-only public key (32 bytes) for npub.

3. **Encode npub**: Custom Bech32 encoding for Nostr npub.

4. **Compute Pubkey Hash (hash160)**: SHA256 + RIPEMD160 of compressed pubkey.

5. **Legacy Base58Check Address**: For BTC/BCH compatibility.

6. **BCH CashAddr**: Custom implementation handling CashAddr's unique HRP expansion (only lower 5 bits, no upper) and a 40-bit BCH checksum (8 chars) with different polymod generators.

7. **Ethereum Address**: Keccak-256 of uncompressed pubkey (minus prefix), last 20 bytes, with checksum.

8. **Sample CashToken Data**: Constructs prefix, category, and amount for a fungible token output.

9. **Build and Sign BCH Transaction**:
   - Dummy input UTXO (P2PKH).
   - Outputs paying to derived CashAddr.
   - Uses libauth's `generateTransaction` to build unsigned tx.
   - Placeholder sighash (double SHA256 of encoded tx).
   - Signs with secp256k1, DER-encodes signature, appends SIGHASH_ALL_FORKID.
   - Applies unlocking bytecode (sig + pubkey) to input.
   - Encodes signed tx and outputs as hex string.

Run the script:

```bash
node pay-to-npub.js
```

Example output includes derived keys/addresses and the signed transaction hex (placeholder; not valid for broadcast).

## How We Got Here (Development Journey)

This script was iteratively built and debugged through a collaborative process to resolve issues in key derivation, address encoding, and transaction construction. Key challenges and fixes:

1. **Nostr Key Derivation**: Started with Bech32 decoding/encoding for nsec/npub—worked out-of-the-box using reference implementations.

2. **Legacy Address**: Base58Check encoding with double SHA256 checksum—straightforward.

3. **CashAddr Encoding Issues**:
   - Initial Bech32-based encoding produced invalid checksums because CashAddr uses a modified HRP expansion (only lower 5 bits, no upper) and a 40-bit BCH checksum (8 chars) with different polymod generators.
   - Fixed by creating separate `cashHrpExpand`, `cashPolymod` (ported from C++ spec using BigInt), and `cashCreateChecksum` functions.
   - Verified with libauth's `cashAddressToLockingBytecode`—threw "invalid checksum" until resolved.

4. **Transaction Construction with libauth**:
   - `cashAddressToLockingBytecode` returns an object `{ bytecode }` or `{ error }`—fixed by extracting `bytecode` and error checking.
   - `generateTransaction` required `unlockingBytecode: new Uint8Array()` for unsigned inputs—omission caused "undefined" error.
   - Outputs used derived locking bytecode for consistency.

5. **Signing with @noble/secp256k1**:
   - No `signSync`—used `sign` (async by default, but sync with HMAC setup).
   - Required HMAC-SHA256 polyfill: Set `etc.hmacSha256Sync` using @noble/hashes.
   - DER encoding for signature (r,s) implemented manually.
   - Appended SIGHASH_ALL_FORKID (0x41) for BCH.

6. **Output Formatting**: `encodeTransaction` returns Uint8Array; default console.log added commas—fixed with `Buffer.from(signedTx).toString('hex')`.

7. **Other**: ETH derivation used uncompressed pubkey and custom checksum; CashToken sample is illustrative (prepend to output value in real tx).

The script evolved from failing on CashAddr checksum, to tx building errors, signing issues, and finally successful (but placeholder) signed tx output.

## Security Considerations

- **Deterministic Wallets**: Deriving BCH/ETH from Nostr nsec is deterministic (same seed yields same addresses), which is fine for HD wallets but risky if nsec is compromised—exposes all derived chains. Use BIP39/44 for multi-chain if integrating with nostr clients; treat nsec as a master seed.
- **No Nonce Reuse**: RFC6979 deterministic signing in noble-secp256k1 mitigates risks.
- **Placeholder Sighash**: Real implementation must use libauth's `generateSigningSerializationBch` to avoid invalid signatures.
- **Testnet Only**: Do not use on mainnet; dummy data could lead to fund loss.
- **Nostr Integration**: If extending to nostr clients, ensure users understand cross-chain exposure; add confirmations for derivations.

## Next Steps (Testnet Expansion)

To move to testnet BCH/CashTokens:
- Fetch real UTXOs for the derived address (use BCH testnet explorer API).
- Implement proper sighash preimage.
- Add CashToken support to outputs (prepend token data to value).
- Broadcast via REST API (e.g., bitcoin.com testnet endpoint).

Contributions welcome! For questions, open an issue.

## License

MIT