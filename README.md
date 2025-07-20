# Nostr NIP Proposal: User-Selected Tipping Preferences and Derived Addresses (NIP-XX)

This repository hosts the draft specification and discussion for a proposed Nostr Improvement Proposal (NIP) that introduces chain-agnostic tipping in Nostr. It allows users to select their preferred cryptocurrency chain for tips (e.g., BCH for low-fee on-chain sends, ETH for smart contracts, or BTC via Lightning as default), using derived addresses from their npub public key. This extends NIP-57 (Zaps) without replacing it, addressing LN's complexities while maintaining backwards compatibility.

## Motivation
Nostr's Zaps (NIP-57) enable social tipping but are limited to Bitcoin's Lightning Network (LN), which can involve setup hurdles like channel funding, liquidity management, and routing failures. This NIP proposes a flexible alternative:
- **User Choice**: Let users specify preferences for any secp256k1-compatible chain (e.g., BCH, ETH, BTC on-chain).
- **Efficiency**: On-chain tips offer sub-cent fees and instant settlement (e.g., BCH 0-conf) without LN's overhead.
- **Seamless Integration**: Derive addresses from npub for automation, reducing manual copy-paste and errors.
- **Broader Use Cases**: Support tokens/NFTs (e.g., BCH CashTokens, ERC-20 on ETH) for creative tipping.
- **Non-Disruptive**: Coexists with LN; optional for clients/relays; non-custodial to avoid regulatory issues (e.g., FinCEN money transmitter licenses).

This fosters a more inclusive ecosystem, attracting multi-chain users while keeping BTC/LN central for maximalists.

## Specification (Draft)
### Profile Metadata Extension (Kind 0)
Users add optional tags to declare preferences and enable derivation:
- `["tipping-pref", "bch"]` or `["tipping-pref", ["eth", "ln", "bch"]]` (ordered list; no pref defaults to LN).
- `["derived-address", {"chain": "bch", "auto-derive": true, "hd-path": "m/44'/145'/0'/0/0"}]` (flags auto-derivation; include prefs for tokens like CashTokens).
- Clients derive addresses from npub's public key (secp256k1):
  - BCH: hash160(compressed pubkey) -> CashAddr.
  - ETH: Keccak-256(uncompressed pubkey)[-20 bytes] -> checksummed 0x...
  - HD for Privacy: Use BIP-44 paths from nsec (as master private key) for fresh addresses per tip.

### Tipping Flow
1. Sender's client checks receiver's pref tag.
2. Derive address (or use published); build tx (amount from context, e.g., post value).
3. Sign/broadcast on-chain (client-integrated or external wallet via NIP-47 extension).
4. Publish receipt event (extend kind 9735): `["chain", "bch"]`, `["txid", "hash"]`, `["amount", "100000"]`, `["token-data", "cashtoken-category"]`.

### Backwards Compatibility
- No pref? Fall back to LN Zaps.
- Non-supporting clients: Ignore tags; show receipt events as generic text (e.g., "Tip on BCH [txid]"). Funds receivable via manual nsec import to wallet.
- Relays: No changes—store tags/events as usual.

### Privacy and Security
- HD derivation for address reuse avoidance.
- Non-custodial: Tx signing local; nsec never shared.
- Verification: Clients recompute derived addresses for trust.

## Examples
See `/examples` for code:
- `derive_addresses.py`: Python script deriving BCH/ETH addresses from nsec/npub.
- `derive_addresses.js`: JS version for client integration.
- `simple_bch_tx.js`: Prototype for building a BCH tx with CashTokens.

## Status and Feedback
- **Draft Stage**: Open for comments—file issues/PRs here.
- **Next Steps**: Prototype in a client fork (e.g., Amethyst); discuss in nostr-protocol/nips.
- **Contributors Wanted**: Help with spec refinements, code, or community outreach.

Join the discussion on X/Nostr (#NostrMultiChain) or open an issue!

## License
MIT License.