import { cashAddressToLockingBytecode, generateTransaction, encodeTransaction } from '@bitauth/libauth';
import * as secp256k1 from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as crypto from 'crypto';
import { keccak256 } from 'ethereum-cryptography/keccak';

secp256k1.etc.hmacSha256Sync = (key, ...messages) => hmac(sha256, key, secp256k1.etc.concatBytes(...messages));

// Bech32 reference implementation (pure JS)
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;

function bech32Polymod(values) {
    const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (let value of values) {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ value;
        for (let i = 0; i < 5; i++) {
            chk ^= ((top >> i) & 1) ? generator[i] : 0;
        }
    }
    return chk;
}

function bech32HrpExpand(hrp) {
    const expanded = [];
    for (let char of hrp) {
        expanded.push(char.charCodeAt(0) >> 5);
    }
    expanded.push(0);
    for (let char of hrp) {
        expanded.push(char.charCodeAt(0) & 31);
    }
    return expanded;
}

function bech32VerifyChecksum(hrp, data) {
    const constVal = bech32Polymod(bech32HrpExpand(hrp).concat(data));
    if (constVal === 1) return 'BECH32';
    if (constVal === BECH32M_CONST) return 'BECH32M';
    return null;
}

function bech32Decode(bech) {
    if (bech.toLowerCase() !== bech && bech.toUpperCase() !== bech || [...bech].some(c => c.charCodeAt(0) < 33 || c.charCodeAt(0) > 126)) {
        return [null, null, null];
    }
    bech = bech.toLowerCase();
    const pos = bech.lastIndexOf('1');
    if (pos < 1 || pos + 7 > bech.length || bech.length > 90) {
        return [null, null, null];
    }
    const hrp = bech.slice(0, pos);
    const data = [];
    for (let char of bech.slice(pos + 1)) {
        const d = CHARSET.indexOf(char);
        if (d === -1) return [null, null, null];
        data.push(d);
    }
    const spec = bech32VerifyChecksum(hrp, data);
    if (spec === null) return [null, null, null];
    return [hrp, data.slice(0, -6), spec];
}

function convertbits(data, frombits, tobits, pad = true) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << tobits) - 1;
    const max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (let value of data) {
        if (value < 0 || (value >> frombits)) return null;
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            ret.push((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) ret.push((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return null;
    }
    return ret;
}

function bech32CreateChecksum(hrp, data, modXor = 1) {
    const values = bech32HrpExpand(hrp).concat(data);
    const mod = bech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ modXor;
    const checksum = [];
    for (let i = 0; i < 6; i++) {
        checksum.push((mod >> 5 * (5 - i)) & 31);
    }
    return checksum;
}

function bech32Encode(hrp, data, modXor = 1, separator = '1') {
    const combined = data.concat(bech32CreateChecksum(hrp, data, modXor));
    return hrp + separator + combined.map(d => CHARSET[d]).join('');
}

// Sample Nostr private key (nsec)
const nsec = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';

// Decode nsec to private key bytes
let [hrp, data5, spec] = bech32Decode(nsec);
let privData = convertbits(data5, 5, 8, false);
let privBytes = new Uint8Array(privData);
let privHex = Buffer.from(privBytes).toString('hex');
console.log(`Private key hex from nsec: ${privHex}`);

// Derive public key
let compressedPub = secp256k1.getPublicKey(privBytes, true);
let compressedHex = Buffer.from(compressedPub).toString('hex');
console.log(`Compressed public key hex: ${compressedHex}`);

// For npub: Use x-only public key (drop parity byte from compressed pub)
let xOnlyPub = compressedPub.slice(1);  // 32 bytes
let xOnlyHex = Buffer.from(xOnlyPub).toString('hex');
console.log(`X-only public key hex (for npub): ${xOnlyHex}`);

// Encode to npub (Bech32 with modXor = 1, separator '1')
let npubData5 = convertbits(Array.from(xOnlyPub), 8, 5, true);
let npubEncoded = bech32Encode('npub', npubData5, 1, '1');
console.log(`Nostr npub: ${npubEncoded}`);

// hash160 for pubkeyhash
function hash160(x) {
    return crypto.createHash('ripemd160').update(crypto.createHash('sha256').update(x).digest()).digest();
}

let pkh = hash160(compressedPub);
let pkhHex = pkh.toString('hex');
console.log(`Public key hash (hash160) hex: ${pkhHex}`);

// Base58Check for BTC/BCH legacy address (prefix 0x00)
function doubleSha256(x) {
    return crypto.createHash('sha256').update(crypto.createHash('sha256').update(x).digest()).digest();
}

function b58encode(v) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let nPad = 0;
    for (let c of v) {
        if (c === 0) nPad++;
        else break;
    }
    let p = BigInt(1);
    let acc = BigInt(0);
    for (let c of Array.from(v).reverse()) {
        acc += p * BigInt(c);
        p = p * BigInt(256);
    }
    let string = '';
    while (acc > 0n) {
        let [newAcc, idx] = [acc / 58n, Number(acc % 58n)];
        acc = newAcc;
        string = alphabet[idx] + string;
    }
    return alphabet[0].repeat(nPad) + string;
}

let prefix = Buffer.from([0x00]);
let payload = Buffer.concat([prefix, pkh]);
let checksum = doubleSha256(payload).slice(0, 4);
let btcBchLegacyAddress = b58encode(Buffer.concat([payload, checksum]));
console.log(`BTC/BCH (legacy) address: ${btcBchLegacyAddress}`);

// CashAddr for BCH (P2PKH, version 0)
let versionByte = 0;
let cashPayload = [versionByte, ...Array.from(pkh)];
let cashData5 = convertbits(cashPayload, 8, 5, true);

// Create separate functions for CashAddr HRP expand and checksum
function cashHrpExpand(hrp) {
    const expanded = [];
    for (let char of hrp) {
        expanded.push(char.charCodeAt(0) & 31);
    }
    expanded.push(0);
    return expanded;
}

function cashPolymod(values) {
    let c = 1n;
    for (let d of values) {
        let c0 = c >> 35n;
        c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
        if (c0 & 1n) c ^= 0x98f2bc8e61n;
        if (c0 & 2n) c ^= 0x79b76d99e2n;
        if (c0 & 4n) c ^= 0xf33e5fb3c4n;
        if (c0 & 8n) c ^= 0xae2eabe2a8n;
        if (c0 & 16n) c ^= 0x1e4f43e470n;
    }
    return c ^ 1n;
}

function cashCreateChecksum(hrp, data) {
    const values = cashHrpExpand(hrp).concat(data);
    const mod = cashPolymod(values.concat(new Array(8).fill(0)));
    const checksum = [];
    for (let i = 0; i < 8; i++) {
        checksum.push(Number((mod >> (5n * (7n - BigInt(i)))) & 31n));
    }
    return checksum;
}

const combined = cashData5.concat(cashCreateChecksum('bitcoincash', cashData5));
let bchAddress = 'bitcoincash:' + combined.map(d => CHARSET[d]).join('');
console.log(`BCH CashAddr address: ${bchAddress}`);

// For ETH address
let uncompressedPub = secp256k1.getPublicKey(privBytes, false);
let uncompressedHex = Buffer.from(uncompressedPub).toString('hex');
console.log(`Uncompressed public key hex: ${uncompressedHex}`);

// Keccak last 20 bytes
let keccak = keccak256(uncompressedPub.slice(1)).slice(-20);
let keccakHex = Buffer.from(keccak).toString('hex');
console.log(`Keccak last 20 bytes hex: ${keccakHex}`);

// ETH checksum function
function ethChecksum(addr) {
    addr = addr.toLowerCase();
    const hashed = Buffer.from(keccak256(Buffer.from(addr))).toString('hex');
    let result = '';
    for (let i = 0; i < addr.length; i++) {
        result += (parseInt(hashed[i], 16) >= 8) ? addr[i].toUpperCase() : addr[i];
    }
    return result;
}

let ethAddress = '0x' + ethChecksum(keccakHex);
console.log(`ETH address: ${ethAddress}`);

// Demonstrating CashTokens: Build a sample unsigned tx output with a fungible CashToken
// Dummy token category (32 bytes hex)
let tokenCategory = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');

// Fungible amount: 100 tokens (as bytes, little-endian varint)
let amountBytes = Buffer.from([0x64]);  // 100 in varint

// Token prefix byte: 0x10 for fungible only
let tokenPrefix = Buffer.from([0x10]);

// Sample CashToken data
let cashTokenData = Buffer.concat([tokenPrefix, tokenCategory, amountBytes]);
console.log(`Sample CashToken data for output (hex): ${cashTokenData.toString('hex')}`);
console.log("In a real BCH tx, prepend this to the output value (8 bytes little-endian) before the script length and script.");

// Function to DER-encode r and s
function encodeDer(r, s) {
    function encodeInt(val) {
        let bytes = [];
        let tmp = val;
        if (tmp === 0n) bytes.push(0);
        while (tmp > 0n) {
            bytes.push(Number(tmp & 0xffn));
            tmp >>= 8n;
        }
        bytes = bytes.reverse();
        if (bytes[0] & 0x80) bytes.unshift(0);
        return new Uint8Array([0x02, bytes.length, ...bytes]);
    }
    const rEnc = encodeInt(r);
    const sEnc = encodeInt(s);
    const totalLen = rEnc.length + sEnc.length;
    return new Uint8Array([0x30, totalLen, ...rEnc, ...sEnc]);
}

// Step 3-5: Build, sign, broadcast tx (testnet example)
// Sender's privkey hex (your nsec raw, for demo use test key)
const senderPrivHex = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';  // Demo priv; replace with testnet
const senderPriv = BigInt('0x' + senderPrivHex);

// Dummy/test UTXO
const inputs = [{
    outpointTransactionHash: Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
    outpointIndex: 0,
    sequenceNumber: 0xffffffff,
    valueSatoshis: 2000n,
    lockingBytecode: Buffer.from('76a914410790829cb31dff0bc2a7ecf7eb4e36982f503388ac', 'hex'),  // Dummy P2PKH (use your pkh)
    unlockingBytecode: new Uint8Array()  // Add this for unsigned input
}];

// Get locking bytecode for the derived address (for paying to npub-derived CashAddr)
const lockingResult = cashAddressToLockingBytecode(bchAddress);
if ('error' in lockingResult) {
    throw new Error(`Failed to convert CashAddr to locking bytecode: ${lockingResult.error}`);
}

const outputs = [{
    lockingBytecode: lockingResult.bytecode,
    valueSatoshis: 1000n  // Tip amount
}, {
    lockingBytecode: lockingResult.bytecode,  // Use same for change (or replace with dummy/other)
    valueSatoshis: 900n  // Change minus fee (~100 sats)
}];

const txConfig = {
    version: 2,
    inputs: inputs,
    outputs: outputs,
    locktime: 0
};

const { transaction: tx } = generateTransaction(txConfig);

// Manual signing (v3 doesn't have signTransactionMutable; calculate sighash and sign)
const SIGHASH_ALL_FORKID = 0x41;  // SIGHASH_ALL | SIGHASH_FORKID
// Placeholder sighash preimage - in real, implement full BCH sighash (hashPrevouts, hashSequence, etc.)
const sighashPreimage = doubleSha256(encodeTransaction(tx));  // Simplified; expand for production

const sig = secp256k1.sign(sighashPreimage, Buffer.from(senderPrivHex, 'hex'));
const derSig = encodeDer(sig.r, sig.s);
const sigWithType = Buffer.concat([derSig, Buffer.from([SIGHASH_ALL_FORKID])]);

// Apply to unlockingBytecode (for P2PKH: sig + pubkey)
tx.inputs[0].unlockingBytecode = Buffer.concat([sigWithType, compressedPub]);

// Re-encode signed tx
const signedTx = encodeTransaction(tx);
const signedTxHex = Buffer.from(signedTx).toString('hex');
console.log(`Signed TX Hex: ${signedTxHex}`);