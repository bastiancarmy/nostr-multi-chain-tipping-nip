import * as readlineSync from 'readline-sync';
import axios from 'axios';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import * as nip19 from 'nostr-tools/nip19';
import { SimplePool, useWebSocketImplementation } from 'nostr-tools/pool';
import { cashAddressToLockingBytecode, generateTransaction, encodeTransaction, bigIntToCompactUint, numberToBinUint32LE, bigIntToBinUint64LE } from '@bitauth/libauth';
import * as secp256k1 from '@noble/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as crypto from 'crypto';
import WebSocket from 'ws';

useWebSocketImplementation(WebSocket);

secp256k1.etc.hmacSha256Sync = (key, ...messages) => hmac(sha256, key, secp256k1.etc.concatBytes(...messages));

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// From original: bech32Decode (kept for potential other uses, but not needed for npub now)
function bech32Decode(bech) {
    bech = bech.toLowerCase();
    const pos = bech.lastIndexOf('1');
    if (pos < 1 || pos + 7 > bech.length || bech.length > 90) return null;
    const hrp = bech.slice(0, pos);
    const data = [];
    for (let char of bech.slice(pos + 1)) {
        const d = CHARSET.indexOf(char);
        if (d === -1) return null;
        data.push(d);
    }
    return { hrp, data };
}

// From original: convertbits
function convertbits(data, frombits, tobits, pad = true) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << tobits) - 1;
    const max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (let value of data) {
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            ret.push((acc >> bits) & maxv);
        }
    }
    if (pad && bits) ret.push((acc << (tobits - bits)) & maxv);
    return ret;
}

// From original: cashHrpExpand
function cashHrpExpand(hrp) {
    const expanded = [];
    for (let char of hrp) {
        expanded.push(char.charCodeAt(0) & 31);
    }
    expanded.push(0);
    return expanded;
}

// From original: cashPolymod
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

// From original: cashCreateChecksum
function cashCreateChecksum(hrp, data) {
    const values = cashHrpExpand(hrp).concat(data);
    const mod = cashPolymod(values.concat(new Array(8).fill(0)));
    const checksum = [];
    for (let i = 0; i < 8; i++) {
        checksum.push(Number((mod >> (5n * (7n - BigInt(i)))) & 31n));
    }
    return checksum;
}

// From original: hash160
function hash160(pubkey) {
    return crypto.createHash('ripemd160').update(sha256(pubkey)).digest();
}

// From original: doubleSha256
function doubleSha256(buffer) {
    return sha256(sha256(buffer));
}

// From original: encodeDer
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

// Custom: deriveCashAddr
function deriveCashAddr(pkh, prefix = 'bitcoincash') {
    let versionByte = 0;
    let cashPayload = [versionByte, ...Array.from(pkh)];
    let cashData5 = convertbits(cashPayload, 8, 5, true);
    const combined = cashData5.concat(cashCreateChecksum(prefix, cashData5));
    return prefix + ':' + combined.map(d => CHARSET[d]).join('');
}

// Custom: encodeOutpoints (LE concat txid + index)
function encodeOutpoints(inputs) {
    let buf = new Uint8Array(inputs.reduce((total, i) => total + 36, 0)); // 32 txid + 4 index per input
    let offset = 0;
    for (let i of inputs) {
        buf.set(i.outpointTransactionHash, offset);
        offset += 32;
        new DataView(buf.buffer, offset).setUint32(0, i.outpointIndex, true); // LE
        offset += 4;
    }
    return buf;
}

// Custom: encodeSequenceNumbers (LE concat sequences)
function encodeSequenceNumbers(inputs) {
    let buf = new Uint8Array(inputs.length * 4);
    let offset = 0;
    for (let i of inputs) {
        new DataView(buf.buffer, offset).setUint32(0, i.sequenceNumber, true); // LE
        offset += 4;
    }
    return buf;
}

// Custom: encodeOutputs (LE value + script len + script)
function encodeOutputs(outputs) {
    let totalSize = outputs.reduce((total, o) => total + 8 + 1 + o.lockingBytecode.length, 0);
    let buf = new Uint8Array(totalSize);
    let offset = 0;
    for (let o of outputs) {
        new DataView(buf.buffer, offset).setBigUint64(0, o.valueSatoshis, true); // LE
        offset += 8;
        buf[offset++] = o.lockingBytecode.length;
        buf.set(o.lockingBytecode, offset);
        offset += o.lockingBytecode.length;
    }
    return buf;
}

// Custom NIP-04 encrypt implementation
function nip04Encrypt(privkeyBytes, pubkeyHex, text) {
    const privkeyHex = bytesToHex(privkeyBytes);
    const sharedPoint = secp256k1.getSharedSecret(privkeyHex, '02' + pubkeyHex);
    const sharedX = sharedPoint.slice(1, 33);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(sharedX), iv);
    let encryptedMessage = cipher.update(text, 'utf8', 'base64');
    encryptedMessage += cipher.final('base64');
    const ivBase64 = iv.toString('base64');
    return `${encryptedMessage}?iv=${ivBase64}`;
}

const RPC_URL = 'http://127.0.0.1:8332';
const RPC_USER = 'rewt';
const RPC_PASS = 'EXNRm12jeIBNbUk0euQ+tIOGwUPHVN+X';

// 1. Generate sender's nsec/npub
const senderPrivBytes = generateSecretKey();
const senderPub = getPublicKey(senderPrivBytes);
const senderNsec = nip19.nsecEncode(senderPrivBytes);
const senderNpub = nip19.npubEncode(senderPub);
console.log(`Sender nsec: ${senderNsec}`);
console.log(`Sender npub: ${senderNpub}`);

// Derive sender's BCH address
const senderCompressedPub = secp256k1.getPublicKey(senderPrivBytes, true);
const senderPkh = hash160(senderCompressedPub);
const senderCashAddr = deriveCashAddr(senderPkh);
console.log(`Fund sender address with at least 2000 sats: ${senderCashAddr}`);

// 2. Prompt for recipient npub
const recipientNpub = readlineSync.question('Enter recipient npub: ');

// 3. Derive BCH CashAddr from npub
const { type, data: recipientPub } = nip19.decode(recipientNpub);
if (type !== 'npub') {
    console.error('Invalid npub');
    process.exit(1);
}
const recipientPubBytes = hexToBytes(recipientPub);
const recipientCompressed = new Uint8Array(33);
recipientCompressed[0] = 0x02; // Assuming even y as per BIP-340 lift_x
recipientCompressed.set(recipientPubBytes, 1);
const recipientPkh = hash160(recipientCompressed);
const recipientCashAddr = deriveCashAddr(recipientPkh);
console.log(`Derived BCH Addr: ${recipientCashAddr}`);

// Prompt for sats to send
const satsInput = readlineSync.question('Enter amount of sats to send: ');
const amount = BigInt(satsInput);
const estimatedTxSize = amount > 0n ? 226 : 148; // With/without change
const fee = BigInt(estimatedTxSize) * 1n; // 1 sat/byte

// RPC helper
async function rpcCall(method, params = []) {
    const res = await axios.post(RPC_URL, {
        jsonrpc: '1.0',
        id: 'poc',
        method,
        params
    }, {
        auth: { username: RPC_USER, password: RPC_PASS }
    });
    if (res.data.error) throw new Error(res.data.error.message);
    return res.data.result;
}

// Fetch UTXOs
async function getUtxos(addr) {
    return await rpcCall('listunspent', [0, 9999999, [addr]]);
}

const utxos = await getUtxos(senderCashAddr);
if (utxos.length === 0) {
    console.error('No UTXOs found - fund the sender address');
    process.exit(1);
}
const input = utxos.find(u => BigInt(Math.floor(u.amount * 1e8)) >= amount + fee); // Find suitable UTXO
if (!input) {
    console.error('Insufficient funds');
    process.exit(1);
}

const inputs = [{
    outpointTransactionHash: Uint8Array.from(Buffer.from(input.txid, 'hex').reverse()),
    outpointIndex: input.vout,
    sequenceNumber: 0xffffffff,
    valueSatoshis: BigInt(Math.floor(input.amount * 1e8)),
    lockingBytecode: Uint8Array.from(Buffer.from(input.scriptPubKey, 'hex')),
    unlockingBytecode: new Uint8Array()
}];

const outputs = [{
    lockingBytecode: cashAddressToLockingBytecode(recipientCashAddr).bytecode,
    valueSatoshis: amount
}];

const change = inputs[0].valueSatoshis - amount - fee;
if (change > 546n) { // Dust limit
    outputs.push({
        lockingBytecode: cashAddressToLockingBytecode(senderCashAddr).bytecode,
        valueSatoshis: change
    });
}

const txConfig = {
    version: 2,
    inputs: inputs,
    outputs: outputs,
    locktime: 0
};

const { transaction: tx } = generateTransaction(txConfig);

const transactionOutpoints = doubleSha256(encodeOutpoints(inputs));
const transactionSequenceNumbers = doubleSha256(encodeSequenceNumbers(inputs));
const transactionOutputs = doubleSha256(encodeOutputs(outputs));
const coveredBytecode = inputs[0].lockingBytecode;
const coveredBytecodeLength = bigIntToCompactUint(BigInt(coveredBytecode.length)).bytes;
const sighashType = 0x41;

const serialization = new Uint8Array([
  ...numberToBinUint32LE(txConfig.version),
  ...transactionOutpoints,
  ...transactionSequenceNumbers,
  ...inputs[0].outpointTransactionHash,
  ...numberToBinUint32LE(inputs[0].outpointIndex),
  ...coveredBytecodeLength,
  ...coveredBytecode,
  ...bigIntToBinUint64LE(inputs[0].valueSatoshis),
  ...numberToBinUint32LE(inputs[0].sequenceNumber),
  ...transactionOutputs,
  ...numberToBinUint32LE(txConfig.locktime),
  ...numberToBinUint32LE(sighashType)
]);

const preimage = doubleSha256(serialization);

const sig = secp256k1.sign(preimage, senderPrivBytes);
const derSig = encodeDer(sig.r, sig.s);
const sigWithType = new Uint8Array([...derSig, sighashType]);

tx.inputs[0].unlockingBytecode = new Uint8Array([...sigWithType, ...senderCompressedPub]);

const signedTx = encodeTransaction(tx);
const signedTxHex = Buffer.from(signedTx).toString('hex');

const txid = await rpcCall('sendrawtransaction', [signedTxHex]);
console.log(`Tx sent: ${txid}`);

// 5. Notify via DM
const pool = new SimplePool();
const relayUrls = ['wss://relay.damus.io'];
const content = nip04Encrypt(senderPrivBytes, recipientPub, `Sent ${amount} sats BCH to your npub-derived addr: ${recipientCashAddr}. Tx: ${txid}. Claim with your nsec!`);
const eventTemplate = {
  kind: 4,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['p', recipientPub]],
  content
};
const signedEvent = finalizeEvent(eventTemplate, senderPrivBytes);
await Promise.all(pool.publish(relayUrls, signedEvent));
console.log('DM sent');