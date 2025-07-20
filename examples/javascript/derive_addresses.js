import * as secp from '@noble/secp256k1';
import { ripemd160 } from 'ethereum-cryptography/ripemd160.js';
import { sha256 } from 'ethereum-cryptography/sha256.js';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import { bech32 } from '@scure/base';

// Sample valid npub (from demo; replace with your own)
const npub = 'npub107jk7htfv44x6jzn7ud3kmvd3fe36cff4k3j6l9vklu3dttmex7sx7cezn';

// Decode npub to x-only pub bytes
const decoded = bech32.decode(npub);
const pubBytes = new Uint8Array(bech32.fromWords(decoded.words));

// Compress pub (add parity byte: 02 even, 03 odd)
const parity = pubBytes[31] % 2 === 0 ? 0x02 : 0x03;
const compressedPub = new Uint8Array(33);
compressedPub[0] = parity;
compressedPub.set(pubBytes, 1);

// BCH hash160
const hash160 = (x) => ripemd160(sha256(x));
const pkh = hash160(compressedPub);
console.log('PKH for BCH (hex):', Buffer.from(pkh).toString('hex'));

// ETH: Keccak of uncompressed
const point = secp.Point.fromHex(compressedPub);
const uncompressed = point.toRawBytes(false).slice(1);
const ethHash = keccak256(uncompressed).slice(-20);
const ethAddr = '0x' + Buffer.from(ethHash).toString('hex');
console.log('Derived ETH Address:', ethAddr);