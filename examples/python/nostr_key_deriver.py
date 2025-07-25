from enum import Enum
import hashlib
import ecdsa

# Bech32 reference implementation (pure Python)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3

class Encoding(Enum):
    BECH32 = 1
    BECH32M = 2

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None

def bech32_decode(bech):
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_create_checksum(hrp, data, spec):
    values = bech32_hrp_expand(hrp) + data
    mod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ (spec.value if spec else 1)
    return [(mod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec=Encoding.BECH32):
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + ':' + ''.join([CHARSET[d] for d in combined])

# Sample nsec
nsec = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'

# Decode nsec to priv_bytes
hrp, data5, spec = bech32_decode(nsec)
priv_data = convertbits(data5, 5, 8, False)
priv_bytes = bytes(priv_data)
priv_hex = priv_bytes.hex()
print(f"Private key hex from nsec: {priv_hex}")

# Derive compressed pub from priv
sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
vk = sk.verifying_key
compressed_pub = vk.to_string("compressed")
compressed_hex = compressed_pub.hex()
print(f"Compressed public key hex: {compressed_hex}")

# hash160 for pubkeyhash
def hash160(x):
    return hashlib.new('ripemd160', hashlib.sha256(x).digest()).digest()

pkh = hash160(compressed_pub)
pkh_hex = pkh.hex()
print(f"Public key hash (hash160) hex: {pkh_hex}")

# BCH CashAddr (P2PKH, version 0)
version_byte = 0
cash_payload = [version_byte] + list(pkh)
cash_data5 = convertbits(cash_payload, 8, 5, True)
bch_address = bech32_encode('bitcoincash', cash_data5)
print(f"Derived BCH Address: {bch_address}")

# ETH address
uncompressed_pub = vk.to_string("uncompressed")
keccak = hashlib.sha3_256(uncompressed_pub).digest()[-20:]
keccak_hex = keccak.hex()

def eth_checksum(addr):
    addr = addr.lower()
    hashed = hashlib.sha3_256(addr.encode()).hexdigest()
    result = ''
    for i in range(len(addr)):
        if int(hashed[i], 16) >= 8:
            result += addr[i].upper()
        else:
            result += addr[i]
    return result

eth_address = '0x' + eth_checksum(keccak_hex)
print(f"Derived ETH Address: {eth_address}")