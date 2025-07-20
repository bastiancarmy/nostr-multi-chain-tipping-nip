const { instantiateBCH, createTransaction } = require('@bitauth/libauth');

// Init libauth
const { now } = await instantiateBCH();

// Sample: Build tx to derived address with CashToken
const tx = createTransaction({
  version: 2,
  inputs: [/* user UTXOs */],
  outputs: [{
    lockingBytecode: ['OP_DUP', 'OP_HASH160', pkh, 'OP_EQUALVERIFY', 'OP_CHECKSIG'],
    valueSatoshis: 1000,
    token: { category: 'token-id-hex', amount: 100 }  // Fungible CashToken
  }]
});

// Sign with nsec-derived privkey
// Broadcast via API