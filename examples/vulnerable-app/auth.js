const crypto = require('crypto');
const forge = require('node-forge');

// Quantum-vulnerable: RSA + EC keygen
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

// Broken: DES + RC4 referenced
const legacy = crypto.createCipheriv('des-ecb', key, null); // DES + ECB
const rc4 = 'RC4';

// node-forge RSA
const kp = forge.pki.rsa.generateKeyPair(2048);

module.exports = { publicKey, ec, kp };
