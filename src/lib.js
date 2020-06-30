/*
 * Copyright ©️ 2018-2020 Galt•Project Society Construction and Terraforming Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka)
 *
 * Copyright ©️ 2018-2020 Galt•Core Blockchain Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka) by
 * [Basic Agreement](ipfs/QmaCiXUmSrP16Gz8Jdzq6AJESY1EAANmmwha15uR3c1bsS)).
 */

const ethers = require('ethers');
const pbkdf2 = require('pbkdf2');
const aesjs = require('aes-js');
const { Transaction } = require('ethereumjs-tx');
const sigUtil = require('eth-sig-util');

const lib = {
  getDefaultCryptoMetadata() {
    return {
      derivationPath: `m/44'/60'/0'/0/`,
      iterations: 100000,
      kdf: 'sha512',
      cryptoCounter: 5,
      version: 1
    }
  },
  generateMnemonic() {
    return ethers.Wallet.createRandom()._mnemonic().phrase;
  },

  getKeypairByMnemonic(mnemonic, index = 0, derivationPath = "m/44'/60'/0'/0/") {
    const wallet = ethers.Wallet.fromMnemonic(mnemonic, `${derivationPath}${index}`);
    return {
      address: wallet.address,
      privateKey: wallet.privateKey,
    };
  },

  getPasswordDerivedKey(password, email, iterations = 100000, kfd = 'sha512') {
    email = email.toLowerCase();
    return aesjs.utils.hex.fromBytes(pbkdf2.pbkdf2Sync(password, email, iterations, 32, kfd));
  },

  getPasswordHash(passwordKey, password) {
    return aesjs.utils.hex.fromBytes(pbkdf2.pbkdf2Sync(passwordKey, password, 1, 32, 'sha512'));
  },

  encrypt(key, text, counter = 5) {
    const textBytes = aesjs.utils.utf8.toBytes(text);
    const keyBytes = lib.hexToBytes(key);

    // The counter is optional, and if omitted will begin at 1
    const aesCtr = new aesjs.ModeOfOperation.ctr(keyBytes, new aesjs.Counter(counter));
    const encryptedBytes = aesCtr.encrypt(textBytes);
    return aesjs.utils.hex.fromBytes(encryptedBytes)
  },

  decrypt(key, encryptedHex, counter = 5) {
    const encryptedBytes = lib.hexToBytes(encryptedHex);
    const keyBytes = lib.hexToBytes(key);
    // The counter mode of operation maintains internal state, so to
    // decrypt a new instance must be instantiated.
    const aesCtr = new aesjs.ModeOfOperation.ctr(keyBytes, new aesjs.Counter(counter));
    const decryptedBytes = aesCtr.decrypt(encryptedBytes);

    // Convert our bytes back into text
    return aesjs.utils.utf8.fromBytes(decryptedBytes);
  },

  hexToBuffer(hex) {
    return Buffer.from(lib.hexToBytes(hex));
  },

  hexToBytes(hex) {
    return aesjs.utils.hex.toBytes(hex.indexOf('0x') === 0 ? hex.slice(2) : hex);
  },

  signAndGetRawTx(privateKey, txParams) {
    const privateKeyBytes = lib.hexToBuffer(privateKey);
    const tx = new Transaction(txParams, {
      chain: txParams.chainId
    });
    tx.sign(privateKeyBytes);
    return '0x' + tx.serialize().toString('hex')
  },

  signMessage(privateKey, msgParams) {
    const privateKeyBytes = lib.hexToBuffer(privateKey);
    return sigUtil.signTypedMessage(privateKeyBytes, {data: msgParams}, 'V1');
  },

  signTypedData(privateKey, msgParams) {
    const privateKeyBytes = lib.hexToBuffer(privateKey);
    return sigUtil.signTypedData(privateKeyBytes, {data: msgParams});
  }
};

module.exports = lib;