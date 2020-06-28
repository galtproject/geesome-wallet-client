/*
 * Copyright ©️ 2018-2020 Galt•Project Society Construction and Terraforming Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka)
 *
 * Copyright ©️ 2018-2020 Galt•Core Blockchain Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka) by
 * [Basic Agreement](ipfs/QmaCiXUmSrP16Gz8Jdzq6AJESY1EAANmmwha15uR3c1bsS)).
 */

const axios = require('axios');
const lib = require('./lib');

module.exports = (options) => {
  let { backendUrl } = options;

  // ad slash to the end if not present
  backendUrl = backendUrl.replace(/\/?$/, '/');

  const http = axios.create({ baseURL: backendUrl });

  const wrapResponse = (response) => {
    return response.data;
  };

  let seed;
  let cryptoMetadata;
  let activeAccountIndex = 0;

  const getAccountByIndex = (index) => {
    return lib.getKeypairByMnemonic(seed, index, cryptoMetadata.derivationPath);
  };

  const getActiveAccount = () => {
    return getAccountByIndex(activeAccountIndex);
  };

  return {
    isReady() {
      return !!seed;
    },

    async waitForReady(times = 0) {
      if(seed) {
        return;
      }
      if(times > 10) {
        throw new Error("failed_to_get_ready");
      }
      return new Promise((resolve) => {
        setTimeout(() => {
          if(seed) {
            resolve();
          } else {
            resolve(this.waitForReady(times++));
          }
        }, 300);
      })
    },

    async register(email, password) {
      cryptoMetadata = lib.getDefaultCryptoMetadata();

      seed = lib.generateMnemonic();
      const passwordDerivedKey = lib.getPasswordDerivedKey(password, email, cryptoMetadata.iterations, cryptoMetadata.kdf);

      const encryptedSeed = lib.encrypt(passwordDerivedKey, seed, cryptoMetadata.cryptoCounter);

      const passwordHash = lib.getPasswordHash(passwordDerivedKey, password);

      return http.post('v1/create-wallet', {
        email,
        passwordHash,
        encryptedSeed,
        cryptoMetadataJson: JSON.stringify(cryptoMetadata)
      }).then(wrapResponse);
    },

    async login(email, password) {
      cryptoMetadata = await this.getCryptoMetadataByEmail(email);

      const passwordDerivedKey = lib.getPasswordDerivedKey(password, email, cryptoMetadata.iterations, cryptoMetadata.kdf);
      const passwordHash = lib.getPasswordHash(passwordDerivedKey, password);
      const wallet = await this.getWalletByEmailAndPasswordHash(email, passwordHash);

      seed = lib.decrypt(passwordDerivedKey, wallet.encryptedSeed, cryptoMetadata.cryptoCounter);
      return wallet;
    },

    async getCryptoMetadataByEmail(email) {
      return http.post('v1/get-crypto-metadata-by-email', { email }).then(wrapResponse);
    },

    async getWalletByEmailAndPasswordHash(email, passwordHash) {
      return http.post('v1/get-wallet-by-email-and-password-hash', { email, passwordHash }).then(wrapResponse);
    },

    getAccountsAddresses() {
      return [getAccountByIndex(0).address];
    },

    changeAccountIndex(index) {
      activeAccountIndex = index;
    },

    signTransaction(txParams) {
      return lib.signAndGetRawTx(getActiveAccount().privateKey, txParams);
    },

    signMessage(msgParams) {
      return lib.signMessage(getActiveAccount().privateKey, msgParams);
    },

    signTypedData(dataParams) {
      return lib.signTypedData(getActiveAccount().privateKey, dataParams);
    }
  }
};