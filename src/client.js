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

  const http = axios.create({ baseURL: backendUrl, withCredentials: true });

  const wrapResponse = (response) => {
    return response.data;
  };

  let email;
  let seed;
  let cryptoMetadata;
  let activeAccountIndex = 0;
  let accountsByIndexes = {

  };

  const getAccountByIndex = (index) => {
    if(!accountsByIndexes[index]) {
      accountsByIndexes[index] = lib.getKeypairByMnemonic(seed, index, cryptoMetadata.derivationPath);
    }
    return accountsByIndexes[index];
  };

  const getActiveAccount = () => {
    return getAccountByIndex(activeAccountIndex);
  };

  return {
    isReady() {
      return !!seed && !!cryptoMetadata;
    },

    async waitForReady(times = 0) {
      if(this.isReady()) {
        return;
      }
      if(times > 10) {
        throw new Error("failed_to_get_ready");
      }
      return new Promise((resolve) => {
        setTimeout(() => {
          if(this.isReady()) {
            resolve();
          } else {
            resolve(this.waitForReady(times++));
          }
        }, 300);
      })
    },

    async register(_email, _password, _additionalData = {}) {
      email = _email;
      cryptoMetadata = lib.getDefaultCryptoMetadata();
      seed = lib.generateMnemonic();
      const primaryWallet = lib.getKeypairByMnemonic(seed, 0, cryptoMetadata.derivationPath);

      const passwordDerivedKey = lib.getPasswordDerivedKey(_password, _email, cryptoMetadata.iterations, cryptoMetadata.kdf);

      const encryptedSeed = lib.encrypt(passwordDerivedKey, seed, cryptoMetadata.cryptoCounter);

      const passwordHash = lib.getPasswordHash(passwordDerivedKey, _password);

      const wallet = await http.post('v1/create-wallet', {
        email: _email,
        passwordHash,
        encryptedSeed,
        primaryAddress: primaryWallet.address,
        cryptoMetadataJson: JSON.stringify(cryptoMetadata),
        ..._additionalData
      }).then(wrapResponse);

      //TODO: figure out - why it got the old session right after create-wallet request
      // setTimeout(() => {
        this.setEncryptedSeedToLocalStorage();
      // }, 5000);

      return wallet;
    },

    async login(_email, _password) {
      email = _email;
      await this.fetchCryptoMetadataByEmail(_email);

      const passwordDerivedKey = lib.getPasswordDerivedKey(_password, _email, cryptoMetadata.iterations, cryptoMetadata.kdf);
      const passwordHash = lib.getPasswordHash(passwordDerivedKey, _password);
      const wallet = await this.getWalletByEmailAndPasswordHash(_email, passwordHash);

      seed = lib.decrypt(passwordDerivedKey, wallet.encryptedSeed, cryptoMetadata.cryptoCounter);

      // setTimeout(() => {
        this.setEncryptedSeedToLocalStorage();
      // }, 5000);

      return wallet;
    },

    async updateWallet(_walletData) {
      const expiredOn = Math.round(new Date().getTime() / 1000) + 60 * 5;
      const messageParams = [
        { type: 'string', name: 'action', value: 'updateWallet'},
        { type: 'string', name: 'walletData', value: JSON.stringify(_walletData)},
        { type: 'string', name: 'expiredOn', value: expiredOn}
      ];

      const signature = this.signMessage(messageParams);
      return http.post('v1/update-wallet', {
        walletData: _walletData,
        signature,
        expiredOn,
        primaryAddress: getActiveAccount().address
      }).then(wrapResponse);
    },

    async setEncryptedSeedToLocalStorage() {
      const { secret } = await this.getSession();
      if(!secret) {
        throw new Error('secret_is_null');
      }
      if(!seed) {
        throw new Error('seed_is_null');
      }
      localStorage.setItem('GeesomeWallet:encryptedSeed', lib.encrypt(secret, seed));
      localStorage.setItem('GeesomeWallet:email', email);
      return true;
    },

    async getEncryptedSeedFromLocalStorage() {
      const { secret } = await this.getSession();
      if(!secret) {
        throw new Error('secret_is_null');
      }
      const encryptedSeed = localStorage.getItem('GeesomeWallet:encryptedSeed');
      if(!encryptedSeed) {
        throw new Error('encryptedSeed_is_null');
      }
      email = localStorage.getItem('GeesomeWallet:email');
      seed = lib.decrypt(secret, encryptedSeed);

      await this.fetchCryptoMetadataByEmail(email);
      return true;
    },

    async getSession() {
      return http.post('v1/get-session').then(wrapResponse);
    },

    async fetchCryptoMetadataByEmail(email) {
      cryptoMetadata = await this.getCryptoMetadataByEmail(email);
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