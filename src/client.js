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
  let phone;
  let username;
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

    async register(_email, _phone, _password, _additionalData = {}) {
      email = _email;
      cryptoMetadata = lib.getDefaultCryptoMetadata();
      seed = lib.generateMnemonic();
      const primaryWallet = lib.getKeypairByMnemonic(seed, 0, cryptoMetadata.derivationPath);

      const walletData = {
        email: _email,
        primaryAddress: primaryWallet.address,
        cryptoMetadataJson: JSON.stringify(cryptoMetadata),
        ..._additionalData
      };

      if(_email) {
        const emailPasswordDerivedKey = lib.getPasswordDerivedKey(_password, _email, cryptoMetadata.iterations, cryptoMetadata.kdf);
        walletData.emailEncryptedSeed = lib.encrypt(emailPasswordDerivedKey, seed, cryptoMetadata.cryptoCounter);
        walletData.emailPasswordHash = lib.getPasswordHash(emailPasswordDerivedKey, _password);
      }

      if(_phone) {
        const phonePasswordDerivedKey = lib.getPasswordDerivedKey(_password, _phone, cryptoMetadata.iterations, cryptoMetadata.kdf);
        walletData.phoneEncryptedSeed = lib.encrypt(phonePasswordDerivedKey, seed, cryptoMetadata.cryptoCounter);
        walletData.phonePasswordHash = lib.getPasswordHash(phonePasswordDerivedKey, _password);
      }

      const wallet = await http.post('v1/create-wallet', walletData).then(wrapResponse);

      username = wallet.username;

      this.setEncryptedSeedToLocalStorage();

      return wallet;
    },

    async login(_login, _password, _method = 'email') {
      let wallet;

      if(_method === 'email') {
        email = _login;
        await this.fetchCryptoMetadataByEmail();

        const emailPasswordDerivedKey = lib.getPasswordDerivedKey(_password, email, cryptoMetadata.iterations, cryptoMetadata.kdf);
        const emailPasswordHash = lib.getPasswordHash(emailPasswordDerivedKey, _password);
        wallet = await this.getWalletByEmailAndPasswordHash(email, emailPasswordHash);

        seed = lib.decrypt(emailPasswordDerivedKey, wallet.emailEncryptedSeed, cryptoMetadata.cryptoCounter);

      } else if(_method === 'phone') {
        phone = _login;
        await this.fetchCryptoMetadataByPhone();

        const phonePasswordDerivedKey = lib.getPasswordDerivedKey(_password, phone, cryptoMetadata.iterations, cryptoMetadata.kdf);
        const phonePasswordHash = lib.getPasswordHash(phonePasswordDerivedKey, _password);
        wallet = await this.getWalletByPhoneAndPasswordHash(phone, phonePasswordHash);

        seed = lib.decrypt(phonePasswordDerivedKey, wallet.phoneEncryptedSeed, cryptoMetadata.cryptoCounter);

      } else if(_method === 'wallet') {
        wallet = _login;

        cryptoMetadata = JSON.parse(wallet.cryptoMetadataJson);

        if(wallet.phone) {
          phone = wallet.phone;
          const phonePasswordDerivedKey = lib.getPasswordDerivedKey(_password, phone, cryptoMetadata.iterations, cryptoMetadata.kdf);
          seed = lib.decrypt(phonePasswordDerivedKey, wallet.phoneEncryptedSeed, cryptoMetadata.cryptoCounter);
        } else if(wallet.email) {
          email = wallet.email;
          const emailPasswordDerivedKey = lib.getPasswordDerivedKey(_password, email, cryptoMetadata.iterations, cryptoMetadata.kdf);
          seed = lib.decrypt(emailPasswordDerivedKey, wallet.emailEncryptedSeed, cryptoMetadata.cryptoCounter);
        }

      } else {
        throw Error('unknown_method');
      }

      username = wallet.username;

      this.setEncryptedSeedToLocalStorage();

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

    async exportSeed() {
      if (seed) {
        return seed;
      }

      if(localStorage.getItem('GeesomeWallet:encryptedSeed')) {
        await this.getEncryptedSeedFromLocalStorage();
      }
      return seed;
    },

    setEncryptedSeedToLocalStorage() {
      localStorage.setItem('GeesomeWallet:email', email);
      localStorage.setItem('GeesomeWallet:phone', phone);
      localStorage.setItem('GeesomeWallet:username', username);
      return this.getSession().then(({ secret }) => {
        if(!secret) {
          throw new Error('secret_is_null');
        }
        if(!seed) {
          throw new Error('seed_is_null');
        }
        localStorage.setItem('GeesomeWallet:encryptedSeed', lib.encrypt(secret, seed));
        return true;
      });
    },

    async getEncryptedSeedFromLocalStorage() {
      const { secret } = await this.getSession();
      if(!secret) {
        throw new Error('secret_is_null');
      }
      const encryptedSeed = localStorage.getItem('GeesomeWallet:encryptedSeed');
      if(!encryptedSeed) {
        throw new Error('emailEncryptedSeed_is_null');
      }
      email = this.getLocalEmail();
      phone = this.getLocalPhone();
      seed = lib.decrypt(secret, encryptedSeed);

      await this.fetchCryptoMetadata();
      return true;
    },

    getLocalEmail() {
      return localStorage.getItem('GeesomeWallet:email');
    },

    getLocalPhone() {
      return localStorage.getItem('GeesomeWallet:phone');
    },

    getLocalUsername() {
      return localStorage.getItem('GeesomeWallet:username');
    },

    async getSession() {
      return http.post('v1/get-session').then(wrapResponse);
    },

    async fetchCryptoMetadata() {
      if(email && email !== 'undefined' && email !== 'null') {
        await this.fetchCryptoMetadataByEmail();
      } else if(phone && phone !== 'undefined' && phone !== 'null') {
        await this.fetchCryptoMetadataByPhone();
      }
    },

    async fetchCryptoMetadataByEmail() {
      cryptoMetadata = await this.getCryptoMetadataByEmail(email);
    },

    async fetchCryptoMetadataByPhone() {
      cryptoMetadata = await this.getCryptoMetadataByPhone(phone);
    },

    async getCryptoMetadataByEmail(_email) {
      return http.post('v1/get-crypto-metadata-by-email', { email: _email }).then(wrapResponse);
    },

    async getCryptoMetadataByPhone(_phone) {
      return http.post('v1/get-crypto-metadata-by-phone', { phone: _phone }).then(wrapResponse);
    },

    async getWalletByEmailAndPasswordHash(email, emailPasswordHash) {
      return http.post('v1/get-wallet-by-email-and-password-hash', { email, emailPasswordHash }).then(wrapResponse);
    },

    async getWalletByPhoneAndPasswordHash(phone, phonePasswordHash) {
      return http.post('v1/get-wallet-by-phone-and-password-hash', { phone, phonePasswordHash }).then(wrapResponse);
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