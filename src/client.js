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
    setWorker(_worker) {
      this.worker = _worker;
    },

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

    async register(_email, _phone, _username, _password, _additionalData = {}) {
      email = _email;
      username = _username;
      phone = _phone;

      cryptoMetadata = lib.getDefaultCryptoMetadata();
      seed = lib.generateMnemonic();
      const primaryWallet = lib.getKeypairByMnemonic(seed, 0, cryptoMetadata.derivationPath);

      const walletData = {
        ..._additionalData,
        email,
        username,
        phone,
        primaryAddress: primaryWallet.address,
        cryptoMetadataJson: JSON.stringify(cryptoMetadata)
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

      if(_username) {
        const usernamePasswordDerivedKey = lib.getPasswordDerivedKey(_password, _username, cryptoMetadata.iterations, cryptoMetadata.kdf);
        walletData.usernameEncryptedSeed = lib.encrypt(usernamePasswordDerivedKey, seed, cryptoMetadata.cryptoCounter);
        walletData.usernamePasswordHash = lib.getPasswordHash(usernamePasswordDerivedKey, _password);
      }

      const {wallet, pendingWallet} = await http.post('v1/register', walletData).then(wrapResponse);

      this.setEncryptedSeedToLocalStorage(wallet || pendingWallet, seed);

      return {wallet, pendingWallet, seed};
    },

    async registerByWorker(_email, _phone, _username, _password, _additionalData = {}) {
      const {wallet, pendingWallet, seed: _seed} = await this.worker.callMethod('register', {
        options,
        args: [_email, _phone, _username, _password, _additionalData]
      });

      this.setEncryptedSeedToLocalStorage(wallet || pendingWallet, _seed);

      return {wallet, pendingWallet, seed: _seed};
    },

    async confirmWallet(confirmationMethod, value, code) {
      const wallet = await http.post('v1/confirm-wallet', {confirmationMethod, value, code}).then(wrapResponse);

      this.setEncryptedSeedToLocalStorage(wallet, seed);

      return wallet;
    },

    async confirmWalletByAdmin(pendingWalletId, confirmMethods) {
      await this.getEncryptedSeedFromLocalStorage();

      const messageParams = [
        { type: 'string', name: 'action', value: 'confirmPendingWallet'},
        { type: 'string', name: 'pendingWalletId', value: pendingWalletId.toString(10)},
        { type: 'string', name: 'confirmMethods', value: confirmMethods}
      ];

      const signature = this.signMessage(messageParams);
      return http.post('v1/admin/confirm-wallet', {
        signature,
        pendingWalletId,
        confirmMethods
      }).then(wrapResponse);
    },

    async login(_login, _password, _method = 'email') {
      let wallet;

      if(_method === 'email') {
        email = _login;
        await this.fetchCryptoMetadataByEmail();

        const {emailPasswordDerivedKey, wallet: _wallet} = await this.getWalletAndPasswordDerivedKeyByEmail(email, _password);

        wallet = _wallet;
        seed = lib.decrypt(emailPasswordDerivedKey, wallet.emailEncryptedSeed, cryptoMetadata.cryptoCounter);

      } else if(_method === 'phone') {
        phone = _login;
        await this.fetchCryptoMetadataByPhone();

        const {phonePasswordDerivedKey, wallet: _wallet} = await this.getWalletAndPasswordDerivedKeyByPhone(phone, _password);

        wallet = _wallet;
        seed = lib.decrypt(phonePasswordDerivedKey, wallet.phoneEncryptedSeed, cryptoMetadata.cryptoCounter);

      } else if(_method === 'username') {
        username = _login;
        await this.fetchCryptoMetadataByUsername();

        const {phonePasswordDerivedKey, wallet: _wallet} = await this.getWalletAndPasswordDerivedKeyByUsername(username, _password);

        wallet = _wallet;
        seed = lib.decrypt(phonePasswordDerivedKey, wallet.usernameEncryptedSeed, cryptoMetadata.cryptoCounter);

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
        } else if(wallet.username) {
          username = wallet.username;
          const usernamePasswordDerivedKey = lib.getPasswordDerivedKey(_password, username, cryptoMetadata.iterations, cryptoMetadata.kdf);
          seed = lib.decrypt(usernamePasswordDerivedKey, wallet.usernameEncryptedSeed, cryptoMetadata.cryptoCounter);
        }

      } else {
        throw Error('unknown_method');
      }

      this.setEncryptedSeedToLocalStorage(wallet, seed);

      return wallet;
    },

    async getWalletAndPasswordDerivedKeyByEmail(_email, _password) {
      const emailPasswordDerivedKey = lib.getPasswordDerivedKey(_password, _email, cryptoMetadata.iterations, cryptoMetadata.kdf);
      const emailPasswordHash = lib.getPasswordHash(emailPasswordDerivedKey, _password);
      const wallet = await this.getWalletByEmailAndPasswordHash(_email, emailPasswordHash);
      return {emailPasswordDerivedKey, wallet};
    },

    async getWalletAndPasswordDerivedKeyByPhone(_phone, _password) {
      const phonePasswordDerivedKey = lib.getPasswordDerivedKey(_password, _phone, cryptoMetadata.iterations, cryptoMetadata.kdf);
      const phonePasswordHash = lib.getPasswordHash(phonePasswordDerivedKey, _password);
      const wallet = await this.getWalletByPhoneAndPasswordHash(_phone, phonePasswordHash);
      return {phonePasswordDerivedKey, wallet};
    },

    async getWalletAndPasswordDerivedKeyByUsername(_username, _password) {
      const usernamePasswordDerivedKey = lib.getPasswordDerivedKey(_password, _username, cryptoMetadata.iterations, cryptoMetadata.kdf);
      const usernamePasswordHash = lib.getPasswordHash(usernamePasswordDerivedKey, _password);
      const wallet = await this.getWalletByUsernameAndPasswordHash(_username, usernamePasswordHash);
      return {usernamePasswordDerivedKey, wallet};
    },

    async updateWallet(_walletData) {
      await this.getEncryptedSeedFromLocalStorage();

      if((_walletData.phone || _walletData.email) && !_walletData.password) {
        throw new Error("password_required")
      }

      if(_walletData.email) {
        const emailPasswordDerivedKey = lib.getPasswordDerivedKey(_walletData.password, _walletData.email, cryptoMetadata.iterations, cryptoMetadata.kdf);
        _walletData.emailEncryptedSeed = lib.encrypt(emailPasswordDerivedKey, seed, cryptoMetadata.cryptoCounter);
        _walletData.emailPasswordHash = lib.getPasswordHash(emailPasswordDerivedKey, _walletData.password);
      }

      if(_walletData.phone) {
        const phonePasswordDerivedKey = lib.getPasswordDerivedKey(_walletData.password, _walletData.phone, cryptoMetadata.iterations, cryptoMetadata.kdf);
        _walletData.phoneEncryptedSeed = lib.encrypt(phonePasswordDerivedKey, seed, cryptoMetadata.cryptoCounter);
        _walletData.phonePasswordHash = lib.getPasswordHash(phonePasswordDerivedKey, _walletData.password);
      }

      if(_walletData.username) {
        const usernamePasswordDerivedKey = lib.getPasswordDerivedKey(_walletData.password, _walletData.username, cryptoMetadata.iterations, cryptoMetadata.kdf);
        _walletData.usernameEncryptedSeed = lib.encrypt(usernamePasswordDerivedKey, seed, cryptoMetadata.cryptoCounter);
        _walletData.usernamePasswordHash = lib.getPasswordHash(usernamePasswordDerivedKey, _walletData.password);
      }

      const expiredOn = Math.round(new Date().getTime() / 1000) + 60 * 5;
      const messageParams = [
        { type: 'string', name: 'action', value: 'updateWallet'},
        { type: 'string', name: 'walletData', value: JSON.stringify(_walletData)},
        { type: 'string', name: 'expiredOn', value: expiredOn.toString(10)}
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

    setEncryptedSeedToLocalStorage(wallet, _seed) {
      if(!localStorage) {
        return;
      }
      const {_email, _phone, _username} = wallet;
      localStorage.setItem('GeesomeWallet:email', _email);
      localStorage.setItem('GeesomeWallet:phone', _phone);
      localStorage.setItem('GeesomeWallet:username', _username);
      email = _email;
      phone = _phone;
      username = _username;
      seed = _seed;
      return this.getSession().then(({ secret }) => {
        if(!secret) {
          throw new Error('secret_is_null');
        }
        if(!_seed) {
          throw new Error('seed_is_null');
        }
        localStorage.setItem('GeesomeWallet:encryptedSeed', lib.encrypt(secret, _seed));
        return true;
      });
    },

    async getEncryptedSeedFromLocalStorage() {
      if((email || phone || username) && seed) {
        return true;
      }
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
      username = this.getLocalUsername();
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
      } else if(username && username !== 'undefined' && username !== 'null') {
        await this.fetchCryptoMetadataByUsername();
      }
    },

    async fetchCryptoMetadataByEmail() {
      cryptoMetadata = await this.getCryptoMetadataByEmail(email);
    },

    async fetchCryptoMetadataByPhone() {
      cryptoMetadata = await this.getCryptoMetadataByPhone(phone);
    },

    async fetchCryptoMetadataByUsername() {
      cryptoMetadata = await this.getCryptoMetadataByUsername(username);
    },

    async getCryptoMetadataByEmail(_email) {
      return http.post('v1/get-crypto-metadata-by-email', { email: _email }).then(wrapResponse);
    },

    async getCryptoMetadataByPhone(_phone) {
      return http.post('v1/get-crypto-metadata-by-phone', { phone: _phone }).then(wrapResponse);
    },

    async getCryptoMetadataByUsername(_username) {
      return http.post('v1/get-crypto-metadata-by-username', { username: _username }).then(wrapResponse);
    },

    async getWalletByEmailAndPasswordHash(email, emailPasswordHash) {
      return http.post('v1/get-wallet-by-email-and-password-hash', { email, emailPasswordHash }).then(wrapResponse);
    },

    async getWalletByPhoneAndPasswordHash(phone, phonePasswordHash) {
      return http.post('v1/get-wallet-by-phone-and-password-hash', { phone, phonePasswordHash }).then(wrapResponse);
    },

    async getWalletByUsernameAndPasswordHash(username, usernamePasswordHash) {
      return http.post('v1/get-wallet-by-username-and-password-hash', { username, usernamePasswordHash }).then(wrapResponse);
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