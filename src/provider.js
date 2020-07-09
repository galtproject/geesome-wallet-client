/*
 * Copyright ©️ 2018-2020 Galt•Project Society Construction and Terraforming Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka)
 *
 * Copyright ©️ 2018-2020 Galt•Core Blockchain Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka) by
 * [Basic Agreement](ipfs/QmaCiXUmSrP16Gz8Jdzq6AJESY1EAANmmwha15uR3c1bsS)).
 */

const ProviderEngine = require('web3-provider-engine');
const CacheSubprovider = require('web3-provider-engine/subproviders/cache.js');
const FixtureSubprovider = require('web3-provider-engine/subproviders/fixture.js');
const FilterSubprovider = require('web3-provider-engine/subproviders/filters.js');
// const VmSubprovider = require('web3-provider-engine/subproviders/vm.js');
const HookedWalletSubprovider = require('web3-provider-engine/subproviders/hooked-wallet.js');
const NonceSubprovider = require('web3-provider-engine/subproviders/nonce-tracker.js');
const RpcSubprovider = require('web3-provider-engine/subproviders/rpc.js');

module.exports = (options) => {
  const {rpcUrl, backendUrl, password, email, phone, wallet} = options;
  const engine = new ProviderEngine();

  const client = require('./client')({ backendUrl });

  if(email && password) {
    client.login(email, password, 'email').catch((err) => {
      console.log('login error', err);
    });
  } else if(phone && password) {
    client.login(phone, password, 'phone').catch((err) => {
      console.log('login error', err);
    });
  } else {
    client.getEncryptedSeedFromLocalStorage().catch((err) => {
      console.log('getEncryptedSeedFromLocalStorage error', err);
    })
  }

  // static results
  engine.addProvider(new FixtureSubprovider({
    web3_clientVersion: 'ProviderEngine/v0.0.0/javascript',
    net_listening: true,
    eth_hashrate: '0x00',
    eth_mining: false,
    eth_syncing: true,
  }));

  // cache layer
  engine.addProvider(new CacheSubprovider());
  // filters
  engine.addProvider(new FilterSubprovider());
  // pending nonce
  engine.addProvider(new NonceSubprovider());
  // vm
  // engine.addProvider({ setEngine() {} });

  // id mgmt
  engine.addProvider(new HookedWalletSubprovider({
    getAccounts: async function (cb) {
      await client.waitForReady().catch(cb);
      cb(null, client.getAccountsAddresses());
    },
    approveTransaction: async function (txParams, cb) {
      await client.waitForReady().catch(cb);
      //TODO: show confirmation window
      cb(null, true);
    },
    signTransaction: async function (txParams, cb) {
      await client.waitForReady().catch(cb);
      this.emitPayload({ method: 'net_version', params: [] }, function(err, res){
        if (err) return cb(err);
        txParams.chainId = parseInt(res.result);
        cb(null, client.signTransaction(txParams));
      });
    },
    signMessage: async function (msgParams, cb) {
      await client.waitForReady().catch(cb);
      cb(null, client.signMessage(msgParams));
    },
    signTypedMessage: async function (msgParams, cb) {
      await client.waitForReady().catch(cb);
      cb(null, client.signTypedData(msgParams));
    }
  }));

  // data source
  engine.addProvider(new RpcSubprovider({rpcUrl}));

  // log new blocks
  engine.on('block', function (block) {
    // console.log('================================');
    // console.log('BLOCK CHANGED:', '#' + block.number.toString('hex'), '0x' + block.hash.toString('hex'));
    // console.log('================================');
  });

  // network connectivity error
  engine.on('error', function (err) {
    // report connectivity errors
    console.error(err.stack)
  });

  // start polling for blocks
  engine.start();

  // var web3 = new Web3(engine);
  return engine;
};