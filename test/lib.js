/*
 * Copyright ©️ 2019-2020 GaltProject Society Construction and Terraforming Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka)
 *
 * Copyright ©️ 2019-2020 Galt•Core Blockchain Company
 * (Founded by [Nikolai Popeka](https://github.com/npopeka) by
 * [Basic Agreement](ipfs/QmaCiXUmSrP16Gz8Jdzq6AJESY1EAANmmwha15uR3c1bsS)).
 */

/* eslint max-nested-callbacks: ["error", 6] */
/* eslint-env mocha */
'use strict';

const chai = require('chai');
const assert = require('assert');
const dirtyChai = require('dirty-chai');
chai.use(dirtyChai);

const _ = require('lodash');

const lib = require('../src/lib');

describe('lib', function () {

  it('should encrypt and decrypt correctly', function () {
    const pass = 'ff9aad63798d60acdae4034a1075c7facbc1914704d2b036bd9dab6bf3f89efc';
    const text = 'Hello world';

    const encryptedText = lib.encrypt(pass, text);
    const decryptedText = lib.decrypt(pass, encryptedText);

    assert.equal(text, decryptedText);

    const incorrectDecryptedText = lib.decrypt(pass.replace('c', 'b'), encryptedText);

    assert.notEqual(text, incorrectDecryptedText);
  });

  it('generateMnemonic', function () {
    const seed = lib.generateMnemonic();
    assert.equal(_.isString(seed), true);
  });

  it('getKeypairByMnemonic', function () {
    const wallet = lib.getKeypairByMnemonic('beauty model hen divide three siege virtual ostrich autumn license earth lottery');
    assert.equal(wallet.address, '0x53364bC3F9D549c975d0678F0468Aab01534C142');
    assert.equal(wallet.privateKey, '0xa10f176408d14f58b6f192d0586d89bdb4508fde2cd912c0edd669f2c64c781a');
  });

  it('getKeypairByMnemonic', function () {
    const wallet = lib.getKeypairByMnemonic('beauty model hen divide three siege virtual ostrich autumn license earth lottery');
    assert.equal(wallet.address, '0x53364bC3F9D549c975d0678F0468Aab01534C142');
    assert.equal(wallet.privateKey, '0xa10f176408d14f58b6f192d0586d89bdb4508fde2cd912c0edd669f2c64c781a');
  });

  it('should correctly sign transactions', function () {
    const txParams = {
      data: "0x12cd12ef00000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000093a8000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000200db1977462ca57f97f909585c7da5231a17723b9f7838734b751b138cb23c8ae60000000000000000000000000000000000000000000000000000000000000001310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000034c4f434b45525f455448000000000000000000000000000000000000000000004d41524b45545f45544800000000000000000000000000000000000000000000434f4e54524f4c4c45525f50524f504f53414c5f4554480000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000002386f26fc10000000000000000000000000000000000000000000000000000002386f26fc1000000000000000000000000000000000000000000000000000000038d7ea4c68000",
      from: "0x53364bC3F9D549c975d0678F0468Aab01534C142",
      gas: "0x6c8e27",
      gasPrice: "0x12a05f200",
      nonce: "0x0",
      to: "0x2d1e4ea5ebb292ab4c9a9694b75364b4c0a50685",
      value: "0x2386f26fc10000",
    };

    lib.signAndGetRawTx('0xa10f176408d14f58b6f192d0586d89bdb4508fde2cd912c0edd669f2c64c781a', txParams);
  })
});
