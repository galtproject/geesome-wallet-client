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
});
