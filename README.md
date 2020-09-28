# GeeSome Wallet Client

## Initialization 
```
const geesomeWallet = geesomeWallet.client({backendUrl: 'https://wallet.galtproject.io'});
```
## Register with new seed
```
const password = `SKhrSfX2`;
await geesomeWallet.register('user@email.com', '+799911112233', 'username', password);
const resultSeed = await geesomeWallet.exportSeed();
```
## Register with existing seed
```
const password = `SKhrSfX2`;
await geesomeWallet.register('user@email.com', '+799911112233', 'username', password, {
  seed: 'direct ordinary element answer novel fossil gift bag device couch disease awesome'
});
const resultSeed = await geesomeWallet.exportSeed();
```
## Confirm email code
```
const receivedByEmailCode = '112233';
await geesomeWallet.confirmWallet('email', 'user@email.com', receivedByEmailCode);
```
## Confirm phone code
```
const receivedByPhoneCode = '112233';
await geesomeWallet.confirmWallet('phone', '+799911112233', receivedByPhoneCode);
```
## Login by email
```
await geesomeWallet.login('user@email.com', password, 'email');
```
## Login by phone
```
await geesomeWallet.login('+799911112233', password, 'phone');
```
## Update data
```
await geesomeWallet.updateWallet({
  phone: '+799911112234'
});
const receivedByPhoneCode = '112233';
await geesomeWallet.confirmWallet('phone', '+799911112234', receivedByPhoneCode);
```
## Initialize provider
```
const provider = geesomeWallet.provider({
  email: 'user@email.com',
  password: password,
  rpcUrl: 'https://mainnet.infura.io/v3/YOUR-PROJECT-ID',
  backendUrl: 'https://wallet.galtproject.io'
});
```
## Using provider for send transaction
```
const Web3 = require('web3');
const web3 = new Web3(provider);
await web3.eth.sendTransaction({
  from: await web3.eth.getAccounts().then(accs => accs[0]),
  to: '0x...',
  value: '0'
});
```
More about using web3: https://web3js.readthedocs.io/
