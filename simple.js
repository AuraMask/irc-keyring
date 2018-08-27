const EventEmitter = require('events').EventEmitter;
const Wallet = require('icjs-wallet');
const ircUtil = require('icjs-util');
const sigUtil = require('irc-sig-util');
const type = 'Simple Key Pair';

class SimpleKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor(opts) {
    super();
    this.type = type;
    this.wallets = [];
    this.deserialize(opts);
  }

  serialize() {
    return Promise.resolve(this.wallets.map(w => w.getPrivateKey().toString('hex')));
  }

  deserialize(privateKeys = []) {
    return new Promise((resolve, reject) => {
      try {
        this.wallets = privateKeys.map((privateKey) => {
          const stripped = ircUtil.stripHexPrefix(privateKey);
          const buffer = new Buffer(stripped, 'hex');
          return Wallet.fromPrivateKey(buffer);
        });
      } catch (e) {
        reject(e);
      }
      resolve();
    });
  }

  addAccounts(n = 1) {
    var newWallets = [];
    for (var i = 0; i < n; i++) {
      newWallets.push(Wallet.generate());
    }
    this.wallets = this.wallets.concat(newWallets);
    const hexWallets = newWallets.map(w => ircUtil.bufferToHex(w.getAddress()));
    return Promise.resolve(hexWallets);
  }

  getAccounts() {
    return Promise.resolve(this.wallets.map(w => ircUtil.bufferToHex(w.getAddress())));
  }

  // tx is an instance of the icjs-transaction class.
  signTransaction(address, tx) {
    const wallet = this._getWalletForAccount(address);
    const privKey = wallet.getPrivateKey();
    tx.sign(privKey);
    return Promise.resolve(tx);
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage(withAccount, data) {
    const wallet = this._getWalletForAccount(withAccount);
    const message = ircUtil.stripHexPrefix(data);
    const privKey = wallet.getPrivateKey();
    const msgSig = ircUtil.ecsign(new Buffer(message, 'hex'), privKey);
    const rawMsgSig = ircUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s));
    return Promise.resolve(rawMsgSig);
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage(withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount);
    const privKey = ircUtil.stripHexPrefix(wallet.getPrivateKey());
    const privKeyBuffer = new Buffer(privKey, 'hex');
    const sig = sigUtil.personalSign(privKeyBuffer, {data: msgHex});
    return Promise.resolve(sig);
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData(withAccount, typedData) {
    const wallet = this._getWalletForAccount(withAccount);
    const privKey = ircUtil.toBuffer(wallet.getPrivateKey());
    const sig = sigUtil.signTypedData(privKey, {data: typedData});
    return Promise.resolve(sig);
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount(address) {
    const wallet = this._getWalletForAccount(address);
    return Promise.resolve(wallet.getPrivateKey().toString('hex'));
  }

  removeAccount(address) {
    if (!this.wallets.map(w => ircUtil.bufferToHex(w.getAddress()).toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`);
    }
    this.wallets = this.wallets.filter(w => ircUtil.bufferToHex(w.getAddress()).toLowerCase() !== address.toLowerCase());
  }

  /* PRIVATE METHODS */

  _getWalletForAccount(account) {
    const address = sigUtil.normalize(account);
    let wallet = this.wallets.find(w => ircUtil.bufferToHex(w.getAddress()) === address);
    if (!wallet) throw new Error('Simple Keyring - Unable to find matching address.');
    return wallet;
  }

}

SimpleKeyring.type = type;
module.exports = SimpleKeyring;
