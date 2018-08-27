const {EventEmitter} = require('events');
const HDKey = require('hdkey');
const ircUtil = require('icjs-util');
const sigUtil = require('irc-sig-util');
const Transaction = require('icjs-tx');
require('isomorphic-fetch');

const hdPathString = `m/44'/60'/0'`;
const type = 'Ledger Hardware';
// const BRIDGE_URL = 'https://metamask.github.io/eth-ledger-bridge-keyring';
const BRIDGE_URL = '';
const pathBase = 'm';
const MAX_INDEX = 1000;
const NETWORK_API_URLS = {
  mainnet: 'https://scan.irchain.io/',
};

class LedgerBridgeKeyring extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.bridgeUrl = null;
    this.type = type;
    this.page = 0;
    this.perPage = 5;
    this.unlockedAccount = 0;
    this.hdk = new HDKey();
    this.paths = {};
    this.iframe = null;
    this.network = 'mainnet';
    this.implementFullBIP44 = false;
    this.deserialize(opts);
    this._setupIframe();
  }

  serialize() {
    return Promise.resolve({
      hdPath: this.hdPath,
      accounts: this.accounts,
      bridgeUrl: this.bridgeUrl,
      implementFullBIP44: false,
    });
  }

  deserialize(opts = {}) {
    this.hdPath = opts.hdPath || hdPathString;
    this.bridgeUrl = opts.bridgeUrl || BRIDGE_URL;
    this.accounts = opts.accounts || [];
    this.implementFullBIP44 = opts.implementFullBIP44 || false;
    return Promise.resolve();
  }

  isUnlocked() {
    return !!(this.hdk && this.hdk.publicKey);
  }

  setAccountToUnlock(index) {
    this.unlockedAccount = parseInt(index, 10);
  }

  setHdPath(hdPath) {
    // Reset HDKey if the path changes
    if (this.hdPath !== hdPath) {
      this.hdk = new HDKey();
    }
    this.hdPath = hdPath;
  }

  unlock(hdPath) {
    if (this.isUnlocked() && !hdPath) return Promise.resolve('already unlocked');
    const path = hdPath ? this._toLedgerPath(hdPath) : this.hdPath;
    return new Promise((resolve, reject) => {
      this._sendMessage(
          {
            action: 'ledger-unlock',
            params: {              hdPath: path,            },
          },
          ({success, payload}) => {
            if (success) {
              this.hdk.publicKey = new Buffer(payload.publicKey, 'hex');
              this.hdk.chainCode = new Buffer(payload.chainCode, 'hex');
              resolve(payload.address);
            } else {
              reject(payload.error || 'Unknown error');
            }
          });
    });
  }

  addAccounts(n = 1) {

    return new Promise((resolve, reject) => {
      this.unlock()
          .then(async () => {
            const from = this.unlockedAccount;
            const to = from + n;
            this.accounts = [];
            for (let i = from; i < to; i++) {
              let address;
              if (this._isBIP44()) {
                const path = this._getPathForIndex(i);
                address = await this.unlock(path);
              } else {
                address = this._addressFromIndex(pathBase, i);
              }
              this.accounts.push(address);
              this.page = 0;
            }
            resolve(this.accounts);
          })
          .catch(reject);
    });
  }

  getFirstPage() {
    this.page = 0;
    return this.__getPage(1);
  }

  getNextPage() {
    return this.__getPage(1);
  }

  getPreviousPage() {
    return this.__getPage(-1);
  }

  getAccounts() {
    return Promise.resolve(this.accounts.slice());
  }

  removeAccount(address) {
    if (!this.accounts.map(a => a.toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`);
    }
    this.accounts = this.accounts.filter(a => a.toLowerCase() !== address.toLowerCase());
  }

  // tx is an instance of the icjs-transaction class.
  signTransaction(address, tx) {
    return new Promise((resolve, reject) => {
      this.unlock()
          .then(() => {

            tx.v = ircUtil.bufferToHex(tx.getChainId());
            tx.r = '0x00';
            tx.s = '0x00';

            let hdPath;
            if (this._isBIP44()) {
              hdPath = this._getPathForIndex(this.unlockedAccount);
            } else {
              hdPath = this._toLedgerPath(this._pathFromAddress(address));
            }

            this._sendMessage(
                {
                  action: 'ledger-sign-transaction',
                  params: {
                    tx: tx.serialize().toString('hex'),
                    hdPath,
                  },
                },
                ({success, payload}) => {
                  if (success) {

                    tx.v = Buffer.from(payload.v, 'hex');
                    tx.r = Buffer.from(payload.r, 'hex');
                    tx.s = Buffer.from(payload.s, 'hex');

                    const valid = tx.verifySignature();
                    if (valid) {
                      resolve(tx);
                    } else {
                      reject('The transaction signature is not valid');
                    }
                  } else {
                    reject(payload);
                  }
                });
          });
    });
  }

  signMessage(withAccount, data) {
    throw new Error('Not supported on this device');
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage(withAccount, message) {
    const humanReadableMsg = this._toAscii(message);
    const bufferMsg = Buffer.from(humanReadableMsg).toString('hex');
    return new Promise((resolve, reject) => {
      this.unlock()
          .then(_ => {
            let hdPath;
            if (this._isBIP44()) {
              hdPath = this._getPathForIndex(this.unlockedAccount);
            } else {
              hdPath = LedgerBridgeKeyring._toLedgerPath(this._pathFromAddress(withAccount));
            }

            this._sendMessage(
                {
                  action: 'ledger-sign-personal-message',
                  params: {
                    hdPath,
                    message: bufferMsg,
                  },
                },
                ({success, payload}) => {
                  if (success) {
                    let v = payload['v'] - 27;
                    v = v.toString(16);
                    if (v.length < 2) {
                      v = `0${v}`;
                    }
                    const signature = `0x${payload['r']}${payload['s']}${v}`;
                    const addressSignedWith = sigUtil.recoverPersonalSignature({data: message, sig: signature});
                    if (ircUtil.toChecksumAddress(addressSignedWith) !== ircUtil.toChecksumAddress(withAccount)) {
                      reject('signature doesnt match the right address');
                    }
                    resolve(signature);
                  } else {
                    reject(payload);
                  }
                });
          });
    });
  }

  signTypedData(withAccount, typedData) {
    throw new Error('Not supported on this device');
  }

  exportAccount(address) {
    throw new Error('Not supported on this device');
  }

  forgetDevice() {
    this.accounts = [];
    this.page = 0;
    this.unlockedAccount = 0;
    this.paths = {};
    this.hdk = new HDKey();
  }

  /* PRIVATE METHODS */

  _setupIframe() {
    this.iframe = document.createElement('iframe');
    this.iframe.src = this.bridgeUrl;
    document.head.appendChild(this.iframe);
  }

  _getOrigin() {
    const tmp = this.bridgeUrl.split('/');
    tmp.splice(-1, 1);
    return tmp.join('/');
  }

  _sendMessage(msg, cb) {
    msg.target = 'LEDGER-IFRAME';
    this.iframe.contentWindow.postMessage(msg, '*');
    window.addEventListener('message', ({origin, data}) => {
      if (origin !== this._getOrigin()) return false;
      if (data && data.action && data.action === `${msg.action}-reply`) {
        cb(data);
      }
    });
  }

  __getPage(increment) {

    this.page += increment;

    if (this.page <= 0) { this.page = 1; }
    const from = (this.page - 1) * this.perPage;
    const to = from + this.perPage;

    return new Promise((resolve, reject) => {
      this.unlock()
          .then(async _ => {
            let accounts;
            if (this._isBIP44()) {
              accounts = await this._getAccountsBIP44(from, to);
            } else {
              accounts = this._getAccountsLegacy(from, to);
            }
            resolve(accounts);
          })
          .catch(e => {
            reject(e);
          });
    });
  }

  async _getAccountsBIP44(from, to) {
    const accounts = [];

    for (let i = from; i < to; i++) {
      const path = this._getPathForIndex(i);
      const address = await this.unlock(path);
      const valid = this.implementFullBIP44 ? await this._hasPreviousTransactions(address) : true;
      accounts.push({
        address: address,
        balance: null,
        index: i,
      });
      // PER BIP44
      // "Software should prevent a creation of an account if
      // a previous account does not have a transaction history
      // (meaning none of its addresses have been used before)."
      if (!valid) {
        break;
      }
    }
    return accounts;
  }

  _getAccountsLegacy(from, to) {
    const accounts = [];

    for (let i = from; i < to; i++) {
      const address = this._addressFromIndex(pathBase, i);
      accounts.push({
        address: address,
        balance: null,
        index: i,
      });
      this.paths[ircUtil.toChecksumAddress(address)] = i;
    }
    return accounts;
  }

  _padLeftEven(hex) {
    return hex.length % 2 !== 0 ? `0${hex}` : hex;
  }

  _normalize(buf) {
    return this._padLeftEven(ircUtil.bufferToHex(buf).toLowerCase());
  }

  _addressFromIndex(pathBase, i) {
    const dkey = this.hdk.derive(`${pathBase}/${i}`);
    const address = ircUtil
        .publicToAddress(dkey.publicKey, true)
        .toString('hex');
    return ircUtil.toChecksumAddress(address);
  }

  _pathFromAddress(address) {
    const checksummedAddress = ircUtil.toChecksumAddress(address);
    let index = this.paths[checksummedAddress];
    if (typeof index === 'undefined') {
      for (let i = 0; i < MAX_INDEX; i++) {
        if (checksummedAddress === this._addressFromIndex(pathBase, i)) {
          index = i;
          break;
        }
      }
    }

    if (typeof index === 'undefined') {
      throw new Error('Unknown address');
    }
    return this._getPathForIndex(index);
  }

  _toAscii(hex) {
    let str = '';
    let i = 0;
    const l = hex.length;
    if (hex.substring(0, 2) === '0x') {
      i = 2;
    }
    for (; i < l; i += 2) {
      const code = parseInt(hex.substr(i, 2), 16);
      str += String.fromCharCode(code);
    }

    return str;
  }

  _getPathForIndex(index) {
    // Check if the path is BIP 44 (Ledger Live)
    return this._isBIP44() ? `m/44'/60'/${index}'/0/0` : `${this.hdPath}/${index}`;
  }

  _isBIP44() {
    return this.hdPath === `m/44'/60'/0'/0/0`;
  }

  _toLedgerPath(path) {
    return path.toString().replace('m/', '');
  }

  async _hasPreviousTransactions(address, chain = 'irc') {
    const apiUrl = this._getApiUrl();
    const fetchUrl = chain === 'irc'
        ? `${apiUrl}/address=${address}/?format=json`
        : `${apiUrl}/api/eth_address=${address}/?format=json`;
    const response = await fetch(fetchUrl);
    if (response.status >= 400) {
      return false;
    }
    const parsedResponse = await response.json();
    return parsedResponse.d && parsedResponse.d.length > 0;
  }

  _getApiUrl() {
    return NETWORK_API_URLS[this.network] || NETWORK_API_URLS['mainnet'];
  }

}

LedgerBridgeKeyring.type = type;
module.exports = LedgerBridgeKeyring;
