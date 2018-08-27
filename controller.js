const log = require('loglevel');
const ircUtil = require('icjs-util');
const BN = ircUtil.BN;
const bip39 = require('bip39');
const EventEmitter = require('events').EventEmitter;
const ObservableStore = require('obs-store');
const filter = require('promise-filter');
const encryptor = require('browser-passworder');
const sigUtil = require('irc-sig-util');
const normalizeAddress = sigUtil.normalize;
const SimpleKeyring = require('eth-simple-keyring');
const HdKeyring = require('eth-hd-keyring');
const keyringTypes = [
  SimpleKeyring,
  HdKeyring,
];

class KeyringController extends EventEmitter {

  // PUBLIC METHODS
  //
  // THE FIRST SECTION OF METHODS ARE PUBLIC-FACING,
  // MEANING THEY ARE USED BY CONSUMERS OF THIS CLASS.
  //
  // THEIR SURFACE AREA SHOULD BE CHANGED WITH GREAT CARE.

  constructor(opts) {
    super();
    const initState = opts.initState || {};
    this.keyringTypes = opts.keyringTypes ? keyringTypes.concat(opts.keyringTypes) : keyringTypes;
    this.store = new ObservableStore(initState);
    this.memStore = new ObservableStore({
      isUnlocked: false,
      keyringTypes: this.keyringTypes.map(krt => krt.type),
      keyrings: [],
    });

    this.encryptor = opts.encryptor || encryptor;
    this.keyrings = [];
    this.getNetwork = opts.getNetwork;
  }

  fullUpdate() {
    this.emit('update', this.memStore.getState());
    return this.memStore.getState();
  }

  createNewVaultAndKeychain(password) {
    return this
        .persistAllKeyrings(password)
        .then(this.createFirstKeyTree.bind(this))
        .then(this.persistAllKeyrings.bind(this, password))
        .then(this.fullUpdate.bind(this));
  }

  createNewVaultAndRestore(password, seed) {
    if (typeof password !== 'string') {
      return Promise.reject('Password must be text.');
    }
    if (!bip39.validateMnemonic(seed)) {
      return Promise.reject(new Error('Seed phrase is invalid.'));
    }

    this.clearKeyrings().then();

    return this
        .persistAllKeyrings(password)
        .then(() =>
            this.addNewKeyring('HD Key Tree', {
              mnemonic: seed,
              numberOfAccounts: 1,
            }))
        .then((firstKeyring) => firstKeyring.getAccounts())
        .then((accounts) =>
            !accounts[0]
                ? Promise.reject('First Account not found.')
                : password)
        .then(this.persistAllKeyrings.bind(this))
        .then(this.fullUpdate.bind(this));
  }

  async setLocked() {
    this.password = null;
    this.memStore.updateState({isUnlocked: false});
    this.keyrings = [];
    await this._updateMemStoreKeyrings();
    return this.fullUpdate();
  }

  submitPassword(password) {
    return this
        .unlockKeyrings(password)
        .then((keyrings) => {
          this.keyrings = keyrings;
          return this.fullUpdate();
        });
  }

  addNewKeyring(type, opts) {
    const Keyring = this.getKeyringClassForType(type);
    const keyring = new Keyring(opts);
    return keyring
        .getAccounts()
        .then((accounts) => this.checkForDuplicate(type, accounts))
        .then(() => this.keyrings.push(keyring) && this.persistAllKeyrings())
        .then(() => this._updateMemStoreKeyrings())
        .then(() => this.fullUpdate())
        .then(() => keyring);
  }

  async removeEmptyKeyrings() {
    const validKeyrings = [];
    await Promise.all(this.keyrings.map(async (keyring) => {
      const accounts = await keyring.getAccounts();
      if (accounts.length > 0) {
        validKeyrings.push(keyring);
      }
    }));
    this.keyrings = validKeyrings;
  }

  checkForDuplicate(type, newAccount) {
    return this
        .getAccounts()
        .then((accounts) => {
          switch (type) {
            case 'Simple Key Pair':
              const isNotIncluded = !accounts.find((key) => key === newAccount[0] || key === ircUtil.stripHexPrefix(newAccount[0]));
              return (isNotIncluded) ? Promise.resolve(newAccount) : Promise.reject(new Error('The account is a duplicate'));
            default:
              return Promise.resolve(newAccount);
          }
        });
  }

  addNewAccount(selectedKeyring) {
    return selectedKeyring
        .addAccounts(1)
        .then((accounts) => {
          accounts.forEach((hexAccount) => {
            this.emit('newAccount', hexAccount);
          });
        })
        .then(this.persistAllKeyrings.bind(this))
        .then(this._updateMemStoreKeyrings.bind(this))
        .then(this.fullUpdate.bind(this));
  }

  exportAccount(address) {
    return this
        .getKeyringForAccount(address)
        .then((keyring) => keyring.exportAccount(normalizeAddress(address)))
        .catch(Promise.bind().reject);
  }

  removeAccount(address) {
    return this
        .getKeyringForAccount(address)
        .then((keyring) => {
          if (typeof keyring.removeAccount === 'function') {
            keyring.removeAccount(address);
            this.emit('removedAccount', address);
            return keyring.getAccounts();
          } else {
            return Promise.reject(`Keyring ${keyring.type} doesn't support account removal operations`);
          }
        })
        .then(accounts => accounts.length === 0 && this.removeEmptyKeyrings())
        .then(this.persistAllKeyrings.bind(this))
        .then(this._updateMemStoreKeyrings.bind(this))
        .then(this.fullUpdate.bind(this))
        .catch(Promise.bind().reject);
  }

  signTransaction(ethTx, _fromAddress) {
    const fromAddress = normalizeAddress(_fromAddress);
    return this
        .getKeyringForAccount(fromAddress)
        .then((keyring) => keyring.signTransaction(fromAddress, ethTx));
  }

  signMessage(msgParams) {
    const address = normalizeAddress(msgParams.from);
    return this
        .getKeyringForAccount(address)
        .then((keyring) => keyring.signMessage(address, msgParams.data));
  }

  signPersonalMessage(msgParams) {
    const address = normalizeAddress(msgParams.from);
    return this
        .getKeyringForAccount(address)
        .then((keyring) => keyring.signPersonalMessage(address, msgParams.data));
  }

  signTypedMessage(msgParams) {
    const address = normalizeAddress(msgParams.from);
    return this
        .getKeyringForAccount(address)
        .then((keyring) => keyring.signTypedData(address, msgParams.data));
  }

  createFirstKeyTree() {
    this.clearKeyrings().then();
    return this
        .addNewKeyring('HD Key Tree', {numberOfAccounts: 1})
        .then((keyring) => keyring.getAccounts())
        .then((accounts) => {
          const firstAccount = accounts[0];
          if (!firstAccount) return Promise.reject('No account found on keychain.');
          const hexAccount = normalizeAddress(firstAccount);
          this.emit('newVault', hexAccount);
        });
  }

  persistAllKeyrings(password = this.password) {
    if (typeof password !== 'string') {
      return Promise.reject('KeyringController - password is not a string');
    }

    this.password = password;
    this.memStore.updateState({isUnlocked: true});
    return Promise
        .all(this.keyrings.map((keyring) =>
            Promise.all([keyring.type, keyring.serialize()])
                   .then((serializedKeyringArray) => ({
                     type: serializedKeyringArray[0],
                     data: serializedKeyringArray[1],
                   }))))
        .then((serializedKeyrings) => this.encryptor.encrypt(this.password, serializedKeyrings))
        .then((encryptedString) => this.store.updateState({vault: encryptedString}));
  }

  async unlockKeyrings(password) {
    const encryptedVault = this.store.getState().vault;
    if (!encryptedVault) {
      throw new Error('Cannot unlock without a previous vault.');
    }

    await this.clearKeyrings();
    const vault = await this.encryptor.decrypt(password, encryptedVault);
    this.password = password;
    this.memStore.updateState({isUnlocked: true});
    await Promise.all(vault.map(this.restoreKeyring.bind(this)));
    return this.keyrings;
  }

  restoreKeyring(serialized) {
    const {type, data} = serialized;
    const Keyring = this.getKeyringClassForType(type);
    const keyring = new Keyring();
    return keyring
        .deserialize(data)
        .then(() => keyring.getAccounts())
        .then(() => this.keyrings.push(keyring) && this._updateMemStoreKeyrings())
        .then(() => keyring);
  }

  getKeyringClassForType(type) {
    return this.keyringTypes.find(kr => kr.type === type);
  }

  getKeyringsByType(type) {
    return this.keyrings.filter((keyring) => keyring.type === type);
  }

  async getAccounts() {
    const keyrings = this.keyrings || [];
    const addresses = await Promise
        .all(keyrings.map(kr => kr.getAccounts()))
        .then((keyringArrays) => keyringArrays.reduce((res, arr) => res.concat(arr), []));
    return addresses.map(normalizeAddress);
  }

  getKeyringForAccount(address) {
    const hexed = normalizeAddress(address);
    log.debug(`KeyringController - getKeyringForAccount: ${hexed}`);

    return Promise
        .all(this.keyrings.map((keyring) =>
            Promise.all([
              keyring,
              keyring.getAccounts()])))
        .then(filter((candidate) =>
            candidate[1]
                .map(normalizeAddress)
                .includes(hexed)))
        .then((winners) =>
            winners && winners.length > 0
                ? Promise.resolve(winners[0][0])
                : Promise.reject('No keyring found.'));
  }

  displayForKeyring(keyring) {
    return keyring
        .getAccounts()
        .then((accounts) => ({
          type: keyring.type,
          accounts: accounts.map(normalizeAddress),
        }));
  }

  addGasBuffer(gas) {
    const gasBuffer = new BN('100000', 10);
    const bnGas = new BN(ircUtil.stripHexPrefix(gas), 16);
    const correct = bnGas.add(gasBuffer);
    return ircUtil.addHexPrefix(correct.toString(16));
  }

  async clearKeyrings() {
    this.keyrings = [];
    this.memStore.updateState({keyrings: []});
  }

  async _updateMemStoreKeyrings() {
    const keyrings = await Promise.all(this.keyrings.map(this.displayForKeyring));
    return this.memStore.updateState({keyrings});
  }

}

module.exports = KeyringController;
