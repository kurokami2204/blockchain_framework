"use strict";

const BN = require("bn.js");
const {isNumber, deserializeState, serializeState} = require("../utils/utils");
const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");

const {EMPTY_HASH, CONTRACT_FLAG} = require("../config.json");
const {serialize} = require("v8");

class Transaction {
  // constructor(recipient = "", amount = "0", gas = "1000000000000", additionalData = {}, nonce = 0) {
  constructor(
    recipient = "",
    amount = "0",
    gas = "1000000000000",
    additionalData = {}
  ) {
    this.recipient = recipient; // Recipient's address (public key)
    this.amount = amount; // Amount to be sent
    this.gas = gas; // Gas that transaction consumed + tip for miner
    this.additionalData = additionalData; // Additional data that goes into the transaction
    // this.nonce          = nonce           // Nonce for signature entropy
    this.signature = {}; // Transaction's signature, will be generated later
  }

  static serialize(tx) {
    // Transaction fields

    // - recipient: 32 bytes | Hex string
    // - amount: 11 bytes | BigInt
    // - gas price: 11 bytes | BigInt
    // - r: 32 bytes | Hex string
    // - s: 32 bytes | Hex string
    // - v: 1 byte | Hex string
    // - additional data: what's left | JSON

    let txHexString = "";

    // Recipient
    txHexString += tx.recipient.padStart(64, "0");

    // Amount
    txHexString += BigInt(tx.amount).toString(16).padStart(22, "0");

    // Gas
    txHexString += BigInt(tx.gas).toString(16).padStart(22, "0");

    // Signature
    txHexString +=
      tx.signature.r.padStart(64, "0") +
      tx.signature.s.padStart(64, "0") +
      tx.signature.v.padStart(2, "0");

    // Additional data
    if (typeof tx.additionalData.scBody === "string") {
      let scBodyHex = Buffer.from(tx.additionalData.scBody, "utf8").toString(
        "hex"
      );

      if (scBodyHex.length % 2 !== 0) {
        scBodyHex = "0" + scBodyHex;
      }

      txHexString += "00" + scBodyHex;
    } else if (typeof tx.additionalData.contractGas === "string") {
      txHexString +=
        "01" +
        BigInt(tx.additionalData.contractGas).toString(16).padStart(22, "0");

      if (Array.isArray(tx.additionalData.txCallArgs)) {
        for (const arg of tx.additionalData.txCallArgs) {
          let newArg = BigInt(arg).toString(16);

          if (newArg.length % 2 !== 0) {
            newArg = "0" + newArg;
          }

          // Offset for knowing arg's size
          txHexString += Math.floor(newArg.length / 2)
            .toString(16)
            .padStart(8, "0");

          // The arg itself
          txHexString += newArg;
        }
      }
    } else {
      txHexString += "02";
    }

    return new Array(...Buffer.from(txHexString, "hex"));
  }

  static deserialize(tx) {
    let txHexString = Buffer.from(tx).toString("hex");

    const txObj = {signature: {}, additionalData: {}};

    txObj.recipient = txHexString.slice(0, 64);
    txHexString = txHexString.slice(64);

    txObj.amount = BigInt("0x" + txHexString.slice(0, 22)).toString();
    txHexString = txHexString.slice(22);

    txObj.gas = BigInt("0x" + txHexString.slice(0, 22)).toString();
    txHexString = txHexString.slice(22);

    txObj.signature.r = txHexString.slice(0, 64);
    txHexString = txHexString.slice(64);

    txObj.signature.s = txHexString.slice(0, 64);
    txHexString = txHexString.slice(64);

    txObj.signature.v = txHexString.slice(0, 2);
    txHexString = txHexString.slice(2);

    const txBody = parseInt("0x" + txHexString.slice(0, 2));
    txHexString = txHexString.slice(2);

    if (txBody === CONTRACT_FLAG.DEPLOY) {
      txObj.additionalData.scBody = Buffer.from(txHexString, "hex").toString(
        "utf8"
      );
    } else if (txBody === CONTRACT_FLAG.CALL) {
      txObj.additionalData.contractGas = BigInt(
        "0x" + txHexString.slice(0, 22)
      ).toString();
      txHexString = txHexString.slice(22);

      if (txHexString.length > 0) {
        txObj.additionalData.txCallArgs = [];
      }

      while (txHexString.length > 0) {
        const offset = parseInt(txHexString.slice(0, 8), 16);
        txHexString = txHexString.slice(8);

        txObj.additionalData.txCallArgs.push(
          BigInt("0x" + txHexString.slice(0, offset * 2)).toString()
        );
        txHexString = txHexString.slice(offset * 2);
      }
    } // Any other flag will make the additional data empty

    return txObj;
  }

  static getHash(tx) {
    return SHA256(
      tx.recipient.padStart(64, "0") +
        tx.amount +
        tx.gas +
        JSON.stringify(tx.additionalData)
    );
  }

  static sign(transaction, keyPair) {
    const sigObj = keyPair.sign(Transaction.getHash(transaction));
    transaction.signature = {
      v: sigObj.recoveryParam.toString(16), // Tham số khôi phục của ECDSA
      r: sigObj.r.toString(16), // Tọa độ x của điểm kết quả trong ESDCA
      s: sigObj.s.toString(16), // Giá trị của chữ ký ESDCA
    };
  }

  static getPubKey(tx) {
    // Get transaction's body's hash and recover original signature object
    const msgHash = Transaction.getHash(tx);

    const sigObj = {
      r: new BN(tx.signature.r, 16),
      s: new BN(tx.signature.s, 16),
      recoveryParam: parseInt(tx.signature.v, 16),
    };

    // Recover public key and get real address.
    const txSenderPubkey = ec.recoverPubKey(
      new BN(msgHash, 16).toString(10),
      sigObj,
      sigObj.recoveryParam
    );

    return ec.keyFromPublic(txSenderPubkey).getPublic("hex");
  }

  static async isValid(tx, stateDB) {
    let txSenderPubkey;

    // If recovering public key fails, then transaction is not valid.
    try {
      txSenderPubkey = Transaction.getPubKey(tx);
    } catch (e) {
      console.log(txSenderPubkey);
      return false;
    }

    const txSenderAddress = SHA256(txSenderPubkey);

    // If sender does not exist return false
    if (!(await stateDB.keys().all()).includes(txSenderAddress)) {
      console.log(`Address ${txSenderAddress} is not in state!`);
      return false;
    }
    const dataFromSender = deserializeState(await stateDB.get(txSenderAddress));

    // If sender is a contract address, then it's not supposed to be used to send money, so return false if it is.

    if (dataFromSender.codeHash !== EMPTY_HASH) {
      return false;
    }

    return true;

    // We don't check balance here, we will check balance directly in execution
  }

  static async compareTx(newTxSignature, txPool) {
    const {v, r, s} = newTxSignature;
    for (let tx of txPool) {
      if (
        tx.signature.v === v &&
        tx.signature.r === r &&
        tx.signature.s === s
      ) {
        return true;
      }
    }
    return false;
  }
}

module.exports = Transaction;
