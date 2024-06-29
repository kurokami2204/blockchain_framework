const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");
const BN = require("bn.js");
const {getPubKey, signMessage} = require("../utils/utils");

class MessagePool {
  static createMessage(block, keyPair) {
    let message = {
      blockHash: block.hash,
      publicKey: getPubKey(keyPair),
      signature: signMessage(keyPair, block.hash),
    };

    return message;
  }

  static serializeMessage(message) {
    // Message fields

    // - hash: 32 bytes | Hex string
    // - publicKey: 65 bytes | Hex string
    // - r: 32 bytes | Hex string
    // - s: 32 bytes | Hex string
    // - v: 1 byte | Hex string
    let messageHexStr = "";

    // blockHash
    messageHexStr += message.blockHash.toString(16).padStart(64, "0");
    // publicKey
    messageHexStr += message.publicKey.toString(16).padStart(130, "0");
    // signature
    messageHexStr +=
      message.signature.r.padStart(64, "0") +
      message.signature.s.padStart(64, "0") +
      message.signature.v.padStart(2, "0");

    return new Array(...Buffer.from(messageHexStr, "hex"));
  }

  static deserializeMessage(message) {
    let messageHexStr = Buffer.from(message).toString("hex");

    const recoverMessage = {signature: {}};

    recoverMessage.blockHash = messageHexStr.slice(0, 64);
    messageHexStr = messageHexStr.slice(64);

    recoverMessage.publicKey = messageHexStr.slice(0, 130);
    messageHexStr = messageHexStr.slice(130);

    recoverMessage.signature.r = messageHexStr.slice(0, 64);
    messageHexStr = messageHexStr.slice(64);

    recoverMessage.signature.s = messageHexStr.slice(0, 64);
    messageHexStr = messageHexStr.slice(64);

    recoverMessage.signature.v = messageHexStr.slice(0, 2);
    messageHexStr = messageHexStr.slice(2);

    return recoverMessage;
  }

  static existingMessage(messagePool, message) {
    let exists = messagePool.some((obj) => obj.publicKey === message.publicKey);
    return exists;
  }

  static isValidMessage(validatorAddress, message) {
    const msgHash = message.blockHash;

    const sigObj = {
      r: new BN(message.signature.r, 16),
      s: new BN(message.signature.s, 16),
      recoveryParam: parseInt(message.signature.v, 16),
    };

    const messagePublicKey = ec.recoverPubKey(
      new BN(msgHash, 16).toString(10),
      sigObj,
      sigObj.recoveryParam
    );

    const publicKey = ec.keyFromPublic(messagePublicKey).getPublic("hex");
    // Check recover public key exist in address pool
    if (!validatorAddress.includes(SHA256(publicKey))) {
      return false;
    }
    // Verify message hash sign by signature
    if (
      !ec
        .keyFromPublic(messagePublicKey)
        .verify(message.blockHash, message.signature)
    ) {
      return false;
    }

    return true;
  }
}

module.exports = MessagePool;
