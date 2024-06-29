const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");
const BN = require("bn.js");
const {getPubKey, signMessage} = require("../utils/utils");

class PreparePool {
  // Danh sách của chứa thông điệp prepare cho hash của block
  constructor() {
    this.list = [];
  }

  // tạo thông điệp prepare cho block gửi đến
  static createPrepare(block, keyPair) {
    let prepare = {
      blockHash: block.hash,
      publicKey: getPubKey(keyPair),
      signature: signMessage(keyPair, block.hash),
    };
    return prepare;
  }

  // đẩy thông điệp prepare cho một block hash vào list
  static addPrepare(chainInfo, prepare) {
    this.list = chainInfo.preparePool;
    this.list.push(prepare);
  }

  // check nếu thông điệp prepare đã tồn tại
  static existingPrepare(chainInfo, prepare) {
    let exists = chainInfo.preparePool.find(
      (p) => p.publicKey === prepare.publicKey
    );
    return exists;
  }

  // validate thông điệp prepare

  static isValidPrepare(validatorAddress, prepare) {
    const msgHash = prepare.blockHash;

    const sigObj = {
      r: new BN(prepare.signature.r, 16),
      s: new BN(prepare.signature.s, 16),
      recoveryParam: parseInt(prepare.signature.v, 16),
    };

    const preparePublicKey = ec.recoverPubKey(
      new BN(msgHash, 16).toString(10),
      sigObj,
      sigObj.recoveryParam
    );

    const publicKey = ec.keyFromPublic(preparePublicKey).getPublic("hex");
    // Check recover public key exist in address pool
    if (!validatorAddress.includes(SHA256(publicKey))) {
      return false;
    }
    // Verify message hash sign by signature
    if (
      !ec
        .keyFromPublic(preparePublicKey)
        .verify(prepare.blockHash, prepare.signature)
    ) {
      return false;
    }

    return true;
  }

  static clearPreparePool(chainInfo) {
    const preparePool = chainInfo.preparePool;

    preparePool.splice(0, preparePool.length);

    return preparePool;
  }
}

module.exports = PreparePool;
