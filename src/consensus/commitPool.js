const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");
const BN = require("bn.js");
const {getPubKey, signMessage} = require("../utils/utils");

class CommitPool {
  // Danh sách của chứa thông điệp commit cho hash của block
  constructor() {
    this.list = [];
  }

  // tạo thông điệp commit cho prepare gửi đến
  static createCommit(prepare, keyPair) {
    let commit = {
      blockHash: prepare.blockHash,
      publicKey: getPubKey(keyPair),
      signature: signMessage(keyPair, prepare.blockHash),
    };
    // console.log(commit);
    return commit;
  }

  // đẩy thông điệp commit cho một block hash vào list
  static addCommit(chainInfo, commit) {
    this.list = chainInfo.commitPool;
    this.list.push(commit);
  }

  // check nếu thông điệp commit đã tồn tại
  static existingCommit(chainInfo, commit) {
    let exists = chainInfo.commitPool.find(
      (p) => p.publicKey === commit.publicKey
    );
    return exists;
  }

  // validate thông điệp commit
  static isValidCommit(validatorAddress, commit) {
    const msgHash = commit.blockHash;

    const sigObj = {
      r: new BN(commit.signature.r, 16),
      s: new BN(commit.signature.s, 16),
      recoveryParam: parseInt(commit.signature.v, 16),
    };

    const commitPublicKey = ec.recoverPubKey(
      new BN(msgHash, 16).toString(10),
      sigObj,
      sigObj.recoveryParam
    );

    const publicKey = ec.keyFromPublic(commitPublicKey).getPublic("hex");
    // Check recover public key exist in address pool
    if (!validatorAddress.includes(SHA256(publicKey))) {
      return false;
    }
    // Verify message hash sign by signature
    if (
      !ec
        .keyFromPublic(commitPublicKey)
        .verify(commit.blockHash, commit.signature)
    ) {
      return false;
    }

    return true;
  }

  static clearCommitPool(chainInfo) {
    const commitPool = chainInfo.commitPool;

    commitPool.splice(0, commitPool.length);

    return commitPool;
  }
}

module.exports = CommitPool;
