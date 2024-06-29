const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const Block = require("../core/block");
const {log16} = require("../utils/utils");
const Merkle = require("../core/merkle");

async function verifyBlock(
  newBlock,
  chainInfo,
  stateDB,
  codeDB,
  enableLogging = false
) {
  // Check if the block is valid or not, if yes, we will push it to the chain, update the difficulty, chain state and the transaction pool.

  // A block is valid under these factors:
  // - The hash of this block is equal to the hash re-generated according to the block's info.
  // - The block is mined (the hash starts with (4+difficulty) amount of zeros).
  // - Transactions in the block are valid.
  // - Block's timestamp is not greater than the current timestamp and is not lower than the previous block's timestamp.
  // - Block's parentHash is equal to latest block's hash
  // - The new difficulty can only be greater than 1 or lower than 1 compared to the old difficulty.

  return (
    // Check hash
    SHA256(
      newBlock.blockNumber.toString() +
        newBlock.timestamp.toString() +
        newBlock.txRoot +
        chainInfo.latestBlock.hash
    ) === newBlock.hash &&
    // Check parent hash
    chainInfo.latestBlock.hash === newBlock.parentHash &&
    // Check transactions ordering
    (await Block.hasValidTxOrder(newBlock, stateDB)) &&
    // Check transaction trie root
    Merkle.buildTxTrie(newBlock.transactions).root === newBlock.txRoot &&
    // Check timestamp
    newBlock.timestamp > chainInfo.latestBlock.timestamp &&
    newBlock.timestamp < Date.now() &&
    // Check block number
    newBlock.blockNumber - 1 === chainInfo.latestBlock.blockNumber &&
    // Check gas limit
    Block.hasValidGasLimit(newBlock) &&
    // Check transactions and transit state right after
    (await Block.verifyTransactionAndTransit(
      newBlock,
      stateDB,
      codeDB,
      enableLogging
    ))
  );
}

async function chooseProposer(validatorList, newBlock) {
  let viewIndex = newBlock.hash.charCodeAt(0) % validatorList.length;

  return validatorList[viewIndex];
}

async function minApprovals(address) {
  // PBFT consensus
  // N is the number of nodes require for f faulty
  // N = 3 * f + 1
  // Minimal approval for pbft consensus = 2 * f + 1
  return 2 * ((address.length - 1) / 3) + 1;
}

module.exports = {verifyBlock, chooseProposer, minApprovals};
