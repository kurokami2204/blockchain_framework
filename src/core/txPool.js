"use strict";

const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");

const Transaction = require("./transaction");

const {BLOCK_GAS_LIMIT} = require("../config.json");

async function addTransaction(transaction, chainInfo, stateDB) {
  try {
    transaction = Transaction.deserialize(transaction);
  } catch (e) {
    console.log(
      `\x1b[31mERROR\x1b[0m [${new Date().toISOString()}] Failed to add one transaction to pool: Can not deserialize transaction.`
    );

    // If transaction can not be deserialized, it's faulty
    return;
  }

  // Transactions are weakly verified when added to the pool (does no state checking), but will be fully checked in block production.
  if (
    !(await Transaction.isValid(transaction, stateDB)) ||
    BigInt(transaction.additionalData.contractGas || 0) >
      BigInt(BLOCK_GAS_LIMIT)
  ) {
    console.log(
      `\x1b[31mERROR\x1b[0m [${new Date().toISOString()}] Failed to add one transaction to pool: Transaction is invalid.`
    );

    return;
  }

  const txPool = chainInfo.transactionPool;

  // Get public key and address from sender
  const txSenderPubkey = Transaction.getPubKey(transaction);
  const txSenderAddress = SHA256(txSenderPubkey);
  // console.log(`txSenderAddress: ` + txSenderAddress);

  if (!(await stateDB.keys().all()).includes(txSenderAddress)) {
    console.log(
      `\x1b[31mERROR\x1b[0m [${new Date().toISOString()}] Failed to add one transaction to pool: Sender does not exist.`
    );

    return;
  }

  txPool.push(transaction);

  console.log(
    `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Added one transaction to pool.`
  );
}

async function clearDepreciatedTxns(chainInfo, stateDB) {
  const txPool = chainInfo.transactionPool;

  const newTxPool = [],
    skipped = {};

  for (const tx of txPool) {
    const txSenderPubkey = Transaction.getPubKey(tx);
    const txSenderAddress = SHA256(txSenderPubkey);

    if (skipped[txSenderAddress]) continue;
  }

  return newTxPool;
}

module.exports = {addTransaction, clearDepreciatedTxns};
