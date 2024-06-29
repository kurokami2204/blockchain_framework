"use strict";

const {Level} = require("level");
const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");

const Merkle = require("./merkle");
const Transaction = require("./transaction");

const {EMPTY_HASH, BLOCK_REWARD} = require("../config.json");
const {serializeState, deserializeState} = require("../utils/utils");

async function changeState(newBlock, stateDB, codeDB, enableLogging = false) {
  // Manually change state
  const existedAddresses = await stateDB.keys().all();

  for (const tx of newBlock.transactions) {
    // If the address doesn't already exist in the chain state, we will create a new empty one.
    if (!existedAddresses.includes(tx.recipient)) {
      await stateDB.put(
        tx.recipient,
        Buffer.from(
          serializeState({
            balance: "0",
            codeHash: EMPTY_HASH,
            storageRoot: EMPTY_HASH,
          })
        )
      );
    }

    // Get sender's public key and address
    const txSenderPubkey = Transaction.getPubKey(tx);
    const txSenderAddress = SHA256(txSenderPubkey);

    // If the address doesn't already exist in the chain state, we will create a new empty one.
    if (!existedAddresses.includes(txSenderAddress)) {
      await stateDB.put(
        txSenderAddress,
        Buffer.from(
          serializeState({
            balance: "0",
            codeHash: EMPTY_HASH,
            storageRoot: EMPTY_HASH,
          })
        )
      );
    } else if (typeof tx.additionalData.scBody === "string") {
      // Contract deployment
      const dataFromSender = deserializeState(
        await stateDB.get(txSenderAddress)
      );

      if (dataFromSender.codeHash === EMPTY_HASH) {
        // dataFromSender.codeHash = SHA256(tx.additionalData.scBody);

        await codeDB.put(dataFromSender.codeHash, tx.additionalData.scBody);
        await stateDB.put(
          txSenderAddress,
          Buffer.from(serializeState(dataFromSender))
        );
      }
    }

    // Normal transfer
    const dataFromSender = deserializeState(await stateDB.get(txSenderAddress));
    const dataFromRecipient = deserializeState(await stateDB.get(tx.recipient));

    const totalAmountToPay =
      BigInt(tx.amount) +
      BigInt(tx.gas) +
      BigInt(tx.additionalData.contractGas || 0);

    // Check balance
    if (BigInt(dataFromSender.balance) >= totalAmountToPay) {
      await stateDB.put(
        txSenderAddress,
        Buffer.from(
          serializeState({
            balance: (
              BigInt(dataFromSender.balance) - totalAmountToPay
            ).toString(),
            codeHash: dataFromSender.codeHash,
            storageRoot: dataFromSender.storageRoot,
          })
        )
      );

      await stateDB.put(
        tx.recipient,
        Buffer.from(
          serializeState({
            balance: (
              BigInt(dataFromRecipient.balance) + BigInt(tx.amount)
            ).toString(),
            codeHash: dataFromRecipient.codeHash,
            storageRoot: dataFromRecipient.storageRoot,
          })
        )
      );
    }
  }

  // Reward

  let gas = 0n;

  for (const tx of newBlock.transactions) {
    gas += BigInt(tx.gas) + BigInt(tx.additionalData.contractGas || 0);
  }

  if (!existedAddresses.includes(newBlock.nodeAddress)) {
    await stateDB.put(
      newBlock.nodeAddress,
      Buffer.from(
        serializeState({
          balance: (BigInt(BLOCK_REWARD) + gas).toString(),
          codeHash: EMPTY_HASH,
          storageRoot: EMPTY_HASH,
        })
      )
    );
  } else {
    const minerState = deserializeState(
      await stateDB.get(newBlock.nodeAddress)
    );

    minerState.balance = (
      BigInt(minerState.balance) +
      BigInt(BLOCK_REWARD) +
      gas
    ).toString();

    await stateDB.put(
      newBlock.nodeAddress,
      Buffer.from(serializeState(minerState))
    );
  }
}

module.exports = changeState;
