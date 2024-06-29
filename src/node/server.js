"use strict";

const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const WS = require("ws");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");
const {Level} = require("level");
const {fork} = require("child_process");

const Block = require("../core/block");
const Transaction = require("../core/transaction");
const PreparePool = require("../consensus/preparePool");
const CommitPool = require("../consensus/commitPool");
const MessagePool = require("../consensus/messagePool");
const changeState = require("../core/state");
const {
  BLOCK_REWARD,
  BLOCK_GAS_LIMIT,
  EMPTY_HASH,
  INITIAL_SUPPLY,
  FIRST_ACCOUNT,
} = require("../config.json");
const {produceMessage, sendMessage} = require("./message");
const generateGenesisBlock = require("../core/genesis");
const {addTransaction, clearDepreciatedTxns} = require("../core/txPool");
const api = require("../api/api");
const TYPE = require("./message-types");
const {
  verifyBlock,
  chooseProposer,
  minApprovals,
} = require("../consensus/consensus");
const {
  parseJSON,
  numToBuffer,
  serializeState,
  deserializeState,
} = require("../utils/utils");
const Merkle = require("../core/merkle");
const {SyncQueue} = require("./queue");
const {resolve} = require("path");

const opened = []; // Addresses and sockets from connected nodes.
const connected = []; // Addresses from connected nodes.
let connectedNodes = 0;

let worker = fork(`${__dirname}/../miner/worker.js`); // Worker thread (for PoW mining).

// console.log(worker.events);

let mined = false; // This will be used to inform the node that another node has already mined before it.

// chain info variable
const chainInfo = {
  transactionPool: [],
  preparePool: [],
  commitPool: [],
  latestBlock: generateGenesisBlock(),
  latestSyncBlock: null,
  syncQueue: new SyncQueue(this),
  syncing: false,
  checkedBlock: {},
};
const validatorAddress = {};
let messagePool = [];
let prepared = false;
let committed = false;
let clearMessages = false;

const stateDB = new Level(__dirname + "/../../log/stateStore", {
  valueEncoding: "buffer",
});
const blockDB = new Level(__dirname + "/../../log/blockStore", {
  valueEncoding: "buffer",
});
const bhashDB = new Level(__dirname + "/../../log/bhashStore", {
  valueEncoding: "buffer",
});
const txhashDB = new Level(__dirname + "/../../log/txhashStore");
const codeDB = new Level(__dirname + "/../../log/codeStore");
const addressDB = new Level(__dirname + "/../../log/addressStore");

// Function to connect to a node.
async function connect(MY_ADDRESS, address) {
  if (
    !connected.find((peerAddress) => peerAddress === address) &&
    address !== MY_ADDRESS
  ) {
    // Get address's socket.
    const socket = new WS(address);

    // Open a connection to the socket.
    socket.on("open", async () => {
      for (const _address of [MY_ADDRESS, ...connected])
        socket.send(produceMessage(TYPE.HANDSHAKE, _address));
      for (const node of opened)
        node.socket.send(produceMessage(TYPE.HANDSHAKE, address));

      // If the address already existed in "connected" or "opened", we will not push, preventing duplications.
      if (
        !opened.find((peer) => peer.address === address) &&
        address !== MY_ADDRESS
      ) {
        opened.push({socket, address});
      }

      if (
        !connected.find((peerAddress) => peerAddress === address) &&
        address !== MY_ADDRESS
      ) {
        connected.push(address);

        connectedNodes++;

        console.log(
          `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Connected to ${address}.`
        );

        // Listen for disconnection, will remove them from "opened" and "connected".
        socket.on("close", () => {
          opened.splice(connected.indexOf(address), 1);
          connected.splice(connected.indexOf(address), 1);
          // delete validatorAddress.address;
          // addressDB.del(address);

          console.log(
            `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Disconnected from ${address}.`
          );
        });
      }
    });
  }

  return true;
}

// Function to broadcast a transaction.
async function sendTransaction(transaction) {
  sendMessage(produceMessage(TYPE.CREATE_TRANSACTION, transaction), opened);

  console.log(
    `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Sent one transaction.`
  );

  await addTransaction(transaction, chainInfo, stateDB);
}

async function proposeBlock(publicKey, keyPair, ENABLE_LOGGING) {
  function mine(block) {
    return new Promise((resolve, reject) => {
      worker.addListener("message", (message) => resolve(message.result));

      worker.send({type: "MINE", data: [block]}); // Send a message to the worker thread, asking it to mine.
    });
  }

  // Block(blockNumber = 1, timestamp = Date.now(), transactions = [], parentHash = "",nodeAddress = "")
  // Create a new block.
  const block = new Block(
    chainInfo.latestBlock.blockNumber + 1,
    Date.now(),
    [], // Will add transactions down here
    chainInfo.latestBlock.hash,
    SHA256(publicKey)
  );

  // Collect a list of transactions to mine
  const transactionsToMine = [];
  const states = {};
  const code = {};
  const storage = {};
  const skipped = {};
  let totalTxGas = 0n;
  let totalContractGas = 0n;

  const existedAddresses = await stateDB.keys().all();

  for (const tx of chainInfo.transactionPool) {
    if (
      totalContractGas + BigInt(tx.additionalData.contractGas || 0) >=
      BigInt(BLOCK_GAS_LIMIT)
    )
      break;

    const txSenderPubkey = Transaction.getPubKey(tx);
    const txSenderAddress = SHA256(txSenderPubkey);

    if (skipped[txSenderAddress]) continue; // Check if transaction is from an ignored address.

    const totalAmountToPay =
      BigInt(tx.amount) +
      BigInt(tx.gas) +
      BigInt(tx.additionalData.contractGas || 0);

    // Normal coin transfers
    if (!states[txSenderAddress]) {
      const senderState = deserializeState(await stateDB.get(txSenderAddress));

      states[txSenderAddress] = senderState;
      code[senderState.codeHash] = await codeDB.get(senderState.codeHash);

      if (
        senderState.codeHash !== EMPTY_HASH ||
        BigInt(senderState.balance) < totalAmountToPay
      ) {
        skipped[txSenderAddress] = true;
        continue;
      }

      states[txSenderAddress].balance = (
        BigInt(senderState.balance) -
        BigInt(tx.amount) -
        BigInt(tx.gas) -
        BigInt(tx.additionalData.contractGas || 0)
      ).toString();
    } else {
      if (
        states[txSenderAddress].codeHash !== EMPTY_HASH ||
        BigInt(states[txSenderAddress].balance) < totalAmountToPay
      ) {
        skipped[txSenderAddress] = true;
        continue;
      }

      states[txSenderAddress].balance = (
        BigInt(states[txSenderAddress].balance) -
        BigInt(tx.amount) -
        BigInt(tx.gas) -
        BigInt(tx.additionalData.contractGas || 0)
      ).toString();
    }

    if (!existedAddresses.includes(tx.recipient) && !states[tx.recipient]) {
      states[tx.recipient] = {
        balance: "0",
        codeHash: EMPTY_HASH,
        storageRoot: EMPTY_HASH,
      };
      code[EMPTY_HASH] = "";
    }

    if (existedAddresses.includes(tx.recipient) && !states[tx.recipient]) {
      states[tx.recipient] = deserializeState(await stateDB.get(tx.recipient));
      code[states[tx.recipient].codeHash] = await codeDB.get(
        states[tx.recipient].codeHash
      );
    }

    states[tx.recipient].balance = (
      BigInt(states[tx.recipient].balance) + BigInt(tx.amount)
    ).toString();

    // Contract deployment
    if (
      states[txSenderAddress].codeHash === EMPTY_HASH &&
      typeof tx.additionalData.scBody === "string"
    ) {
      // states[txSenderAddress].codeHash = SHA256(tx.additionalData.scBody);
      code[states[txSenderAddress].codeHash] = tx.additionalData.scBody;
    }

    // Decide to drop or add transaction to block
    if (BigInt(states[txSenderAddress].balance) < 0n) {
      skipped[txSenderAddress] = true;
      continue;
    } else {
      transactionsToMine.push(tx);

      totalContractGas += BigInt(tx.additionalData.contractGas || 0);
      totalTxGas += BigInt(tx.gas) + BigInt(tx.additionalData.contractGas || 0);
    }
  }

  const transactionsAsObj = [...transactionsToMine];

  block.transactions = transactionsToMine.map((tx) =>
    Transaction.serialize(tx)
  ); // Add transactions to block
  block.txRoot = Merkle.buildTxTrie(transactionsAsObj).root; // Re-gen transaction root with new transactions
  block.hash = Block.getHash(block); // Re-hash with new transactions

  // Mine the block.
  mine(block)
    .then(async (block) => {
      // If the block is not mined before, we will add it to our chain and broadcast this new block.
      if (!mined) {
        chainInfo.latestBlock = block; // Update latest block cache

        // Reward
        if (
          !existedAddresses.includes(block.nodeAddress) &&
          !states[block.nodeAddress]
        ) {
          states[block.nodeAddress] = {
            balance: "0",
            codeHash: EMPTY_HASH,
            storageRoot: EMPTY_HASH,
          };
          code[EMPTY_HASH] = "";
        }

        if (
          existedAddresses.includes(block.nodeAddress) &&
          !states[block.nodeAddress]
        ) {
          states[block.nodeAddress] = deserializeState(
            await stateDB.get(block.nodeAddress)
          );
          code[states[block.nodeAddress].codeHash] = await codeDB.get(
            states[block.nodeAddress].codeHash
          );
        }

        let gas = 0n;

        for (const tx of transactionsAsObj) {
          gas += BigInt(tx.gas) + BigInt(tx.additionalData.contractGas || 0);
        }

        states[block.nodeAddress].balance = (
          BigInt(states[block.nodeAddress].balance) +
          BigInt(BLOCK_REWARD) +
          gas
        ).toString();

        // Transit state
        for (const address in storage) {
          const storageDB = new Level(
            __dirname + "/../../log/accountStore/" + address
          );
          const keys = Object.keys(storage[address]);

          states[address].storageRoot = Merkle.buildTxTrie(
            keys.map((key) => key + " " + storage[address][key]),
            false
          ).root;

          for (const key of keys) {
            await storageDB.put(key, storage[address][key]);
          }

          await storageDB.close();
        }

        for (const account of Object.keys(states)) {
          await stateDB.put(
            account,
            Buffer.from(serializeState(states[account]))
          );

          await codeDB.put(
            states[account].codeHash,
            code[states[account].codeHash]
          );
        }

        // Update the new transaction pool (remove all the transactions that are no longer valid).
        chainInfo.transactionPool = await clearDepreciatedTxns(
          chainInfo,
          stateDB
        );

        // Check whether preparePool and commitPool has been clear
        const intervalCheck = setInterval(function () {
          if (clearMessages || chainInfo.latestBlock.blockNumber == 2) {
            prepared = false;
            committed = false;
            clearMessages = false;

            // Create prepare messages
            let prepare = PreparePool.createPrepare(
              chainInfo.latestBlock,
              keyPair
            );
            chainInfo.preparePool.push(prepare); // Add to the pool

            sendMessage(
              produceMessage(TYPE.PRE_PREPARE, {
                newBlock: Block.serialize(chainInfo.latestBlock),
                prepareMsg: MessagePool.serializeMessage(prepare),
              }),
              opened
            ); // Broadcast the new block

            console.log(
              `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Broadcast pre_prepare message`
            );
            console.log(chainInfo);
            console.log(
              `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Block #${
                chainInfo.latestBlock.blockNumber
              } created and broadcasted, state transited.`
            );

            // Clear intervalCheck
            clearInterval(intervalCheck);
          }
        }, 100);
      } else {
        mined = false;
      }

      // Stop and Re-create the worker thread
      worker.kill();
      // if (connected.length === 0) {
      worker = fork(`${__dirname}/../miner/worker.js`);
      // }
    })
    .catch((err) =>
      console.log(
        `\x1b[31mERROR\x1b[0m [${new Date().toISOString()}] Error at mining child process`,
        err
      )
    );
}

// Function to mine continuously
async function loopPropose(publicKey, keyPair, ENABLE_LOGGING, chainInfo) {
  const currentTime = Date.now();
  const proposeTime = 3000;
  const nextTriggerTime = Math.ceil(currentTime / proposeTime) * proposeTime;
  // Sort validatorAddress in variable validatorAddress
  // let keys = await addressDB.keys().all();
  // let values = await addressDB.values().all();
  // let newValidatorAddress = {};
  // if (keys.length === values.length) {
  //   keys.forEach((key, index) => {
  //     newValidatorAddress[key] = values[index];
  //   });
  // }
  // validatorAddress = newValidatorAddress;

  setTimeout(async () => {
    // console.log(`loop propose call`);

    // Check transaction before propose block
    const transactionsToMine = [],
      states = {},
      skipped = {};
    for (const tx of chainInfo.transactionPool) {
      const txSenderPubkey = Transaction.getPubKey(tx);
      const txSenderAddress = SHA256(txSenderPubkey);

      if (skipped[txSenderAddress]) continue;

      const totalAmountToPay =
        BigInt(tx.amount) +
        BigInt(tx.gas) +
        BigInt(tx.additionalData.contractGas || 0);

      // Balance check
      if (!states[txSenderAddress]) {
        const senderState = deserializeState(
          await stateDB.get(txSenderAddress)
        );

        states[txSenderAddress] = senderState;
        // If sender do not have enough money, skip
        if (BigInt(senderState.balance) < totalAmountToPay) {
          skipped[txSenderAddress] = true;
          continue;
        }
        // Calculate after check every transaction
        states[txSenderAddress].balance = (
          BigInt(senderState.balance) -
          BigInt(tx.amount) -
          BigInt(tx.gas) -
          BigInt(tx.additionalData.contractGas || 0)
        ).toString();
      } else {
        // If sender do not have enough money, skip
        if (BigInt(states[txSenderAddress].balance) < totalAmountToPay) {
          skipped[txSenderAddress] = true;
          continue;
        }
        // Calculate after check every transaction
        states[txSenderAddress].balance = (
          BigInt(states[txSenderAddress].balance) -
          BigInt(tx.amount) -
          BigInt(tx.gas) -
          BigInt(tx.additionalData.contractGas || 0)
        ).toString();
      }

      // Decide to drop or add transaction to block
      if (BigInt(states[txSenderAddress].balance) < 0n) {
        skipped[txSenderAddress] = true;
        continue;
      } else {
        transactionsToMine.push(tx);
      }
    }

    if (transactionsToMine.length > 0) {
      // // Get all block from blockDB
      // const filterTimes = Date.now() - 20 * 1000; // 20 seconds
      // let blockInfo = await blockDB.values().all();
      // blockInfo = blockInfo.map((block) => Block.deserialize(block));
      // // console.log(blockInfo);

      // // Filtered block from 20s ago
      // const filteredBlock = blockInfo.filter((obj) => {
      //   return new Date(obj.timestamp) >= filterTimes;
      // });
      // // console.log(filteredBlock);

      // // All txs from filtered block
      // const allTransactions = filteredBlock.map((block) => block.transactions);
      // // console.log(allTransactions);

      // //filter all txs in all blocks to array
      // const flattenTx = allTransactions.flat();
      // const deserializedTx = flattenTx.map((tx) => Transaction.deserialize(tx));

      // // Get total distance from all filtered transactions
      // const numberOfMiner = Object.keys(validatorAddress).length;

      // const totalDistance = deserializedTx.reduce((distance, transaction) => {
      //   return (
      //     (distance + BigInt(transaction.additionalData.scBody || 0)) /
      //     numberOfMiner
      //   );
      // }, BigInt(0));
      // // console.log("totalDistance: " + totalDistance);

      // // Get total distance of each sender from all filtered transactions
      // const senderDistance = deserializedTx.reduce((distance, transaction) => {
      //   const senderAddress = SHA256(Transaction.getPubKey(transaction));
      //   const scBodyValue = BigInt(transaction.additionalData.scBody);

      //   if (!distance[senderAddress]) {
      //     distance[senderAddress] = scBodyValue;
      //   } else {
      //     distance[senderAddress] += scBodyValue;
      //   }

      //   return distance;
      // }, {});

      // for (const [senderAddress, total] of Object.entries(senderDistance)) {
      //   // console.log(`senderAddress: ${senderAddress} \nDistance: ${total}`);
      // }
      // for (
      //   let txIndex = 0;
      //   txIndex < blockInfo.transactions.length;
      //   txIndex++
      // ) {
      //   const tx = Transaction.deserialize(blockInfo.transactions[txIndex]);
      // }

      // PBFT begin here
      // Random choose a proposer
      const validator = await addressDB.values().all();
      const proposer = await chooseProposer(validator, chainInfo.latestBlock);
      console.log(
        `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Proposer address: ` +
          proposer
      );
      if (proposer == SHA256(publicKey)) {
        await proposeBlock(publicKey, keyPair, ENABLE_LOGGING);
      }
    }
  }, nextTriggerTime - currentTime);
}

async function startLoopProposeInterval(
  publicKey,
  keyPair,
  ENABLE_LOGGING,
  chainInfo
) {
  setInterval(async () => {
    await loopPropose(publicKey, keyPair, ENABLE_LOGGING, chainInfo);
  }, 3000);
}

async function disableChainRequest() {
  if ((await blockDB.keys().all()).length === 0) {
    // Initial state
    console.log(chainInfo.latestBlock);
    await stateDB.put(
      FIRST_ACCOUNT,
      Buffer.from(
        serializeState({
          balance: INITIAL_SUPPLY,
          codeHash: EMPTY_HASH,
          storageRoot: EMPTY_HASH,
        })
      )
    );

    await blockDB.put(
      chainInfo.latestBlock.blockNumber.toString(),
      Buffer.from(Block.serialize(chainInfo.latestBlock))
    );
    await bhashDB.put(
      chainInfo.latestBlock.hash,
      numToBuffer(chainInfo.latestBlock.blockNumber)
    ); // Assign block number to the matching block hash

    console.log(
      `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Created Genesis Block with:\n` +
        `    Block number: ${chainInfo.latestBlock.blockNumber.toString()}\n` +
        `    Timestamp: ${chainInfo.latestBlock.timestamp.toString()}\n` +
        `    NodeAddress: ${chainInfo.latestBlock.nodeAddress.toString()}\n` +
        `    Hash: ${chainInfo.latestBlock.hash.toString()}\n` +
        `    TxRoot: ${chainInfo.latestBlock.txRoot.toString()}`
    );

    await changeState(chainInfo.latestBlock, stateDB, codeDB);
  } else {
    // Update latest block in chain cache
    chainInfo.latestBlock = Block.deserialize([
      ...(await blockDB.get(
        Math.max(
          ...(await blockDB.keys().all()).map((key) => parseInt(key))
        ).toString()
      )),
    ]);
  }
}

async function enableChainRequest(
  currentSyncBlock,
  MY_ADDRESS,
  nodeAddress,
  proposeStatus
) {
  const blockNumbers = await blockDB.keys().all();

  // Get the last block in stateDB to synchronize
  if (blockNumbers.length !== 0) {
    currentSyncBlock = Math.max(...blockNumbers.map((key) => parseInt(key)));
    // currentSyncBlock = 1;
  }
  console.log(
    `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Enable chain request`
  );
  if (currentSyncBlock === 1) {
    // Lưu trạng thái khởi tạo vào tài khoản FIRST_ACCOUNT trong database stateDB
    await stateDB.put(
      nodeAddress,
      Buffer.from(
        serializeState({
          balance: INITIAL_SUPPLY,
          codeHash: EMPTY_HASH,
          storageRoot: EMPTY_HASH,
        })
      )
    );
  }

  return new Promise((resolve) => {
    setTimeout(async () => {
      for (const node of opened) {
        node.socket.send(
          produceMessage(TYPE.REQUEST_BLOCK, {
            blockNumber: currentSyncBlock,
            requestAddress: MY_ADDRESS,
            nodeAddress: nodeAddress,
            proposeStatus: proposeStatus,
          })
        );
      }
      // Resolve the Promise with currentSyncBlock
      resolve(currentSyncBlock);
    }, 2000);
  });
}

async function startServer(options) {
  const PORT = options.PORT || 3000; // Node's PORT
  const API_PORT = options.API_PORT || 5000; // API server's PORT
  const PEERS = options.PEERS || []; // Peers to connect to
  const MAX_PEERS = options.MAX_PEERS || 10; // Maximum number of peers to connect to
  const MY_ADDRESS = options.MY_ADDRESS || "ws://localhost:3000"; // Node's address
  const ENABLE_MINING = options.ENABLE_MINING ? true : false; // Enable mining?
  const ENABLE_LOGGING = options.ENABLE_LOGGING ? true : false; // Enable logging?
  const ENABLE_API = options.ENABLE_API ? true : false; // Enable API server?
  let ENABLE_CHAIN_REQUEST = options.ENABLE_CHAIN_REQUEST ? true : false; // Enable chain sync request?
  const GENESIS_HASH = options.GENESIS_HASH || ""; // Genesis block's hash
  const PROPOSE_INTERVAL = options.PROPOSE_INTERVAL || 5000;

  const privateKey = options.PRIVATE_KEY || ec.genKeyPair().getPrivate("hex");
  const keyPair = ec.keyFromPrivate(privateKey, "hex");
  const publicKey = keyPair.getPublic("hex");

  process.on("uncaughtException", (err) =>
    console.log(
      `\x1b[31mERROR\x1b[0m [${new Date().toISOString()}] Uncaught Exception`,
      err
    )
  );

  await codeDB.put(EMPTY_HASH, "");
  // Lưu địa chỉ node
  if (ENABLE_MINING) {
    validatorAddress[MY_ADDRESS] = SHA256(publicKey);
    await addressDB.put(MY_ADDRESS, SHA256(publicKey));
  }

  const server = new WS.Server({port: PORT});

  console.log(
    `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] P2P server listening on PORT`,
    PORT.toString()
  );

  server.on("connection", async (socket, req) => {
    // Message handler
    socket.on("message", async (message) => {
      const _message = parseJSON(message); // Parse binary message to JSON

      switch (_message.type) {
        // Below are handlers for every message types.

        case TYPE.HANDSHAKE:
          const address = _message.data;

          if (connectedNodes <= MAX_PEERS) {
            try {
              connect(MY_ADDRESS, address);
            } catch (e) {
              // Debug console.log(e);
            }
          }
        case TYPE.REQUEST_BLOCK:
          const {blockNumber, requestAddress, nodeAddress, proposeStatus} =
            _message.data;

          if (blockNumber === undefined) break;
          let requestedBlock;
          // Send node address to join validating request
          if (
            proposeStatus &&
            !validatorAddress.hasOwnProperty("nodeAddress")
          ) {
            await addressDB.put(requestAddress, nodeAddress);
            validatorAddress[requestAddress] = nodeAddress;
          }

          // Check and add address to the stateDB
          const existedAddresses = await stateDB.keys().all();
          if (!existedAddresses.includes(nodeAddress)) {
            await stateDB.put(
              nodeAddress,
              Buffer.from(
                serializeState({
                  balance: "0",
                  codeHash: EMPTY_HASH,
                  storageRoot: EMPTY_HASH,
                })
              )
            );
          }

          const socket = opened.find(
            (node) => node.address === requestAddress
          ).socket; // Get socket from address

          try {
            requestedBlock = [...(await blockDB.get(blockNumber.toString()))]; // Get block
          } catch (err) {
            if (err.notFound) {
              socket.send(
                produceMessage(TYPE.SEND_BLOCK, {
                  responseBlock: requestedBlock,
                  listNodeAddress: validatorAddress,
                })
              ); // Send block
            } else {
              // Handle other errors (if needed)
              console.error(
                "An error occurred while fetching the block:",
                err.message
              );
            }
            // If block does not exist, break
            break;
          }

          socket.send(
            produceMessage(TYPE.SEND_BLOCK, {
              responseBlock: requestedBlock,
              listNodeAddress: validatorAddress,
            })
          ); // Send block
          console.log(
            `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Sent block at position ${blockNumber} to ${requestAddress}.`
          );

          break;

        case TYPE.SEND_BLOCK:
          const {responseBlock, listNodeAddress} = _message.data;
          let block;
          // Save validatorAddress list

          const addressInState = await stateDB.keys().all();
          for (let key in listNodeAddress) {
            if (!validatorAddress.hasOwnProperty(key)) {
              validatorAddress[key] = listNodeAddress[key];
              addressDB.put(key, listNodeAddress[key], function (err) {
                if (err) return console.log("Error saving data:", err);
              });
            }

            if (!addressInState.includes(listNodeAddress[key])) {
              await stateDB.put(
                validatorAddress[key],
                Buffer.from(
                  serializeState({
                    balance: "0",
                    codeHash: EMPTY_HASH,
                    storageRoot: EMPTY_HASH,
                  })
                )
              );
            }
          }

          try {
            block = Block.deserialize(responseBlock);
          } catch (error) {
            console.error(
              `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Sync chain finish`
            );
            // If block fails to be deserialized, it's faulty
            ENABLE_CHAIN_REQUEST = false;

            return;
          }

          // If latest synced block is null, we immediately add the block into the chain without verification.
          // This happens due to the fact that the genesis block can discard every possible set rule ¯\_(ツ)_/¯

          // But wait, isn't that unsafe? Well, this is because we don't have an official JeChain "network" yet.
          // But if there is, one can generate the first genesis block and we can add its hash into config,
          // we then check if the genesis block matches with the hash which is safe.
          if (ENABLE_CHAIN_REQUEST && block.blockNumber === currentSyncBlock) {
            const verificationHandler = async function (block) {
              if (
                (chainInfo.latestSyncBlock === null &&
                  (!GENESIS_HASH || GENESIS_HASH === block.hash)) || // For genesis
                (await verifyBlock(
                  block,
                  chainInfo,
                  stateDB,
                  codeDB,
                  ENABLE_LOGGING
                )) // For all others
              ) {
                await blockDB.put(
                  block.blockNumber.toString(),
                  Buffer.from(responseBlock)
                ); // Add block to chain
                await bhashDB.put(block.hash, numToBuffer(block.blockNumber)); // Assign block number to the matching block hash

                // Assign transaction index and block number to transaction hash
                for (
                  let txIndex = 0;
                  txIndex < block.transactions.length;
                  txIndex++
                ) {
                  const tx = Transaction.deserialize(
                    block.transactions[txIndex]
                  );
                  const txHash = Transaction.getHash(tx);

                  await txhashDB.put(
                    txHash,
                    block.blockNumber.toString() + " " + txIndex.toString()
                  );
                }

                if (!chainInfo.latestSyncBlock) {
                  chainInfo.latestSyncBlock = block; // Update latest synced block.
                  await changeState(block, stateDB, codeDB, ENABLE_LOGGING); // Force transit state
                }

                chainInfo.latestBlock = block; // Update latest block cache
                console.log(
                  `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Synced block at position ${
                    block.blockNumber
                  }.`
                );

                chainInfo.syncing = false;
                chainInfo.syncQueue.wipe(); // Wipe sync queue
                currentSyncBlock++;

                // Continue requesting the next block
                for (const node of opened) {
                  node.socket.send(
                    produceMessage(TYPE.REQUEST_BLOCK, {
                      blockNumber: currentSyncBlock,
                      requestAddress: MY_ADDRESS,
                      nodeAddress: SHA256(publicKey),
                      proposeStatus: ENABLE_MINING,
                    })
                  );
                }

                return true;
              }

              return false;
            };

            chainInfo.syncQueue.add(block, verificationHandler);
          }

          break;

        case TYPE.CREATE_TRANSACTION:
          if (ENABLE_CHAIN_REQUEST) break; // Unsynced nodes should not be able to proceed.

          // TYPE.CREATE_TRANSACTION is sent when someone wants to submit a transaction.
          // Its message body must contain a transaction.

          // Weakly verify the transation, full verification is achieved in block production.

          let transaction;
          console.log(`Create transaction call`);

          try {
            transaction = Transaction.deserialize(_message.data);
          } catch (e) {
            // If transaction can not be deserialized, it's faulty
            break;
          }

          if (!(await Transaction.isValid(transaction, stateDB))) break;

          // Get public key and address from sender
          const txSenderPubkey = Transaction.getPubKey(transaction);
          const txSenderAddress = SHA256(txSenderPubkey);

          if (!(await stateDB.keys().all()).includes(txSenderAddress)) break;

          // After transaction is added, the transaction must be broadcasted to others since the sender might only send it to a few nodes.

          // This is pretty much the same as addTransaction, but we will send the transaction to other connected nodes if it's valid.

          if (
            !(await Transaction.compareTx(
              transaction.signature,
              chainInfo.transactionPool
            ))
          ) {
            console.log(
              `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] New transaction received, broadcasted and added to pool.`
            );

            chainInfo.transactionPool.push(transaction);

            // Broadcast the transaction
            sendMessage(message, opened);
          }

          break;

        case TYPE.PRE_PREPARE:
          // "TYPE.PRE_PREPARE" is sent when someone wants to submit a new block.
          // Its message body must contain the new block

          let {newBlock, prepareMsg} = _message.data;

          if (!ENABLE_MINING) break;

          try {
            newBlock = Block.deserialize(newBlock);
          } catch (e) {
            // If block fails to be deserialized, it's faulty
            if (e.notFound) {
              console.error(`Block number not found in blockDB: ${newBlock}`);
            }
            return;
          }
          try {
            prepareMsg = MessagePool.deserializeMessage(prepareMsg);
          } catch (e) {
            // If block fails to be deserialized, it's faulty
            if (e.notFound) {
              console.error(`prepareMsg error: ${prepareMsg}`);
            }
            return;
          }

          // Checking proposer address
          let proposerPrePrepare = await addressDB.values().all();
          if (
            Block.verifyNodeAddress(
              newBlock,
              await chooseProposer(proposerPrePrepare, newBlock)
            )
          ) {
            if (!chainInfo.checkedBlock[newBlock.hash]) {
              chainInfo.checkedBlock[newBlock.hash] = true;
            } else {
              return;
            }

            if (
              newBlock.parentHash !== chainInfo.latestBlock.parentHash &&
              (!ENABLE_CHAIN_REQUEST ||
                (ENABLE_CHAIN_REQUEST && currentSyncBlock > 1))
              // Only proceed if syncing is disabled or enabled but already synced at least the genesis block
            ) {
              chainInfo.checkedBlock[newBlock.hash] = true;

              console.log("Pre_Prepare call");
              // Need to check again
              if (
                await verifyBlock(
                  newBlock,
                  chainInfo,
                  stateDB,
                  codeDB,
                  ENABLE_LOGGING
                )
              ) {
                console.log(
                  `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] New block received.`
                );

                chainInfo.latestBlock = newBlock; // Update latest block to chainInfo variable

                sendMessage(message, opened); // Broadcast block to other nodes

                // Create prepare messages
                prepared = false;
                committed = false;
                clearMessages = false;

                let proposerPrepare = Object.values(validatorAddress);

                if (
                  !PreparePool.existingPrepare(chainInfo, prepareMsg) &&
                  PreparePool.isValidPrepare(proposerPrepare, prepareMsg) &&
                  proposerPrepare.includes(SHA256(prepareMsg.publicKey))
                ) {
                  chainInfo.preparePool.push(prepareMsg); // Add to the pool

                  let prepare = PreparePool.createPrepare(
                    chainInfo.latestBlock,
                    keyPair
                  );

                  chainInfo.preparePool.push(prepare); // Add to the pool

                  sendMessage(
                    produceMessage(
                      TYPE.PREPARE,
                      MessagePool.serializeMessage(prepare)
                    ),
                    opened
                  ); // Broadcast prepare message
                }

                if (ENABLE_CHAIN_REQUEST) {
                  ENABLE_CHAIN_REQUEST = false;
                }
              } else {
                console.log("false to verify block");
                console.log(`block.hash`);
                console.log(
                  SHA256(
                    newBlock.blockNumber.toString() +
                      newBlock.timestamp.toString() +
                      newBlock.txRoot +
                      chainInfo.latestBlock.hash
                  )
                );
                console.log(newBlock.hash);
                console.log(`block.parentHash`);
                console.log(chainInfo.latestBlock.hash === newBlock.parentHash);
                console.log(`hasValidTxOrder`);
                console.log(await Block.hasValidTxOrder(newBlock, stateDB));
                console.log(`block.txRoot`);
                console.log(
                  Merkle.buildTxTrie(newBlock.transactions).root ===
                    newBlock.txRoot
                );
                console.log(`block.timestamp`);
                console.log(
                  newBlock.timestamp > chainInfo.latestBlock.timestamp
                );
                console.log(newBlock.timestamp < Date.now());
                console.log(`block.blockNumber`);
                console.log(
                  newBlock.blockNumber - 1 === chainInfo.latestBlock.blockNumber
                );
                console.log(`hasValidGasLimit`);
                console.log(Block.hasValidGasLimit(newBlock));
                console.log(`verifyTransactionAndTransit`);
                console.log(
                  await Block.verifyTransactionAndTransit(
                    newBlock,
                    stateDB,
                    codeDB,
                    ENABLE_LOGGING
                  )
                );
              }
            } else {
              // console.log("false to update block");
              // console.log(`parendHash`);
              // console.log(newBlock.parentHash);
              // console.log(chainInfo.latestBlock.parentHash);
              // console.log(`currentSyncBlock`);
              // console.log(currentSyncBlock);
            }
          } else {
            console.log("false");
          }
          // We will only continue checking the block if its parentHash is not the same as the latest block's hash.
          // This is because the block sent to us is likely duplicated or from a node that has lost and should be discarded.

          break;

        case TYPE.PREPARE:
          // "TYPE.PREPARE" is sent when a nodes wants to submit a new prepare message in pbft consensus.
          // Its message body must contain the prepare message
          let prepare = _message.data;
          if (!ENABLE_MINING) break;

          console.log("Prepare call");
          let proposerPrepare = Object.values(validatorAddress);

          try {
            prepare = MessagePool.deserializeMessage(prepare);
          } catch (e) {
            // If block fails to be deserialized, it's faulty
            if (e.notFound) {
              console.error(`prepareMsg error: ${prepare}`);
            }
            return;
          }

          if (
            !prepared &&
            PreparePool.isValidPrepare(proposerPrepare, prepare) &&
            proposerPrepare.includes(SHA256(prepare.publicKey))
          ) {
            if (!PreparePool.existingPrepare(chainInfo, prepare)) {
              // Add prepare message to the pool
              chainInfo.preparePool.push(prepare);

              // Send to other nodes
              sendMessage(message, opened);
            }

            // Minimum requirement
            let prepareApprovals = await minApprovals(proposerPrepare);

            // If minimum requirement of prepare message reached, send commit message
            if (chainInfo.preparePool.length >= prepareApprovals) {
              // Mark as prepared
              prepared = true;
              // Create commit messages
              let commit = CommitPool.createCommit(prepare, keyPair);
              chainInfo.commitPool.push(commit);
              sendMessage(
                produceMessage(
                  TYPE.COMMIT,
                  MessagePool.serializeMessage(commit)
                ),
                opened
              );
            }
          }

          break;

        case TYPE.COMMIT:
          // "TYPE.COMMIT" is sent when a nodes wants to submit a new commit message in pbft consensus.
          // Its message body must contain the commit message
          let commit = _message.data;

          if (!ENABLE_MINING) break;
          console.log("Commit call");
          let proposerCommit = Object.values(validatorAddress);

          try {
            commit = MessagePool.deserializeMessage(commit);
          } catch (e) {
            // If block fails to be deserialized, it's faulty
            if (e.notFound) {
              console.error(`commitMsg error: ${commit}`);
            }
            return;
          }

          if (
            !committed &&
            !CommitPool.existingCommit(chainInfo, commit) &&
            CommitPool.isValidCommit(proposerCommit, commit) &&
            proposerCommit.includes(SHA256(commit.publicKey))
          ) {
            // Add commit message to the pool
            chainInfo.commitPool.push(commit);

            // Send to other nodes
            sendMessage(message, opened);

            // Minimum requirement
            let commitApprovals = await minApprovals(proposerCommit);
            // If minimum requirement of commit message reached, update block to chain
            if (chainInfo.commitPool.length >= commitApprovals) {
              // mark as committed
              committed = true;
              // Add block to chain
              if (
                !(await blockDB.keys().all()).includes(
                  chainInfo.latestBlock.blockNumber.toString()
                )
              ) {
                await blockDB.put(
                  chainInfo.latestBlock.blockNumber.toString(),
                  Buffer.from(Block.serialize(chainInfo.latestBlock))
                );

                // Assign block number to the matching block hash
                await bhashDB.put(
                  chainInfo.latestBlock.hash,
                  numToBuffer(chainInfo.latestBlock.blockNumber)
                );

                // Apply to all txns of the block: Assign transaction index and block number to transaction hash
                for (
                  let txIndex = 0;
                  txIndex < chainInfo.latestBlock.transactions.length;
                  txIndex++
                ) {
                  const tx = Transaction.deserialize(
                    chainInfo.latestBlock.transactions[txIndex]
                  );
                  const txHash = Transaction.getHash(tx);

                  await txhashDB.put(
                    txHash,
                    chainInfo.latestBlock.blockNumber.toString() +
                      " " +
                      txIndex.toString()
                  );
                }

                chainInfo.transactionPool = await clearDepreciatedTxns(
                  chainInfo,
                  stateDB
                );

                console.log(
                  `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Block #${
                    chainInfo.latestBlock.blockNumber
                  } synced, state transited.`
                );
                console.log(chainInfo);
              }

              // Create and add message round change to the pool
              let roundChange = MessagePool.createMessage(
                chainInfo.latestBlock,
                keyPair
              );
              messagePool.push(roundChange);

              sendMessage(
                produceMessage(TYPE.ROUND_CHANGE, {
                  roundChange: MessagePool.serializeMessage(roundChange),
                  verifiedBlock: Block.serialize(chainInfo.latestBlock),
                }),
                opened
              );
            }
          }

          break;

        case TYPE.ROUND_CHANGE:
          let {roundChange, verifiedBlock} = _message.data;

          let proposerMsg = Object.values(validatorAddress);

          try {
            roundChange = MessagePool.deserializeMessage(roundChange);
          } catch (e) {
            // If block fails to be deserialized, it's faulty
            if (e.notFound) {
              console.error(`roundchangeMsg error: ${commit}`);
            }
            return;
          }

          // Validate message
          if (
            !MessagePool.existingMessage(messagePool, roundChange) &&
            MessagePool.isValidMessage(proposerMsg, roundChange) &&
            proposerMsg.includes(SHA256(roundChange.publicKey))
          ) {
            if (!ENABLE_MINING) {
              try {
                verifiedBlock = Block.deserialize(verifiedBlock);
              } catch (e) {
                // If block fails to be deserialized, it's faulty

                return;
              }
              if (!chainInfo.checkedBlock[verifiedBlock.hash]) {
                chainInfo.checkedBlock[verifiedBlock.hash] = true;
              } else {
                return;
              }

              if (
                verifiedBlock.parentHash !== chainInfo.latestBlock.parentHash &&
                (!ENABLE_CHAIN_REQUEST ||
                  (ENABLE_CHAIN_REQUEST && currentSyncBlock > 1))
                // Only proceed if syncing is disabled or enabled but already synced at least the genesis block
              ) {
                chainInfo.checkedBlock[verifiedBlock.hash] = true;
                // Need to check again
                if (
                  await verifyBlock(
                    verifiedBlock,
                    chainInfo,
                    stateDB,
                    codeDB,
                    ENABLE_LOGGING
                  )
                ) {
                  console.log(
                    `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] New block received.`
                  );
                  // Add block to the chain for disable mining nodes
                  await blockDB.put(
                    verifiedBlock.blockNumber.toString(),
                    Buffer.from(Block.serialize(verifiedBlock))
                  ); // Add block to chain

                  await bhashDB.put(
                    verifiedBlock.hash,
                    numToBuffer(verifiedBlock.blockNumber)
                  ); // Assign block number to the matching block hash

                  // Apply to all txns of the block: Assign transaction index and block number to transaction hash
                  for (
                    let txIndex = 0;
                    txIndex < verifiedBlock.transactions.length;
                    txIndex++
                  ) {
                    const tx = Transaction.deserialize(
                      verifiedBlock.transactions[txIndex]
                    );
                    const txHash = Transaction.getHash(tx);
                    await txhashDB.put(
                      txHash,
                      verifiedBlock.blockNumber.toString() +
                        " " +
                        txIndex.toString()
                    );
                  }

                  chainInfo.latestBlock = verifiedBlock; // Update latest block variable

                  // Update the new transaction pool (remove all the transactions that are no longer valid).
                  chainInfo.transactionPool = await clearDepreciatedTxns(
                    chainInfo,
                    stateDB
                  );

                  console.log(
                    `\x1b[32mLOG\x1b[0m [${new Date().toISOString()}] Block #${
                      verifiedBlock.blockNumber
                    } synced, state transited.`
                  );
                }
              }
            } else {
              if (!clearMessages) {
                console.log(`Round change`);
                //Add message to the pool
                messagePool.push(roundChange);

                // Clear prepare pool and commit pool
                PreparePool.clearPreparePool(chainInfo);
                CommitPool.clearCommitPool(chainInfo);
                clearMessages = true;

                // Send to other nodes
                sendMessage(message, opened);

                messagePool.splice(0, messagePool.length);
              }
            }
          }
          break;
      }
    });
  });

  try {
    PEERS.forEach(async (peer) => await connect(MY_ADDRESS, peer)); // Connect to peers
  } catch (e) {}

  // If node is a proposer
  if (!ENABLE_CHAIN_REQUEST) {
    await disableChainRequest(chainInfo);
  }
  // Sync chain
  let currentSyncBlock = 1;

  if (ENABLE_CHAIN_REQUEST) {
    await enableChainRequest(
      currentSyncBlock,
      MY_ADDRESS,
      SHA256(publicKey),
      ENABLE_MINING
    ).then((newCurrentSyncBlock) => {
      currentSyncBlock = newCurrentSyncBlock;
    });
  }

  if (ENABLE_MINING)
    await startLoopProposeInterval(
      publicKey,
      keyPair,
      ENABLE_LOGGING,
      chainInfo
    );
  if (ENABLE_API)
    api(
      API_PORT,
      {publicKey, mining: ENABLE_MINING, chainInfo},
      sendTransaction,
      keyPair,
      stateDB,
      blockDB,
      bhashDB,
      codeDB,
      txhashDB
    );
}

module.exports = {startServer};
