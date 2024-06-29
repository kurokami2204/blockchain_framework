const {Level} = require("level");
const crypto = require("crypto"),
  SHA256 = (message) =>
    crypto.createHash("sha256").update(message).digest("hex");
const EC = require("elliptic").ec,
  ec = new EC("secp256k1");
const Block = require("../core/block");

const {
  parseJSON,
  numToBuffer,
  bufferToNum,
  serializeState,
  deserializeState,
} = require("../utils/utils");
const Transaction = require("../core/transaction");
const stateDB = new Level("../../log/stateStore", {
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

const getStateDB = async (account) => {
  return new Promise((resolve, reject) => {
    stateDB.get(account, (err, value) => {
      if (err) {
        console.error("Error retrieving state data:", err);
        reject(err); // Reject the promise if there's an error
      } else {
        const deserializedValue = deserializeState(value);
        const balance = deserializedValue.balance;
        const codeHash = deserializedValue.codeHash;
        const storageRoot = deserializedValue.storageRoot;
        const state = {
          balance: balance,
          codeHash: codeHash,
          storageRoot: storageRoot,
        };
        resolve(state); // Resolve the promise with the retrieved state
      }
    });
  });
};

const getBlockDB = async (blockNumber) => {
  return new Promise((resolve, reject) => {
    blockDB.get(blockNumber.toString(), (err, value) => {
      if (err) {
        console.error(
          `Can not get block by block number ${blockNumber}: ${err}`
        );
        reject(err);
      } else {
        const deserializedValue = Block.deserialize(value);
        const blockNumber = deserializedValue.blockNumber;
        const timestamp = deserializedValue.timestamp;
        const parentHash = deserializedValue.parentHash;
        const txRoot = deserializedValue.txRoot;
        const nodeAddress = deserializedValue.nodeAddress;
        const hash = deserializedValue.hash;
        const block = {
          blockNumber: blockNumber,
          timestamp: timestamp,
          parentHash: parentHash,
          txRoot: txRoot,
          nodeAddress: nodeAddress,
          hash: hash,
        };
        resolve(block);
      }
    });
  });
};

const getbhashDB = async (blockHash) => {
  return new Promise((resolve, reject) => {
    bhashDB.get(blockHash, (err, value) => {
      if (err) {
        console.error(`Can not retrieve block hash ${blockHash}: ${err}`);
        reject(err);
      } else {
        const blockNumber = value.readUIntBE(0, value.length);
        resolve(blockNumber);
      }
    });
  });
};

const getTxHash = async (txHash) => {
  return new Promise((resolve, reject) => {
    txhashDB.get(txHash, (err, value) => {
      if (err) {
        console.error(`Can not get transaction hash ${txHash}: ${err}`);
        reject(err);
      } else {
        const deserializedValue = deserializeState(value);
        resolve(deserializedValue);
      }
    });
  });
};

const getCodeDB = async (code) => {
  return new Promise((resolve, reject) => {
    codeDB.get(code, (err, value) => {
      if (err) {
        console.error(`Can not get code ${code}: ${err} `);
        reject(err);
      } else {
        console.log(`Value: ${value}`);
        // const deserializedValue = deserializeState(value);
        // console.log(deserializedValue)
        // resolve(deserializedValue);
      }
    });
  });
};

// *** TEST ***
const main = async () => {
  const privateKey =
    "fc92f78ca113cf33f174d158300ec832dc4ecad60eaa980ce8f990fa89edca3b";
  const keyPair = ec.keyFromPrivate(privateKey, "hex");
  const publicKey = keyPair.getPublic("hex");
  const nodeAddress = SHA256(publicKey);

  // block.blockNumber.toString(),
  // Buffer.from(Block.serialize(block))
  // const blockNumber = 2;
  // for (let i = 1; i <= blockNumber; i++) {
  //   const bDB = await getBlockDB(i);
  //   console.log(bDB);
  // }
  // let blockData = [];
  // await blockDB.createReadStream().on("data", function (data) {
  //   const block = JSON.parse(Block.deserialize(data.value));
  //   if (block.timestamp && block.timestamp > 5000000) {
  //     blockData.push(value);
  //   }
  // });
  // console.log(blockData);
  const filterTimes = Date.now() - 60 * 1000; // 20 seconds
  // let block = await blockDB.keys().all();
  // console.log(block);
  let blockInfo = await blockDB.values().all();
  blockInfo = blockInfo.map((block) => Block.deserialize(block));
  console.log(blockInfo);

  const filteredBlock = blockInfo.filter((obj) => {
    return new Date(obj.timestamp) >= filterTimes;
  });
  console.log(filteredBlock);

  const allTransactions = blockInfo.map((block) => block.transactions);
  // console.log(allTransactions);
  // const filteredTx = allTransactions.filter((item) =>
  //   Array.isArray(item) ? item.length > 0 : true
  // );
  // console.log(filteredTx);
  //filter all txs in all blocks to array
  const flattenTx = allTransactions.flat(); // ???
  const deserializedTx = flattenTx.map((tx) => Transaction.deserialize(tx));
  // for (let txIndex = 0; txIndex < blockInfo.transactions.length; txIndex++) {
  //   const tx = Transaction.deserialize(blockInfo.transactions[txIndex]);
  //   console.log(tx);
  // }

  const totalDistance = deserializedTx.reduce((distance, transaction) => {
    return distance + BigInt(transaction.additionalData.scBody || 0);
  }, BigInt(0));
  console.log(`transactions`);
  // console.log(deserializedTx);
  console.log("totalDistance: " + totalDistance);

  const senderDistance = deserializedTx.reduce((distance, transaction) => {
    const senderAddress = SHA256(Transaction.getPubKey(transaction));
    const scBodyValue = BigInt(transaction.additionalData.scBody);

    if (!distance[senderAddress]) {
      distance[senderAddress] = scBodyValue;
    } else {
      distance[senderAddress] += scBodyValue;
    }

    return distance;
  }, {});

  for (const [senderAddress, total] of Object.entries(senderDistance)) {
    console.log(`senderAddress: ${senderAddress} \nDistance: ${total}`);
  }
  // console.log("recipientDistance: " + senderDistance);

  console.log(`bhashDB`);
  // bHash
  let bHash = await bhashDB.keys().all();
  console.log(bHash);
  // numToBuffer
  let bHashInfo = await bhashDB.values().all();
  bHashInfo = bHashInfo.map((tx) => bufferToNum(tx));
  console.log(bHashInfo);
  console.log(`txhashDB`);
  // txHash
  let tx = await txhashDB.keys().all();
  console.log(tx);
  // blockNumber.toStrings + " " + block.transactions.txIndex.toStrings
  let info = await txhashDB.values().all();
  console.log(info);
  console.log(`codeDB`);
  // SHA256(scBody)
  let code = await codeDB.keys().all();
  console.log(code);
  //scBody
  let codeInfo = await codeDB.values().all();
  console.log(codeInfo);
  console.log(`stateDB`);
  let address = await stateDB.keys().all();
  console.log(address);
  let addressInfo = await stateDB.values().all();
  addressInfo = addressInfo.map((state) => deserializeState(state));
  console.log(addressInfo);
  let addressAll = await addressDB.keys().all();
  console.log(addressAll);
  let publicAddress = await addressDB.values().all();
  // console.log(Date.now());
  console.log(publicAddress);

  let MY_ADDRESS = "ws://192.168.50.204:10511"; // replace with your actual address

  addressDB.get(MY_ADDRESS, function (err, value) {
    if (err) {
      if (err.notFound) {
        console.log("Address not found in database");
      } else {
        console.log("Failed to read address from database:", err);
      }
    } else {
      console.log("Address:", value);
    }
  });
};

main();
