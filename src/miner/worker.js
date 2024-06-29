"use strict";

// Miner worker thread's code.

const Block = require("../core/block");
const {log16} = require("../utils/utils");

// Listening for messages from the main process.
process.on("message", (message) => {
  if (message.type === "MINE") {
    // When the "MINE" message is received, the thread should be mining by incrementing the nonce value until a preferable hash is met.

    const block = message.data[0];

    process.send({result: block});
    block.hash = Block.getHash(block);
  }
});
