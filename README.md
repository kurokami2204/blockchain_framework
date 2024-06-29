### Requirements

Operating System Windows, Linux, or MaxOS with a minimum of dual-core, 8GB RAM, and the minimum storage for the blockchain is 1GB.

### Installation

Extract the zip file in the `project-vehicle-chain` folder, open terminal and install the required packages through `npm`:

```
npm install
```

### Configure the node

In `config.json`, these properties should be configured:

```js
{
    "PORT": /*PORT that node run on, default: 3000*/,
    "API_PORT": /*PORT that the API server run on, , default: 5000*/,

    "PEERS": /*An array contains peers' addresses that the node will connect with, default is an empty array*/,
    "MY_ADDRESS": /*A string contains a node's address, default: "localhost:3000"*/,
    "PRIVATE_KEY": /*A string contains a node's private key*/,

    "ENABLE_MINING": /*To enable mining function of a node, default: false*/
    "ENABLE_API": /*To interact with blockchain network, default: false*/,
    "ENABLE_CHAIN_REQUEST": /*To sync chain from other nodes, default: false*/
}
```

### Generate a private key, a public key and an address

From the project folder, go to folder `./utils/` and run command

```
node keygen.js
```

### Run the node

```
node .
```

### Interact with the node through JSON API

Change ENABLE_API to true
