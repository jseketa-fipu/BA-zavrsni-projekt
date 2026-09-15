# Deploying to Sepolia

Everything below runs from the project folder. Steps 1-2 are one-time.

## 1. Get Sepolia ETH

The deploy plus three role grants costs roughly 0.01 ETH at typical Sepolia
gas prices. Faucets (pick any; some need a Google/GitHub login):

- https://cloud.google.com/application/web3/faucet/ethereum/sepolia
- https://www.alchemy.com/faucets/ethereum-sepolia
- https://sepolia-faucet.pk910.de

Send it to the MetaMask account you will deploy from. Check:

```bash
cast balance <your address> --ether --rpc-url sepolia
```

## 2. Put your key in a Foundry keystore

Foundry can store the private key encrypted, so it never appears on the
command line or in shell history. Export the key from MetaMask
(account menu → Account details → Show private key), then:

```bash
cast wallet import deployer --interactive
```

It prompts for the key and a password. From then on `--account deployer`
uses it (and asks for the password).

## 3. Deploy

```bash
forge script script/Deploy.s.sol --rpc-url sepolia --account deployer --broadcast
```

The script deploys `AccessRegistry`, then `ArtifactRegistry` pointing at it,
and grants the deployer all three roles (publisher rights come with deploying
the access contract). It prints:

```
AccessRegistry:   0x...
ArtifactRegistry: 0x...
publisher + all roles: 0x...
```

Keep both addresses; the page only needs the ArtifactRegistry one. The printed block number is from the simulation and may be
off by a few; the exact deployment block is in the transaction record
`broadcast/Deploy.s.sol/11155111/run-latest.json` (`receipts[0].blockNumber`,
in hex) or on the explorer page for the address.

## 4. Verify the source (so the grader can read it on the explorer)

```bash
forge verify-contract <access address> src/AccessRegistry.sol:AccessRegistry \
  --chain sepolia --verifier sourcify
forge verify-contract <registry address> src/ArtifactRegistry.sol:ArtifactRegistry \
  --chain sepolia --verifier sourcify \
  --constructor-args $(cast abi-encode "constructor(uint8,address)" 3 <access address>)
```

Sourcify needs no API key. Blockscout picks it up automatically:
https://eth-sepolia.blockscout.com/address/<address>
(Etherscan verification needs an Etherscan API key; `--verifier etherscan --etherscan-api-key <key>`.)

## 5. Use the page against Sepolia

```bash
cd web && python -m http.server 8000
```

Open, with your values filled in:

```
http://localhost:8000/?chain=11155111&registry=<address>&from=<block>
```

- `chain=11155111` makes Connect wallet switch MetaMask to Sepolia.
- `from=<block>` is the deployment block, so the page reads events from there
  instead of from block 0 (public RPCs refuse huge ranges).

Then the same flow as locally: drop a file, Register (one transaction), Sign
three times (signatures, free), Submit (one transaction), Revoke.

## 6. Extra reviewer accounts (optional)

To demo with separate accounts per role instead of one:

```bash
cast send <access address> "setRole(address,bytes32,bool)" <reviewer> $(cast keccak QA) true \
  --rpc-url sepolia --account deployer
```

Reviewers need no ETH to sign; only the account that presses Submit pays.
