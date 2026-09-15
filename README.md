# ArtifactRegistry

A release ledger for software builds on Ethereum. A build is recorded by its
SHA-256 digest and counts as **released** only once three roles — build
server, QA, security review — have signed it. Reviewers sign in their wallet
for free (EIP-712); one transaction submits all signatures. Anyone can verify
a build with a free read.

## Files

```
src/ArtifactRegistry.sol      the contract (the only thing deployed)
script/Deploy.s.sol           deploys it and grants the roles
lib/openzeppelin-contracts    OpenZeppelin v5.7 (EIP712, ECDSA)
test/ArtifactRegistry.t.sol   19 Foundry tests
web/index.html                the frontend, one file (demo mode + MetaMask)
tools/verify-frontend.mjs     optional: checks the page's ABI against the contract
lib/forge-std                 Foundry test library (git submodule)
```

## Run

```bash
forge test                                   # 1. tests

anvil                                        # 2. local chain (keep running)
forge create src/ArtifactRegistry.sol:ArtifactRegistry \
  --rpc-url http://127.0.0.1:8545 --broadcast --constructor-args 3 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
#   -> 0x5FbDB2315678afecb367f032d93F642f64180aa3

cd web && python -m http.server 8000         # 3. open http://localhost:8000/?registry=0x5FbD...0aa3
```

Click **Connect wallet**; the page asks MetaMask to switch to the Anvil chain
(31337). Grant roles to your accounts with `cast send <registry>
"setRole(address,bytes32,bool)" <account> $(cast keccak QA) true ...`.
Without a wallet the page runs in demo mode.

Optional: `forge build && npm install && node tools/verify-frontend.mjs`
(with anvil running).

## Design notes

- **No nonce in the signed message** — each (build, role) can be signed once.
- **OpenZeppelin `EIP712` + `ECDSA`** build the domain hash and recover the
  signer; the role, quorum and replay rules are in the contract itself.
- **Quorum is fixed at deployment** — it cannot be lowered later.
- **Revoked wins** — a withdrawn build is never released.

Weak points: the owner is a single key (use a multisig in production); the
page loads ethers.js from a CDN.
