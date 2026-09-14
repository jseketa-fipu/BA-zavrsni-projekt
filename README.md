# ArtifactRegistry

A release ledger for build artifacts on Ethereum. A build is filed under the
SHA-256 of its bytes and counts as **released** only once three independent
roles — build server, QA, security review — have signed off on it. Sign-offs
are EIP-712 signatures made off-chain (no gas, no funded account); a relayer
submits them in one transaction. Anyone can verify a build with a free view
call.

## Layout

```
src/ArtifactRegistry.sol      the contract — the only thing deployed
test/ArtifactRegistry.t.sol   19 Foundry tests, incl. real EIP-712 signing
web/index.html                the whole frontend in one file (demo mode + MetaMask)
tools/verify-frontend.mjs     Node script: proves the page's ABI/EIP-712 strings
                              against the compiled contract on a local chain
lib/forge-std                 Foundry's test library (git submodule, tests only)
```

Generated, ignored by git: `out/`, `cache/`, `node_modules/`.

## Run it

```bash
export PATH="$PATH:$HOME/.foundry/bin"     # Git Bash only; PowerShell finds forge

forge test                                  # 1. the contract

anvil                                       # 2. a local chain, leave it running
forge create src/ArtifactRegistry.sol:ArtifactRegistry \
  --rpc-url http://127.0.0.1:8545 --broadcast --constructor-args 3 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
#   -> Deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3   (always, on a fresh Anvil)

cd web && python -m http.server 8000        # 3. the page, at http://localhost:8000
```

In MetaMask: add a network with RPC `http://127.0.0.1:8545`, chain ID `31337`;
import a couple of Anvil's printed private keys as the reviewer accounts. Click
**Connect wallet** and paste the deployed address. Without a wallet the page
runs in demo mode against a seeded in-memory ledger.

Optional, proves the JS side agrees with the Solidity side:

```bash
forge build && npm install && node tools/verify-frontend.mjs   # with anvil running
```

## Design decisions worth defending

- **No nonce in the signed message.** The `(digest, role)` slot is written once
  and never cleared, so it is the replay guard. Cross-chain and
  cross-deployment replay is stopped by the EIP-712 domain.
- **Hand-rolled ECDSA recovery** with the same checks OpenZeppelin's
  `ECDSA.recover` makes (length, high-`s`, zero address), written out so each
  can be explained.
- **Immutable quorum.** A settable one would retroactively change what
  "released" means for builds already signed.
- **Events, not an on-chain array**, for the ledger listing — ~29k gas cheaper
  per registration; the page rebuilds the list from `Registered` logs.
- **Revocation dominates quorum.** A withdrawn build is never released.

Known weak points: the owner is a single key that grants every role (a multisig
would fix it, with no code change), and `attestBatch` is an unbounded loop.
