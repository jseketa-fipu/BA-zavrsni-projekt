# Presentation — ArtifactRegistry

About 10 minutes. The demo is the main part.

---

## 1. The problem (1 min)

When you download a firmware image or an installer, two questions matter:

- Is this file *exactly* what was released, byte for byte?
- Who approved releasing it?

Today the answer is usually "a download page says so", or one team holds one
signing key. One compromised key or one careless person is enough to ship a
bad build.

## 2. The goal (1 min)

A public record where a build counts as **released** only after three
independent parties have approved it — the build server, QA, and security
review — and where **none of them can fake the others' approval**.

Why a blockchain and not a database? A database has an admin, and the admin
can write any row, including someone else's approval. On a blockchain an
approval is a digital signature, and nobody can make one without that
team's private key. The rules (three signatures, no overwriting, revocation
is permanent) are enforced by the contract, not by whoever runs the server.

## 3. What is EIP-712? (1 min)

EIP-712 is the Ethereum standard for **signing structured data**.

- Without it, a wallet asks you to sign a meaningless hex string.
- With it, the wallet shows readable fields — *digest, role, signer,
  deadline* — and signs exactly those.

Signing is **not** a transaction: no gas, no ETH needed, nothing is sent to
the chain. The signature is just 65 bytes. Later, one person collects the
signatures and submits them all in a single transaction. The contract
recomputes the same hash and recovers the signer's address from the
signature (`ecrecover`) — if it matches a reviewer with that role, the
approval counts.

Included in what is signed: the contract's address and the chain ID, so a
signature made for one deployment or one network is useless on any other.

## 4. How it works (1 min)

```
 file ──sha256──▶ digest ──register()──▶ record on chain
                                          │
  build ┐                                 │
  QA    ├── sign in MetaMask (free) ──▶ one person submits all ──▶ 3 of 3 = RELEASED
  sec   ┘                                                          │
                                        anyone ──verify()──▶ free read
```

Two contracts: **AccessRegistry** (who may publish, who holds which role)
and **ArtifactRegistry** (the ledger), which calls the first one whenever it
needs a permission. Reviewers can change without touching the ledger.

- **Register**: the publisher records the SHA-256 of the build. One paid
  transaction.
- **Sign**: each role signs in their wallet. Free.
- **Submit**: one transaction carries all three signatures.
- **Verify**: anyone can check a file — no wallet, no gas.

## 5. Demo (4 min)

Before: `anvil` running, contract deployed, roles granted, page served,
MetaMask on chain 31337.

| Do | Say |
|---|---|
| `forge test` — 21 tests pass | "Tests sign with real keys, nothing is mocked." |
| Drop a file → **Not in the registry** | "Hashed locally. Only the 32-byte digest goes to the chain." |
| Register (MetaMask confirm) | "That is the one paid write." |
| Sign as Build, QA, Security (MetaMask *Sign*, not *Confirm*) | "No transaction happened — look, the balance is unchanged." |
| Submit (one MetaMask confirm) → **Cleared for release** | "Three approvals, one transaction." |
| Revoke → **Published, then withdrawn** | "The record stays. A revoked build is never released." |
| Drop the same file again | "Instant, and free." |

If the chain misbehaves: reload without connecting — demo mode shows the same
screens from an in-memory ledger. Say so honestly.

## 6. Two honest weak points (30 s)

- The contract owner is one key that hands out all roles. In production the
  owner would be a multisig wallet.
- The page loads ethers.js from the internet. A local copy fixes it.

## 7. Likely questions

| Question | Answer |
|---|---|
| Why SHA-256, not keccak? | It's built into the browser, and anyone can check it with `sha256sum`. |
| Can the person submitting cheat? | No — the contract ignores who sent the transaction and only trusts the signatures. |
| Why no nonce in the signed message? | Each (build, role) can be signed only once, so a signature cannot be replayed. |
| What does OpenZeppelin do here? | `EIP712` builds the domain hash; `ECDSA.recover` checks the signature's length, rejects its mirror-twin form and the zero address, and returns the signer. Roles, quorum and replay rules are mine. |
| Can a revoked build come back? | No. Fix it, and the new file gets a new digest. |
| Gas cost? | ~64k for one signature, ~137k for a batch of three. |
| Why two contracts? | Permissions and data are different concerns. The ledger asks `AccessRegistry` "does X hold role R?" via an external call; swap or extend the access rules without redeploying the ledger. |

## 8. Close

"Reading is free, writing is rare, and no single party can approve a release
alone. Two contracts, about 150 lines of Solidity on top of OpenZeppelin, 21 tests."
