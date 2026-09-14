# Presentation outline — ArtifactRegistry

Assumes ~12 minutes talking + questions. Times are targets; the demo is the
part to protect.

---

## 1. The problem — 1 min

- A firmware image / package / container is just bytes. The question anyone
  installing it asks: **is this exactly what was released, and who agreed to
  release it?**
- Today that is answered by a download page and a signing key held by one
  team. One compromised key, or one person, is enough.

**Say:** "I wanted release approval to require three *separate* parties, where
none of them can fake the others."

## 2. Why a chain and not a database — 1 min

- Three roles: build server, QA, security review — imagined as different teams
  or companies.
- A shared database is owned by *someone*. That someone can write any row,
  including the other two approvals.
- On chain, an approval is a **signature over the exact digest**. Nobody — not
  the publisher, not the contract owner, not the relayer — can produce one
  without the key.

This is the slide that kills "why not Postgres?". Spend the minute here, not
later.

## 3. The design in one diagram — 2 min

```
 file ──sha256──▶ digest ──register()──▶ ledger entry
                                          │
      build ┐                             │
      QA    ├── sign EIP-712 (off-chain, free) ──▶ relayer ──attestBatch()──▶ 3 of 3 → RELEASED
      sec   ┘                                                                  │
                                                       anyone ──verify()──▶ free view call
```

Three sentences, one per arrow group:

1. **Register** — a publisher files a build under its SHA-256. Records are
   never overwritten, only revoked.
2. **Attest** — each role signs a typed message in their wallet. No
   transaction, no gas, no funded account. One relayer submits all signatures
   in one transaction.
3. **Verify** — a `view` call. No wallet, no gas. Reading is free; writing is
   rare and paid for.

**Say:** "That asymmetry is the whole design. Reviewers pay nothing, the
public pays nothing, one relayer pays once."

## 4. Live demo — 4 min

**Pre-flight (before you walk in):**

- `anvil` running
- contract deployed: `forge create src/ArtifactRegistry.sol:ArtifactRegistry --rpc-url http://127.0.0.1:8545 --broadcast --constructor-args 3 --private-key <anvil key 0>` → `0x5FbDB2315678afecb367f032d93F642f64180aa3`
- roles granted to three Anvil accounts (`setRole`), via `cast send` or the tools script
- `python -m http.server 8000` running in `web/`
- MetaMask on chain 31337 with those three Anvil keys imported
- a small file on the desktop to drop

| Step | What they see | What to say |
|---|---|---|
| `forge test` | 19 passed in a few ms | "Tests sign with real keys — the EIP-712 path isn't mocked." |
| Drop the file | digest painted, **Not in the registry** | "Hashed locally. Only 32 bytes ever go to the chain." |
| Register | MetaMask tx → **Awaiting sign-off, 0 of 3** | "That was the one paid write." |
| Switch account, sign as Build | chip → *signed, not yet submitted*; tray shows 1 | "No transaction happened. Look at the balance." ← show it |
| Sign as QA, then Security | tray shows 3 | |
| Submit | one MetaMask tx → **Cleared for release**, 3 of 3 | "Three approvals, one transaction, paid by whoever pressed the button." |
| Revoke | **Published, then withdrawn** | "Revocation dominates quorum. The record stays." |
| Drop the same file again | verdict comes back instantly | "That lookup cost nothing — no wallet involved." |

**Fallback:** if the chain or MetaMask misbehaves, reload the page without
connecting — demo mode shows the same three states from a seeded ledger. Say
so plainly: "this is the in-memory stub; the chain is what makes it
persistent."

## 5. Inside the contract — 2 min

Pick three things and show the actual lines:

- **Storage packing** (`struct Artifact`): `address + uint64 + bool + uint8 =
  240 bits` → one slot. Reorder it and registration costs 20k more gas.
- **`attest()` check ordering**: cheap checks first, `ecrecover` (3000 gas)
  last. "A caller who fails pays less; the happy path costs nothing extra."
- **`_recover()`**: the ways bare `ecrecover` misleads you — length, the
  high-`s` mirror signature, and `address(0)` on garbage. "OpenZeppelin does
  the same checks; I wrote them out so I can point at them."

## 6. Decisions to defend — 1 min, then let them ask

State each in one breath; details are in the code comments if pushed.

- **No nonce.** The `(digest, role)` slot is written once and never cleared —
  that *is* the replay guard. A nonce would cost a storage write and force
  signing order.
- **Cross-chain / cross-deployment replay** is stopped by `chainId` +
  `verifyingContract` in the EIP-712 domain. A test fires a signature at a
  second deployment and watches it fail.
- **Quorum is immutable.** A settable one would retroactively release every
  half-approved build in history.
- **Events, not an array**, for the listing. ~29k gas cheaper per
  registration; the frontend rebuilds the ledger from `Registered` logs.
- **Losing a role doesn't retract past sign-offs.** A signed document stays
  signed when the signer leaves.

## 7. Weak points — 30 s, say them first

- **Owner is one key** that grants every role. A multisig fixes it with no
  code change.
- **`attestBatch` is unbounded** — a huge batch hits the block gas limit
  (nothing lost, resubmit smaller).
- **Frontend pulls ethers from a CDN** — needs network; a local copy is a
  one-line change.
- **Demo mode isn't persistence.** The chain is.

Naming these yourself is worth more than having them found.

## 8. Questions to expect

| Question | Answer |
|---|---|
| Why SHA-256 and not keccak? | The browser has it built in, and the examiner can reproduce the key with `sha256sum`. |
| What stops the relayer from lying? | Nothing it sends is trusted — the signature decides who attested. `msg.sender` is never consulted in `attest`. |
| Why hand-roll ECDSA instead of OpenZeppelin? | Same checks, same constant. Written out to be explainable; swapping in the library is two lines. |
| What's `0x1901`? | EIP-191 prefix: makes the signed bytes impossible to confuse with a transaction, so a sign-off can't be replayed as one that moves funds. |
| Can a revoked build be re-released? | No. One-way by design; a fixed build gets a new digest. |
| What did the tests catch? | Honest answer: a Foundry footgun — `vm.prank` binds to the *next call*, and a helper's view call was eating it, so the relayer tests ran as the owner. Fixed by hashing from literals in the test; mutation-tested afterwards. |
| Gas per attestation? | ~64k for one, ~137k for a batch of three — batching amortises the base cost. |
| Where's the version string stored? | On chain, but display-only. The digest is the identity. |

## 9. Close — 20 s

"A registry where reading is free, writing is rare, and no single party can
approve a release alone. 144 lines of Solidity, no dependencies deployed,
19 tests."
