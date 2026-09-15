// Drives the page's chain layer against a local Anvil, without a browser.
//
//   forge build                                   # the script deploys from out/
//   anvil                                         # in another terminal
//   npm install && node tools/verify-frontend.mjs
//
// It deploys fresh contracts every run (so it can be re-run against a
// long-lived Anvil), pulls the ABI and the EIP-712 `types` object out of
// web/index.html so the exact strings the browser uses are what is under
// test, and then drives the contracts directly through ethers 6.13.2 - the
// same pinned version the page loads from the CDN.
//
// Behavioural rules (quorum, replay, revocation) are forge's job. This only
// checks that the JavaScript side agrees with the Solidity side.
import { readFileSync } from "node:fs";
import {
  JsonRpcProvider, HDNodeWallet, ContractFactory, Contract, Interface, TypedDataEncoder,
  ZeroAddress, id
} from "ethers";

const read = (rel) => readFileSync(new URL(rel, import.meta.url), "utf8");
const page = read("../web/index.html");
const fromPage = (re) => new Function("return " + page.match(re)[1])();
const ABI = fromPage(/const ABI = (\[[\s\S]*?\]);/);
const ACCESS_ABI = fromPage(/const ACCESS_ABI = (\[[\s\S]*?\]);/);
const types = fromPage(/const types = (\{[\s\S]*?\});/);
const [, name, version] = page.match(/name: "([^"]+)",\s*version: "([^"]+)"/);
const artifact = JSON.parse(read("../out/ArtifactRegistry.sol/ArtifactRegistry.json"));
const accessArtifact = JSON.parse(read("../out/AccessRegistry.sol/AccessRegistry.json"));

let failures = 0;
const ok = (label, cond, extra = "") => {
  console.log(`${cond ? "  PASS" : "  FAIL"}  ${label}${extra && "  " + extra}`);
  if (!cond) failures++;
};

// Same as the page's chainBackend.send: a write that reverts surfaces from gas
// estimation, which has no ABI, so decode e.data with the contract's Interface.
const send = (promise) =>
  promise.then((tx) => tx.wait()).catch((e) => {
    throw e.data ? registry.interface.makeError(e.data, e.transaction) : e;
  });
const failsWith = (promise) => promise.then(() => null, (e) => e.revert && e.revert.name);

// Anvil's default accounts come from a well-known mnemonic.
const provider = new JsonRpcProvider("http://127.0.0.1:8545");
const root = HDNodeWallet.fromPhrase(
  "test test test test test test test test test test test junk", "", "m/44'/60'/0'/0"
);
const [owner, build, qa, sec, relayer] = [0, 1, 2, 3, 4].map((i) => root.deriveChild(i).connect(provider));
const reviewers = [[build, "BUILD"], [qa, "QA"], [sec, "SECURITY"]];
const roleHash = (r) => id(r); // keccak256 of the UTF-8 name, as the page does

console.log("1. deploy both contracts from out/ and prove the page's ABI against the compiled one");
const access = await new ContractFactory(accessArtifact.abi, accessArtifact.bytecode.object, owner).deploy();
await access.waitForDeployment();
const full = await new ContractFactory(artifact.abi, artifact.bytecode.object, owner)
  .deploy(3, await access.getAddress());
await full.waitForDeployment();
const registry = new Contract(await full.getAddress(), ABI, owner); // the page's view of it
const compiled = new Interface(artifact.abi).format(true);
const declared = new Interface(ABI).format(true);
ok("every page ABI fragment exists in the compiled ABI", declared.every((f) => compiled.includes(f)));
ok("page declares every contract error",
  compiled.filter((f) => f.startsWith("error ")).every((f) => declared.includes(f)));
ok("page's access ABI fragments exist in the compiled AccessRegistry ABI",
  new Interface(ACCESS_ABI).format(true).every((f) => new Interface(accessArtifact.abi).format(true).includes(f)));
ok("page's EIP-712 types hash to ATTESTATION_TYPEHASH",
  id(TypedDataEncoder.from(types).encodeType("Attestation")) === await full.ATTESTATION_TYPEHASH());

console.log("2. grant roles on the access contract, register a build, read it back");
for (const [w, r] of reviewers) await (await access.setRole(w.address, roleHash(r), true)).wait();
const pageAccess = new Contract(await registry.access(), ACCESS_ABI, owner); // as the page finds it
ok("page reaches the access contract through registry.access()",
  (await pageAccess.holdsRole(qa.address, roleHash("QA"))) === true);
const DIGEST = id("gateway-2.6.0.bin");
ok("unknown digest reads as ZeroAddress publisher",
  (await registry.verify(DIGEST)).record.publisher === ZeroAddress);
await send(registry.register(DIGEST, "gateway 2.6.0"));
const { record } = await registry.verify(DIGEST);
ok("verify() decodes as a named tuple", record.version === "gateway 2.6.0" && record.publisher === owner.address);
const logs = await registry.queryFilter(registry.filters.Registered());
ok("ledger rebuilt from Registered logs", logs.some((l) => l.args.digest === DIGEST));

console.log("3. sign with the page's own `types` - off chain, no gas");
const domain = {
  name, version, chainId: (await provider.getNetwork()).chainId, verifyingContract: await registry.getAddress()
};
const deadline = Math.floor(Date.now() / 1000) + 7 * 86400;
const before = await Promise.all(reviewers.map(([w]) => provider.getBalance(w.address)));
const queued = [];
for (const [w, r] of reviewers) {
  const value = { digest: DIGEST, role: roleHash(r), signer: w.address, deadline };
  queued.push({ ...value, signature: await w.signTypedData(domain, types, value) });
}
const after = await Promise.all(reviewers.map(([w]) => provider.getBalance(w.address)));
ok("no reviewer spent anything", before.every((b, i) => b === after[i]));

console.log("4. relay all three in one transaction from a fourth account");
await send(registry.connect(relayer).attestBatch(
  queued.map((q) => [q.digest, q.role, q.signer, q.deadline]), queued.map((q) => q.signature)));
ok("recorded against the signers, not the relayer",
  (await registry.signedBy(DIGEST, roleHash("QA"))) === qa.address);
ok("released", (await registry.verify(DIGEST)).released === true);

console.log("5. revoke, and read the reason back from the log");
await send(registry.revoke(DIGEST, "bootloader watchdog fault"));
const [revokedLog] = await registry.queryFilter(registry.filters.Revoked(DIGEST));
ok("reason recovered from Revoked log", revokedLog.args.reason === "bootloader watchdog fault");
ok("revocation dominates quorum", (await registry.verify(DIGEST)).released === false);

console.log("6. custom errors decode by name on both paths");
ok("write path: AlreadyRegistered",
  (await failsWith(send(registry.register(DIGEST, "again")))) === "AlreadyRegistered");
ok("read path: NotTheOriginalPublisher",
  (await failsWith(registry.connect(qa).revoke.staticCall(DIGEST, "not mine"))) === "NotTheOriginalPublisher");

console.log(failures ? `\n${failures} FAILED` : "\nall frontend chain-layer checks passed");
process.exitCode = failures ? 1 : 0;
