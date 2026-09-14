// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ArtifactRegistry} from "../src/ArtifactRegistry.sol";

/// @notice Tests for ArtifactRegistry.
///
/// @dev Foundry writes tests in Solidity, which is why signing can be exercised
///      at all: `vm.sign` produces a real secp256k1 signature from a private
///      key, so the EIP-712 path is tested end to end rather than mocked.
///
///      The cheatcodes used below:
///        vm.addr(pk)          - the address belonging to a private key
///        vm.sign(pk, hash)    - sign a hash, returning (v, r, s)
///        vm.prank(addr)       - make msg.sender be `addr` for the NEXT call
///        vm.warp(ts)          - move block.timestamp
///        vm.expectRevert(sel) - require that the NEXT call reverts with `sel`
///        vm.assume(cond)      - in a fuzz test, discard inputs failing `cond`
///
///      "NEXT call" is literal for prank and expectRevert alike: it means the
///      next external call of any kind, including a view call hidden inside an
///      argument expression. Calls to `vm` itself do not count. That is why
///      the helpers below never touch the registry - an earlier version read
///      the typehash from the contract inside `_sign`, and every
///      `vm.prank(relayer); registry.attest(a, _sign(...))` silently spent its
///      prank on that read and ran attest as the owner instead.
contract ArtifactRegistryTest is Test {
    ArtifactRegistry registry;

    address vendor = address(0xA11CE);
    address stranger = address(0xB0B);
    address relayer = address(0xFEE);

    // Reviewer keys. Any non-zero number below the curve order works as a
    // private key; these are deliberately tiny so they are easy to read. The
    // matching addresses come from vm.addr(pk) wherever one is needed.
    uint256 buildPk = 0xB01;
    uint256 qaPk = 0xB02;
    uint256 secPk = 0xB03;

    // Stands in for the SHA-256 of a build. The contract never hashes anything
    // itself - it stores whatever 32 bytes it is given - so keccak is fine here.
    bytes32 constant DIGEST = keccak256("firmware-v1.2.3.bin");

    // The EIP-712 strings a wallet works from, written out as literals rather
    // than read back from the contract - see `_hash` for why that matters.
    string constant ATTESTATION_TYPE =
        "Attestation(bytes32 digest,bytes32 role,address signer,uint256 deadline)";
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() public {
        // The test contract itself deploys, so it is `owner` and every
        // unpranked call below arrives as the owner.
        registry = new ArtifactRegistry(3);
        registry.setPublisher(vendor, true);
        registry.setRole(vm.addr(buildPk), registry.ROLE_BUILD(), true);
        registry.setRole(vm.addr(qaPk), registry.ROLE_QA(), true);
        registry.setRole(vm.addr(secPk), registry.ROLE_SECURITY(), true);

        vm.prank(vendor);
        registry.register(DIGEST, "1.2.3");
    }

    // ------------------------------------------------------------- helpers

    function _attestation(bytes32 role, uint256 pk)
        internal
        view
        returns (ArtifactRegistry.Attestation memory)
    {
        // Fields in declaration order: digest, role, signer, deadline.
        return ArtifactRegistry.Attestation(DIGEST, role, vm.addr(pk), block.timestamp + 1 days);
    }

    function _domain() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("ArtifactRegistry"),
                keccak256("1"),
                block.chainid,
                address(registry)
            )
        );
    }

    /// @dev Rebuilds the EIP-712 digest the way a wallet would: from the type
    ///      string and domain LITERALS above, never from the contract under
    ///      test. If this helper read `registry.ATTESTATION_TYPEHASH()` back,
    ///      a typo in that constant would cancel itself out and every test
    ///      would still pass while MetaMask produced signatures the contract
    ///      rejects. Both sides computing the same hash from the same rules is
    ///      the thing actually being tested.
    function _hash(ArtifactRegistry.Attestation memory a) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(keccak256(bytes(ATTESTATION_TYPE)), a));
        return keccak256(abi.encodePacked("\x19\x01", _domain(), structHash));
    }

    function _sign(uint256 pk, ArtifactRegistry.Attestation memory a)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _hash(a));
        return abi.encodePacked(r, s, v); // the order wallets use
    }

    function _attestAs(uint256 pk, bytes32 role) internal {
        ArtifactRegistry.Attestation memory a = _attestation(role, pk);
        vm.prank(relayer);
        registry.attest(a, _sign(pk, a));
    }

    function _released(bytes32 digest) internal view returns (bool released) {
        (, released) = registry.verify(digest);
    }

    // ------------------------------------------------------------ registry

    /// @dev The two constants a wallet computes on its own, checked by name.
    function test_contractConstantsMatchTheWalletSide() public view {
        assertEq(registry.ATTESTATION_TYPEHASH(), keccak256(bytes(ATTESTATION_TYPE)));
        assertEq(registry.domainSeparator(), _domain());
    }

    function test_registeredButNotYetReleased() public view {
        (ArtifactRegistry.Artifact memory rec, bool released) = registry.verify(DIGEST);
        assertEq(rec.publisher, vendor);
        assertEq(rec.version, "1.2.3");
        assertEq(rec.signOffs, 0);
        assertFalse(released);
    }

    function test_unknownDigestReadsAsEmpty() public view {
        (ArtifactRegistry.Artifact memory rec, bool released) = registry.verify(keccak256("nope"));
        assertEq(rec.publisher, address(0)); // the sentinel for "never seen"
        assertFalse(released);
    }

    function test_digestCannotBeReclaimed() public {
        vm.prank(vendor);
        vm.expectRevert(ArtifactRegistry.AlreadyRegistered.selector);
        registry.register(DIGEST, "1.2.4");
    }

    function test_nonPublisherCannotRegister() public {
        vm.prank(stranger);
        vm.expectRevert(ArtifactRegistry.NotPublisher.selector);
        registry.register(keccak256("other"), "9.9.9");
    }

    // --------------------------------------------------------- attestation

    function test_quorumReleasesBuild() public {
        _attestAs(buildPk, registry.ROLE_BUILD());
        _attestAs(qaPk, registry.ROLE_QA());
        assertFalse(_released(DIGEST)); // two of three is not enough

        _attestAs(secPk, registry.ROLE_SECURITY());
        assertTrue(_released(DIGEST));
    }

    /// @dev The signature decides who attested, not who paid for the gas.
    function test_relayerCannotForgeIdentity() public {
        _attestAs(qaPk, registry.ROLE_QA());

        // Recorded against the signer, even though `relayer` sent the tx.
        assertEq(registry.signedBy(DIGEST, registry.ROLE_QA()), vm.addr(qaPk));
    }

    function test_signatureFromWrongKeyIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_SECURITY(), secPk);
        vm.expectRevert(ArtifactRegistry.BadSignature.selector);
        registry.attest(a, _sign(qaPk, a)); // QA key signing a security sign-off
    }

    function test_signerWithoutRoleIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), 0xDEAD);

        // A perfectly valid signature from someone with no standing to give it.
        vm.expectRevert(ArtifactRegistry.RoleNotHeld.selector);
        registry.attest(a, _sign(0xDEAD, a));
    }

    /// @dev Replay protection without a nonce: the (digest, role) slot is filled
    ///      once and never cleared, so resubmitting the same bytes reverts.
    function test_sameSignatureCannotBeReplayed() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_BUILD(), buildPk);
        bytes memory sig = _sign(buildPk, a);
        registry.attest(a, sig);

        vm.expectRevert(ArtifactRegistry.RoleAlreadySigned.selector);
        registry.attest(a, sig);
    }

    function test_expiredSignatureIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), qaPk);
        vm.warp(a.deadline + 1);

        vm.expectRevert(ArtifactRegistry.SignatureExpired.selector);
        registry.attest(a, _sign(qaPk, a));
    }

    /// @dev A signature valid on one deployment must not work on another, even
    ///      with identical contents. This is what `verifyingContract` in the
    ///      EIP-712 domain buys, and it is the same mechanism that stops a
    ///      testnet signature being replayed on mainnet.
    function test_signatureDoesNotCarryToAnotherDeployment() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), qaPk);
        bytes memory sig = _sign(qaPk, a); // bound to `registry` via _domain()

        ArtifactRegistry twin = new ArtifactRegistry(3);
        twin.setRole(vm.addr(qaPk), twin.ROLE_QA(), true);
        twin.register(DIGEST, "1.2.3");

        vm.expectRevert(ArtifactRegistry.BadSignature.selector);
        twin.attest(a, sig);
    }

    /// @dev Take a valid signature and flip it to its mirror image: s becomes
    ///      (order - s) and v flips 27<->28. Raw `ecrecover` would accept this
    ///      as a second valid signature from the same signer.
    function test_malleableSignatureIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_BUILD(), buildPk);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buildPk, _hash(a));

        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // curve order
        bytes memory flipped =
            abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));

        vm.expectRevert(ArtifactRegistry.MalleableSignature.selector);
        registry.attest(a, flipped);
    }

    function test_batchRelaysEverySignOff() public {
        ArtifactRegistry.Attestation[] memory list = new ArtifactRegistry.Attestation[](3);
        bytes[] memory sigs = new bytes[](3);

        list[0] = _attestation(registry.ROLE_BUILD(), buildPk);
        list[1] = _attestation(registry.ROLE_QA(), qaPk);
        list[2] = _attestation(registry.ROLE_SECURITY(), secPk);
        sigs[0] = _sign(buildPk, list[0]);
        sigs[1] = _sign(qaPk, list[1]);
        sigs[2] = _sign(secPk, list[2]);

        // Three reviewers released a build in one transaction, none of them
        // holding any ether. This is the whole design in four lines.
        vm.prank(relayer);
        registry.attestBatch(list, sigs);

        assertTrue(_released(DIGEST));
    }

    /// @dev Losing a role does not retract sign-offs already given.
    function test_pastSignOffSurvivesLosingTheRole() public {
        _attestAs(buildPk, registry.ROLE_BUILD());
        registry.setRole(vm.addr(buildPk), registry.ROLE_BUILD(), false);

        assertEq(registry.signedBy(DIGEST, registry.ROLE_BUILD()), vm.addr(buildPk));
    }

    // -------------------------------------------------------------- revoke

    function test_revokedBuildIsNotReleasedEvenAtQuorum() public {
        _attestAs(buildPk, registry.ROLE_BUILD());
        _attestAs(qaPk, registry.ROLE_QA());
        _attestAs(secPk, registry.ROLE_SECURITY());
        assertTrue(_released(DIGEST));

        vm.prank(vendor);
        registry.revoke(DIGEST, "bootloader watchdog fault");

        assertFalse(_released(DIGEST)); // revocation dominates quorum
    }

    function test_revokedBuildCannotCollectMoreSignOffs() public {
        vm.prank(vendor);
        registry.revoke(DIGEST, "withdrawn");

        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), qaPk);
        vm.expectRevert(ArtifactRegistry.ArtifactRevoked.selector);
        registry.attest(a, _sign(qaPk, a));
    }

    function test_onlyOriginalPublisherRevokes() public {
        registry.setPublisher(stranger, true); // a publisher, just not this one
        vm.prank(stranger);
        vm.expectRevert(ArtifactRegistry.NotTheOriginalPublisher.selector);
        registry.revoke(DIGEST, "not mine");
    }

    // --------------------------------------------------------------- fuzz

    /// @dev Foundry calls this 256 times with random bytes32 values. Fuzzing is
    ///      cheap insurance against the case you did not think to write down.
    function testFuzz_anyDigestRoundTrips(bytes32 digest) public {
        vm.assume(digest != DIGEST);

        vm.prank(vendor);
        registry.register(digest, "fuzz");

        (ArtifactRegistry.Artifact memory rec,) = registry.verify(digest);
        assertEq(rec.publisher, vendor);
    }
}
