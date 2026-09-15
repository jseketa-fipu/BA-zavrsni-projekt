// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ArtifactRegistry} from "../src/ArtifactRegistry.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Tests for ArtifactRegistry, written in Solidity and run by Foundry.
///
/// @dev Foundry gives tests "cheatcodes" through `vm`:
///        vm.addr(pk)          - the address that belongs to a private key
///        vm.sign(pk, hash)    - sign a hash with a private key, like a wallet
///        vm.prank(addr)       - the NEXT call is sent from `addr`
///        vm.warp(ts)          - set the block timestamp
///        vm.expectRevert(sel) - the NEXT call must fail with this error
///        vm.assume(cond)      - in a fuzz test, skip inputs where cond is false
///
///      "NEXT call" means the next call to any contract - including a small
///      read hidden inside an argument. Calls to `vm` itself do not count.
///      That is why the helpers below never call the registry: an earlier
///      version read a constant from the contract inside `_sign`, and
///      `vm.prank(relayer); registry.attest(a, _sign(...))` used up the prank
///      on that read, so attest was actually sent by the owner.
contract ArtifactRegistryTest is Test {
    ArtifactRegistry registry;

    address vendor = address(0xA11CE);
    address stranger = address(0xB0B);
    address relayer = address(0xFEE);

    // Reviewer private keys. Any small number works as a test key; the
    // matching addresses come from vm.addr(pk).
    uint256 buildPk = 0xB01;
    uint256 qaPk = 0xB02;
    uint256 secPk = 0xB03;

    // Stands in for a file's SHA-256. The contract just stores 32 bytes.
    bytes32 constant DIGEST = keccak256("firmware-v1.2.3.bin");

    // The EIP-712 strings a wallet uses, written out here as literals rather
    // than read from the contract - see `_hash` for why.
    string constant ATTESTATION_TYPE =
        "Attestation(bytes32 digest,bytes32 role,address signer,uint256 deadline)";
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function setUp() public {
        // This test contract deploys the registry, so it is the owner.
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
        // Fields in order: digest, role, signer, deadline.
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

    /// @dev Compute the hash a wallet would sign, from our own literals - not
    ///      from the contract. If we read the contract's constants back, a typo
    ///      in them would go unnoticed: the test would sign with the same wrong
    ///      value and pass, while real MetaMask signatures would be rejected.
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
        return abi.encodePacked(r, s, v); // the 65-byte order wallets use
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

    /// @dev The contract's constants must equal what a wallet computes.
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
        assertEq(rec.publisher, address(0)); // zero address = never registered
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

    /// @dev The signature says who signed; who sent the transaction is irrelevant.
    function test_relayerCannotForgeIdentity() public {
        _attestAs(qaPk, registry.ROLE_QA());

        // Recorded under the signer, even though `relayer` sent it.
        assertEq(registry.signedBy(DIGEST, registry.ROLE_QA()), vm.addr(qaPk));
    }

    function test_signatureFromWrongKeyIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_SECURITY(), secPk);
        vm.expectRevert(ArtifactRegistry.BadSignature.selector);
        registry.attest(a, _sign(qaPk, a)); // QA key signing a security sign-off
    }

    function test_signerWithoutRoleIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), 0xDEAD);

        // A valid signature from someone who does not hold the role.
        vm.expectRevert(ArtifactRegistry.RoleNotHeld.selector);
        registry.attest(a, _sign(0xDEAD, a));
    }

    /// @dev No nonce needed: each (digest, role) can be signed once, so
    ///      sending the same signature twice fails.
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

    /// @dev A signature for one deployment is useless on another, because the
    ///      contract address is part of what gets signed (EIP-712 domain).
    function test_signatureDoesNotCarryToAnotherDeployment() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), qaPk);
        bytes memory sig = _sign(qaPk, a); // made for `registry`

        ArtifactRegistry twin = new ArtifactRegistry(3);
        twin.setRole(vm.addr(qaPk), twin.ROLE_QA(), true);
        twin.register(DIGEST, "1.2.3");

        vm.expectRevert(ArtifactRegistry.BadSignature.selector);
        twin.attest(a, sig);
    }

    /// @dev Take a valid signature and turn it into its "mirror twin":
    ///      s -> (order - s), v flipped 27<->28. It recovers to the same
    ///      signer, and it must still be rejected - OpenZeppelin's ECDSA does
    ///      that, with its own error (which carries `s`, hence expectPartialRevert).
    function test_malleableSignatureIsRejected() public {
        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_BUILD(), buildPk);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buildPk, _hash(a));

        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141; // curve order
        bytes memory flipped =
            abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));

        vm.expectPartialRevert(ECDSA.ECDSAInvalidSignatureS.selector);
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

        // Three reviewers, one transaction, sent by someone else.
        vm.prank(relayer);
        registry.attestBatch(list, sigs);

        assertTrue(_released(DIGEST));
    }

    /// @dev Losing a role does not undo signatures already given.
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

        assertFalse(_released(DIGEST)); // revoked wins over quorum
    }

    function test_revokedBuildCannotCollectMoreSignOffs() public {
        vm.prank(vendor);
        registry.revoke(DIGEST, "withdrawn");

        ArtifactRegistry.Attestation memory a = _attestation(registry.ROLE_QA(), qaPk);
        vm.expectRevert(ArtifactRegistry.ArtifactRevoked.selector);
        registry.attest(a, _sign(qaPk, a));
    }

    function test_onlyOriginalPublisherRevokes() public {
        registry.setPublisher(stranger, true); // a publisher, but not this build's
        vm.prank(stranger);
        vm.expectRevert(ArtifactRegistry.NotTheOriginalPublisher.selector);
        registry.revoke(DIGEST, "not mine");
    }

    // --------------------------------------------------------------- fuzz

    /// @dev Foundry runs this 256 times with random digests.
    function testFuzz_anyDigestRoundTrips(bytes32 digest) public {
        vm.assume(digest != DIGEST);

        vm.prank(vendor);
        registry.register(digest, "fuzz");

        (ArtifactRegistry.Artifact memory rec,) = registry.verify(digest);
        assertEq(rec.publisher, vendor);
    }
}
