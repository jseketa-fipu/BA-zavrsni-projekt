// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title  ArtifactRegistry
/// @notice A public record of software builds and who approved them.
///
///         A "build" is a file: firmware, a package, an installer. We never
///         store the file itself, only its SHA-256 fingerprint (the "digest").
///         A build counts as RELEASED once three different roles have signed
///         it: the build server, QA, and security review.
///
///         Why on a blockchain? Because the three roles are different teams.
///         With a normal database, whoever runs the database could fake the
///         other teams' approvals. Here an approval is a digital signature,
///         and nobody can produce one without that team's private key.
///
///         Who pays? Reviewers sign in their wallet for free (no transaction).
///         One person then sends all the signatures to the chain in a single
///         transaction. Checking a build is a free read. So writing is rare
///         and paid, reading is unlimited and free.
///
/// @dev Two OpenZeppelin pieces are used: `EIP712` computes the domain hash
///      that ties signatures to this contract and this chain, and
///      `ECDSA.recoverCalldata` turns a signature back into the signer's
///      address (checking its length, rejecting the "mirror twin" form of a
///      signature, and rejecting the zero address). Everything about roles,
///      quorum, replay and revocation is in this file.
contract ArtifactRegistry is EIP712 {
    // =====================================================================
    //                                TYPES
    // =====================================================================

    /// @dev One record per build. Small fields first so they fit in one
    ///      storage slot (cheaper); the string goes last because it cannot
    ///      share a slot with anything.
    struct Artifact {
        address publisher;    // who registered it; zero address = not registered
        uint64 registeredAt;  // block timestamp
        bool revoked;         // withdrawn by the publisher
        uint8 signOffs;       // how many roles have signed so far (0-3)
        string version;       // a label like "2.4.0", for display only
    }

    /// @dev The message a reviewer signs in their wallet. There is no nonce
    ///      (counter) here on purpose: every (digest, role) pair can only be
    ///      signed once - see `signedBy` - so a signature cannot be reused.
    struct Attestation {
        bytes32 digest;    // which build
        bytes32 role;      // as which role (BUILD / QA / SECURITY)
        address signer;    // who is signing
        uint256 deadline;  // signature is invalid after this time
    }

    // =====================================================================
    //                              CONSTANTS
    // =====================================================================

    // Roles are just hashes of their names.
    bytes32 public constant ROLE_BUILD = keccak256("BUILD");
    bytes32 public constant ROLE_QA = keccak256("QA");
    bytes32 public constant ROLE_SECURITY = keccak256("SECURITY");

    /// @dev EIP-712 describes the "shape" of the signed message with this
    ///      hash. The string must match what the frontend sends to MetaMask,
    ///      character for character.
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes32 digest,bytes32 role,address signer,uint256 deadline)");

    // =====================================================================
    //                                STATE
    // =====================================================================

    // `immutable` = set once in the constructor, then baked into the code.
    // Cheaper to read than normal storage.

    address public immutable owner;

    /// @notice How many roles must sign before a build counts as released.
    /// @dev Fixed at deployment. If it could be lowered later, builds that
    ///      were half-approved would suddenly become "released".
    uint8 public immutable quorum;

    /// @notice Who is allowed to register builds.
    mapping(address => bool) public isPublisher;

    /// @notice Who holds which role. account => role => yes/no
    mapping(address => mapping(bytes32 => bool)) public holdsRole;

    /// @notice Who signed which role on which build. digest => role => signer.
    ///         Zero address = not signed yet. Once set, never cleared - this is
    ///         what stops the same signature being submitted twice.
    mapping(bytes32 => mapping(bytes32 => address)) public signedBy;

    /// @dev All build records, by digest. Read through `verify()`.
    mapping(bytes32 => Artifact) private _artifacts;

    // =====================================================================
    //                                EVENTS
    // =====================================================================

    /// @dev Events are cheap log entries that apps outside the chain can read
    ///      (the frontend builds its list of builds from `Registered` events).
    ///      Contracts cannot read them. `indexed` fields can be searched.
    event Registered(bytes32 indexed digest, address indexed publisher, string version);
    event Attested(bytes32 indexed digest, bytes32 indexed role, address indexed signer);
    event Released(bytes32 indexed digest, uint8 signOffs);
    event Revoked(bytes32 indexed digest, address indexed publisher, string reason);
    event PublisherSet(address indexed publisher, bool allowed);
    event RoleSet(address indexed account, bytes32 indexed role, bool held);

    // =====================================================================
    //                                ERRORS
    // =====================================================================

    /// @dev Named errors instead of `require("some text")`. They are cheaper,
    ///      and the frontend turns the name into a readable message. Malformed
    ///      signatures revert with OpenZeppelin's own `ECDSAInvalidSignature*`
    ///      errors; `BadSignature` means "valid, but not from the claimed signer".
    error NotOwner();
    error NotPublisher();
    error AlreadyRegistered();
    error UnknownDigest();
    error NotTheOriginalPublisher();
    error AlreadyRevoked();
    error ArtifactRevoked();
    error RoleNotHeld();
    error RoleAlreadySigned();
    error SignatureExpired();
    error BadSignature();
    error LengthMismatch();
    error QuorumOutOfRange();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param quorum_ How many roles must sign (1 to 3).
    /// @dev `EIP712("ArtifactRegistry", "1")` sets the name and version that go
    ///      into every signature's domain; the frontend uses the same two
    ///      strings. Weak point to be aware of: the owner is one address that
    ///      hands out all the roles, so the whole thing is only as safe as that
    ///      key. In production the owner would be a multisig wallet.
    constructor(uint8 quorum_) EIP712("ArtifactRegistry", "1") {
        if (quorum_ == 0 || quorum_ > 3) revert QuorumOutOfRange();

        owner = msg.sender;
        quorum = quorum_;
        isPublisher[msg.sender] = true;

        emit PublisherSet(msg.sender, true);
    }

    // =====================================================================
    //                             ADMINISTRATION
    // =====================================================================

    /// @notice Allow (or disallow) an address to register builds.
    function setPublisher(address publisher, bool allowed) external onlyOwner {
        isPublisher[publisher] = allowed;
        emit PublisherSet(publisher, allowed);
    }

    /// @notice Give (or take away) a role.
    /// @dev Taking a role away does not undo signatures already given. A
    ///      signature records what was true at the time it was made.
    function setRole(address account, bytes32 role, bool held) external onlyOwner {
        holdsRole[account][role] = held;
        emit RoleSet(account, role, held);
    }

    // =====================================================================
    //                              PUBLISHING
    // =====================================================================

    /// @notice Register a build under its SHA-256 digest.
    /// @dev A digest can be registered only once. Records are never deleted or
    ///      overwritten, only revoked.
    function register(bytes32 digest, string calldata version) external {
        if (!isPublisher[msg.sender]) revert NotPublisher();

        // "Already registered" means: a publisher is stored for this digest.
        if (_artifacts[digest].publisher != address(0)) revert AlreadyRegistered();

        _artifacts[digest] = Artifact({
            publisher: msg.sender,
            registeredAt: uint64(block.timestamp),
            revoked: false,
            signOffs: 0,
            version: version
        });

        emit Registered(digest, msg.sender, version);
    }

    /// @notice Withdraw a build. Only the original publisher can, and it is
    ///         permanent - the record stays, marked as revoked.
    function revoke(bytes32 digest, string calldata reason) external {
        Artifact storage a = _artifacts[digest];
        if (a.publisher == address(0)) revert UnknownDigest();
        if (a.publisher != msg.sender) revert NotTheOriginalPublisher();
        if (a.revoked) revert AlreadyRevoked();

        a.revoked = true;
        emit Revoked(digest, msg.sender, reason);
    }

    // =====================================================================
    //                             ATTESTATION
    // =====================================================================

    /// @notice Submit one reviewer's signature for a build.
    /// @dev Anyone can call this - the sender does not matter. What matters is
    ///      who SIGNED, and we find that out from the signature itself. That is
    ///      why reviewers need no ETH: someone else sends the transaction.
    function attest(Attestation calldata a, bytes calldata signature) public {
        Artifact storage art = _artifacts[a.digest];

        // Cheap checks first, the expensive signature check last.
        if (art.publisher == address(0)) revert UnknownDigest();
        if (art.revoked) revert ArtifactRevoked();
        if (block.timestamp > a.deadline) revert SignatureExpired();
        if (!holdsRole[a.signer][a.role]) revert RoleNotHeld();
        if (signedBy[a.digest][a.role] != address(0)) revert RoleAlreadySigned();

        // Recover the address that made the signature; it must be the one
        // the message claims. (OpenZeppelin reverts here on a malformed one.)
        if (ECDSA.recoverCalldata(_hashToSign(a), signature) != a.signer) revert BadSignature();

        signedBy[a.digest][a.role] = a.signer;

        // Max three roles, each once, so this can never overflow a uint8.
        uint8 count = ++art.signOffs;

        emit Attested(a.digest, a.role, a.signer);

        // Fires exactly once, on the signature that reaches the quorum.
        if (count == quorum) emit Released(a.digest, count);
    }

    /// @notice Submit several signatures in one transaction. This is the
    ///         normal way: reviewers sign whenever they want, one person pays
    ///         once for all of them.
    /// @dev No limit on the list length - a huge batch could run out of gas.
    ///      Nothing is lost if it does; just resubmit in smaller batches.
    function attestBatch(Attestation[] calldata list, bytes[] calldata signatures) external {
        if (list.length != signatures.length) revert LengthMismatch();
        for (uint256 i = 0; i < list.length; ++i) {
            attest(list[i], signatures[i]);
        }
    }

    // =====================================================================
    //                                READING
    // =====================================================================

    /// @notice Look up a build. If `record.publisher` is the zero address, the
    ///         digest was never registered.
    /// @dev `view` = free to call, no wallet or gas needed. `released` is
    ///      calculated on the spot so it can never be out of date.
    function verify(bytes32 digest) external view returns (Artifact memory record, bool released) {
        record = _artifacts[digest];

        // A revoked build is never released, no matter how many signed it.
        released = record.publisher != address(0) && !record.revoked && record.signOffs >= quorum;
    }

    /// @notice The EIP-712 "domain": identifies this exact contract on this
    ///         exact chain, so a signature made for it is useless anywhere else.
    /// @dev OpenZeppelin caches it at deployment and recomputes it if the chain
    ///      ID ever changes (a fork), so old signatures do not carry over.
    function domainSeparator() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // =====================================================================
    //                              INTERNALS
    // =====================================================================

    /// @dev The 32-byte hash the wallet actually signed:
    ///      keccak256( 0x19 0x01 ‖ domain ‖ hash of the struct ).
    ///      `_hashTypedDataV4` (OpenZeppelin) adds the prefix and the domain;
    ///      the 0x19 0x01 prefix makes sure this can never be mistaken for a
    ///      real transaction.
    function _hashToSign(Attestation calldata a) private view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(ATTESTATION_TYPEHASH, a)));
    }
}
