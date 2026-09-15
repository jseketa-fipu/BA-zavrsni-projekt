// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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
contract ArtifactRegistry {
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

    /// @dev EIP-712 is the standard for signing structured data so that the
    ///      wallet can show the user readable fields instead of hex. These two
    ///      constants describe the "shape" of what is signed. The strings must
    ///      match what the frontend sends to MetaMask, character for character.
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes32 digest,bytes32 role,address signer,uint256 deadline)");

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev Every ECDSA signature has a "mirror twin" that is also valid for
    ///      the same signer. We accept only the one with the smaller `s` value
    ///      so each signature has exactly one valid form. This is the standard
    ///      check; OpenZeppelin does the same.
    uint256 private constant HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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

    uint256 private immutable _cachedChainId;
    bytes32 private immutable _cachedDomainSeparator;

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
    ///      and the frontend turns the name into a readable message.
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
    error MalleableSignature();
    error LengthMismatch();
    error QuorumOutOfRange();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param quorum_ How many roles must sign (1 to 3).
    /// @dev Weak point to be aware of: the owner is one address that hands out
    ///      all the roles, so the whole thing is only as safe as that key.
    ///      In production the owner would be a multisig wallet.
    constructor(uint8 quorum_) {
        if (quorum_ == 0 || quorum_ > 3) revert QuorumOutOfRange();

        owner = msg.sender;
        quorum = quorum_;
        isPublisher[msg.sender] = true;

        // Pre-compute the EIP-712 domain hash once; see domainSeparator().
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();

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
        // the message claims.
        if (_recover(_hashToSign(a), signature) != a.signer) revert BadSignature();

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
    /// @dev Normally the cached value. If the chain ID has changed (a fork),
    ///      it is recomputed so old signatures do not carry over.
    function domainSeparator() public view returns (bytes32) {
        return block.chainid == _cachedChainId ? _cachedDomainSeparator : _buildDomainSeparator();
    }

    // =====================================================================
    //                              INTERNALS
    // =====================================================================

    function _buildDomainSeparator() private view returns (bytes32) {
        // name + version identify the app; chainId + address(this) pin the
        // signature to this chain and this deployment.
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("ArtifactRegistry")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev Build the 32-byte hash that the wallet actually signed. Must be
    ///      computed exactly the way EIP-712 says, or the recovered signer will
    ///      be wrong:  keccak256( 0x19 0x01 ‖ domain ‖ hash of the struct ).
    ///      The 0x19 0x01 prefix makes sure this can never be mistaken for a
    ///      real transaction.
    function _hashToSign(Attestation calldata a) private view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(ATTESTATION_TYPEHASH, a));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @dev Turn (hash, signature) back into the signer's address.
    ///      A signature is 65 bytes: r (32) + s (32) + v (1). `ecrecover` is a
    ///      built-in that does the math. We add the checks it does not do
    ///      itself; OpenZeppelin's ECDSA library does the same three.
    function _recover(bytes32 hash, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) revert BadSignature();

        // Split the 65 bytes into the three parts.
        (bytes32 r, bytes32 s) = abi.decode(sig[:64], (bytes32, bytes32));
        uint8 v = uint8(sig[64]);

        // Reject the "mirror twin" form (see HALF_ORDER).
        if (uint256(s) > HALF_ORDER) revert MalleableSignature(); // the mirror signature

        // On garbage input ecrecover does not fail - it returns the zero
        // address. Without this check, a role accidentally granted to the zero
        // address would accept any random bytes as a signature.
        address recovered = ecrecover(hash, v, r, s);
        if (recovered == address(0)) revert BadSignature();

        return recovered;
    }
}
