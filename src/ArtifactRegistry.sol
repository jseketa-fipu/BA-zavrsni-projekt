// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  ArtifactRegistry
/// @notice A release ledger for build artifacts: firmware images, packages,
///         container layers. A build is filed under the SHA-256 digest of its
///         bytes, and only counts as *released* once a quorum of distinct
///         roles - build server, QA, security review - have signed off on it.
///
/// @dev WHY A CHAIN AND NOT A DATABASE
///      The three roles are meant to be separate parties: different teams, or
///      different companies. A shared database gives whoever runs it the power
///      to forge the other two sign-offs. Here each sign-off is a secp256k1
///      signature over a message naming the exact digest, so nobody - not the
///      publisher, not the relayer, not the contract owner - can manufacture
///      an approval they do not hold the key for.
///
/// @dev THE GAS ASYMMETRY, WHICH IS THE POINT OF THE DESIGN
///      Reviewers sign off chain (EIP-712) and pay nothing. One relayer bundles
///      the signatures into a single transaction and pays once. Anyone checking
///      a build calls `verify`, a view function: no wallet, no account, no gas.
///      Writing is rare and paid for; reading is constant and free.
contract ArtifactRegistry {
    // =====================================================================
    //                                TYPES
    // =====================================================================

    /// @dev Storage is the expensive resource in the EVM: one 32-byte slot
    ///      costs 20,000 gas to first write. The compiler packs consecutive
    ///      fields into one slot when they fit, so field ORDER is a real
    ///      decision, not styling.
    ///
    ///      address(160) + uint64(64) + bool(8) + uint8(8) = 240 bits <= 256,
    ///      so all four fixed-width fields share slot 0 of the record and a
    ///      registration writes it once. `version` is a dynamic string and can
    ///      never share a slot, so it goes last where it costs one more write
    ///      and is then never touched again by the signing hot path.
    ///
    ///      Reorder this struct - put `version` first, or `publisher` between
    ///      the bools - and registration silently costs ~20k more gas. That is
    ///      the kind of thing worth checking with `forge test --gas-report`.
    struct Artifact {
        address publisher;    // who filed it; address(0) means "never seen"
        uint64 registeredAt;  // block timestamp; good until year 584942
        bool revoked;         // withdrawn by its publisher, never deleted
        uint8 signOffs;       // how many distinct roles have signed, 0..3
        string version;       // human label, e.g. "2.4.0" - display only
    }

    /// @dev The message a reviewer signs in their wallet.
    ///
    ///      NOTE THE MISSING NONCE. Almost every signature scheme carries one,
    ///      and its absence is the first thing to defend:
    ///
    ///      A nonce exists to stop a signature being replayed. Here the
    ///      (digest, role) slot in `signedBy` is written exactly once and never
    ///      cleared, so a second submission of the same signature hits
    ///      RoleAlreadySigned. The stored attestation *is* the replay guard.
    ///      Adding a nonce would buy nothing, cost an extra storage write per
    ///      signature, and force reviewers to sign in a fixed order - the third
    ///      reviewer could not sign until the second had landed on chain.
    ///
    ///      Replay across *chains* (mainnet signature reused on a testnet) and
    ///      across *deployments* (signature reused against a second copy of
    ///      this contract) is stopped instead by chainId and verifyingContract
    ///      inside the EIP-712 domain separator. See `_domainSeparator`.
    struct Attestation {
        bytes32 digest;    // which build is being approved
        bytes32 role;      // in which capacity
        address signer;    // who claims to be signing - checked against ecrecover
        uint256 deadline;  // unix time after which this signature is dead
    }

    // =====================================================================
    //                              CONSTANTS
    // =====================================================================

    // Roles are hashes rather than an enum so new ones can be added later
    // without changing the storage layout or the signed message format.
    bytes32 public constant ROLE_BUILD = keccak256("BUILD");
    bytes32 public constant ROLE_QA = keccak256("QA");
    bytes32 public constant ROLE_SECURITY = keccak256("SECURITY");

    /// @dev EIP-712 hashes a struct by prefixing a "typehash": the keccak of
    ///      the type's signature, written with no spaces and fields in
    ///      declaration order. It commits the signature to this exact shape, so
    ///      a message meant as an Attestation can never be reinterpreted as
    ///      some other struct that happens to encode to the same bytes.
    ///      Get one character wrong here and every signature fails to verify -
    ///      it must match what the wallet computes from the `types` object.
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes32 digest,bytes32 role,address signer,uint256 deadline)");

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev Half the secp256k1 curve order.
    ///
    ///      SIGNATURE MALLEABILITY: for any valid signature (r, s, v) the pair
    ///      (r, order - s, 55 - v) - s mirrored, v flipped between 27 and 28 -
    ///      is a *different* byte string that recovers to the same signer. Raw
    ///      `ecrecover` accepts both. That is harmless here - the (digest,
    ///      role) slot stops the second one either way -
    ///      but it is fatal in any design that uses the signature bytes
    ///      themselves as an identifier, which is how it sank Mt. Gox era
    ///      transaction ids. Rejecting the high half is one comparison, and it
    ///      is the question an examiner reaches for the moment they see a bare
    ///      `ecrecover`, so it is worth having.
    uint256 private constant HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // =====================================================================
    //                                STATE
    // =====================================================================

    // `immutable` values are burned into the deployed bytecode instead of
    // living in storage, so reading one is nearly free compared to an SLOAD.

    address public immutable owner;

    /// @notice Distinct role sign-offs required before a build is released.
    /// @dev Immutable on purpose. A settable quorum would let the owner change
    ///      what "released" means for builds that were already signed - drop it
    ///      from 3 to 1 and every half-approved artifact in history becomes
    ///      released retroactively, with no transaction recording the change to
    ///      those records. Deploy a new registry instead.
    uint8 public immutable quorum;

    uint256 private immutable _cachedChainId;
    bytes32 private immutable _cachedDomainSeparator;

    /// @notice Who may file new builds.
    mapping(address => bool) public isPublisher;

    /// @notice Who may sign off in which role. account => role => allowed.
    mapping(address => mapping(bytes32 => bool)) public holdsRole;

    /// @notice Which address filled each role for each build.
    ///         digest => role => signer, address(0) meaning "not yet signed".
    ///         Doubles as the replay guard; see the note on `Attestation`.
    mapping(bytes32 => mapping(bytes32 => address)) public signedBy;

    /// @dev Private, and read through `verify` so the derived `released` flag
    ///      is computed in one place rather than by every caller.
    mapping(bytes32 => Artifact) private _artifacts;

    // =====================================================================
    //                                EVENTS
    // =====================================================================

    /// @dev Events are the cheap half of the EVM: a few hundred gas, versus
    ///      20,000 for a storage slot. They are not readable by contracts, only
    ///      by off-chain code watching the chain - which is exactly what a
    ///      frontend is. So the ledger listing in the UI is built by querying
    ///      `Registered` logs, and this contract keeps no array of digests.
    ///      An on-chain `bytes32[] digests` would have cost every publisher an
    ///      extra ~20k gas per registration purely to serve a page that could
    ///      read the logs for free.
    ///
    ///      `indexed` puts a field in the log's topics, which is what lets a
    ///      client filter server-side ("all registrations by this publisher")
    ///      instead of downloading everything. Three indexed fields max, and
    ///      indexed strings are stored as a hash - unsearchable and unreadable
    ///      - which is why `version` and `reason` are left unindexed.
    event Registered(bytes32 indexed digest, address indexed publisher, string version);
    event Attested(bytes32 indexed digest, bytes32 indexed role, address indexed signer);
    event Released(bytes32 indexed digest, uint8 signOffs);
    event Revoked(bytes32 indexed digest, address indexed publisher, string reason);
    event PublisherSet(address indexed publisher, bool allowed);
    event RoleSet(address indexed account, bytes32 indexed role, bool held);

    // =====================================================================
    //                                ERRORS
    // =====================================================================

    /// @dev Custom errors instead of require strings: the revert carries a
    ///      4-byte selector rather than the whole sentence, which is cheaper to
    ///      deploy and cheaper to revert with. The frontend decodes the
    ///      selector back into a readable message, so nothing is lost to users.
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

    /// @param quorum_ Sign-offs needed to release, 1..3.
    /// @dev KNOWN WEAKNESS, worth naming before someone asks: `owner` is a
    ///      single key that grants every role, so the whole trust model rests
    ///      on it. It cannot forge a signature, but it can appoint itself to
    ///      all three roles and sign alone. The real answer is a multisig or a
    ///      DAO as owner - which needs no change here, since any contract
    ///      address works as `owner`.
    constructor(uint8 quorum_) {
        if (quorum_ == 0 || quorum_ > 3) revert QuorumOutOfRange();

        owner = msg.sender;
        quorum = quorum_;
        isPublisher[msg.sender] = true;

        // Cache the domain separator once. It only depends on values fixed at
        // deployment, so recomputing it per signature would be four wasted
        // keccaks - but see `_domainSeparator` for the fork caveat.
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();

        emit PublisherSet(msg.sender, true);
    }

    // =====================================================================
    //                             ADMINISTRATION
    // =====================================================================

    /// @notice Allow or forbid an address to file new builds.
    /// @dev One setter with a bool rather than add/remove twins: half the
    ///      functions, half the events, and no way for the two to drift apart.
    function setPublisher(address publisher, bool allowed) external onlyOwner {
        isPublisher[publisher] = allowed;
        emit PublisherSet(publisher, allowed);
    }

    /// @notice Allow or forbid an address to sign off in a role.
    /// @dev Taking a role away does NOT retract sign-offs already given, and
    ///      that is deliberate: an attestation records what was true at the
    ///      moment it was made, the way a signed document stays signed after
    ///      the signer leaves the company. The opposite choice is defensible
    ///      too - if a reviewer's key is found to have been stolen you would
    ///      want their past approvals gone - but it needs a way to re-open a
    ///      released build, which is a bigger design than this one.
    function setRole(address account, bytes32 role, bool held) external onlyOwner {
        holdsRole[account][role] = held;
        emit RoleSet(account, role, held);
    }

    // =====================================================================
    //                              PUBLISHING
    // =====================================================================

    /// @notice File a build under the SHA-256 digest of its bytes.
    /// @dev Records are never overwritten or deleted, only revoked. Letting a
    ///      digest be re-registered would let a publisher wipe the sign-off
    ///      history of a build that had already been approved.
    function register(bytes32 digest, string calldata version) external {
        if (!isPublisher[msg.sender]) revert NotPublisher();

        // No zero-digest guard on purpose: `publisher` is the sentinel for
        // "unknown", not the digest, so a record filed under bytes32(0) would
        // be a perfectly ordinary (and revocable) record. SHA-256 of real
        // bytes is never all zeros anyway.
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

    /// @notice Withdraw a build. Only its original publisher may do this, and
    ///         it is one-way: the record stays, flagged, forever.
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

    /// @notice Submit one reviewer's signed sign-off.
    /// @dev Anyone may relay this. `msg.sender` is deliberately never consulted
    ///      - the signature decides who attested. That is what lets reviewers
    ///      keep unfunded, cold, or hardware-held keys and still participate.
    function attest(Attestation calldata a, bytes calldata signature) public {
        Artifact storage art = _artifacts[a.digest];

        // Checks are ordered cheapest-first on purpose. `ecrecover` is a 3,000
        // gas precompile and the keccaks above it are not free either, so every
        // condition that can be settled with an SLOAD or a timestamp compare is
        // settled before we get there. A caller who fails these pays less, and
        // in the happy path the ordering costs nothing.
        if (art.publisher == address(0)) revert UnknownDigest();
        if (art.revoked) revert ArtifactRevoked();
        if (block.timestamp > a.deadline) revert SignatureExpired();
        if (!holdsRole[a.signer][a.role]) revert RoleNotHeld();
        if (signedBy[a.digest][a.role] != address(0)) revert RoleAlreadySigned();

        // Only now, having established the sign-off would actually count, do we
        // spend the gas to find out who signed it.
        if (_recover(_hashToSign(a), signature) != a.signer) revert BadSignature();

        signedBy[a.digest][a.role] = a.signer;

        // Cannot overflow: three roles, each fills its slot once, and the line
        // above guarantees this role's slot was empty - at most three per digest.
        uint8 count = ++art.signOffs;

        emit Attested(a.digest, a.role, a.signer);

        // `==` not `>=`: fire exactly once, on the sign-off that crosses the
        // line, so a client can treat Released as the release moment.
        if (count == quorum) emit Released(a.digest, count);
    }

    /// @notice Relay several sign-offs in one transaction - the normal path.
    ///         Reviewers sign whenever they like and pay nothing; one account
    ///         pays one transaction fee for all of them.
    /// @dev KNOWN WEAKNESS: the loop is unbounded, so a large enough batch
    ///      exceeds the block gas limit and reverts. Nothing is lost (the
    ///      signatures are still valid, just resubmit in smaller batches) but a
    ///      production version would cap the length. Note that `attest` is
    ///      `public`, not `external`, precisely so it can be called from here.
    function attestBatch(Attestation[] calldata list, bytes[] calldata signatures) external {
        if (list.length != signatures.length) revert LengthMismatch();
        for (uint256 i = 0; i < list.length; ++i) {
            attest(list[i], signatures[i]);
        }
    }

    // =====================================================================
    //                                READING
    // =====================================================================

    /// @notice Look up a build. `record.publisher == address(0)` means the
    ///         digest has never been registered here.
    /// @dev A `view` function: no transaction, no wallet, no gas. Checking a
    ///      download costs the checker nothing, which is what makes the whole
    ///      scheme usable. `released` is derived rather than stored so it can
    ///      never fall out of sync with the fields it is computed from.
    function verify(bytes32 digest) external view returns (Artifact memory record, bool released) {
        record = _artifacts[digest];

        // Revocation dominates quorum: a withdrawn build is not released even
        // with every signature in place.
        released = record.publisher != address(0) && !record.revoked && record.signOffs >= quorum;
    }

    /// @notice The EIP-712 domain separator wallets must sign under.
    /// @dev Rebuilt instead of served from cache if the chain id has changed
    ///      since deployment. That happens on a hard fork: the same contract
    ///      exists at the same address on both chains, and without this check a
    ///      sign-off given on one would verify on the other. Costs an SLOAD-free
    ///      immutable compare in the normal case.
    function domainSeparator() public view returns (bytes32) {
        return block.chainid == _cachedChainId ? _cachedDomainSeparator : _buildDomainSeparator();
    }

    // =====================================================================
    //                              INTERNALS
    // =====================================================================

    function _buildDomainSeparator() private view returns (bytes32) {
        // `name` and `version` separate this contract's messages from any other
        // protocol's; `chainId` and `verifyingContract` pin them to this chain
        // and this deployment. Together they are why a signature collected on
        // Anvil is worthless against the Sepolia copy - a property with a test
        // of its own in the suite.
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

    /// @dev The full EIP-712 digest: 0x19 0x01 ‖ domainSeparator ‖ structHash.
    ///
    ///      The 0x19 prefix comes from EIP-191 and is the reason a wallet can
    ///      show you a structured message instead of a hex blob. It also makes
    ///      this byte string impossible to confuse with an RLP-encoded
    ///      transaction, so a signature harvested here can never be replayed as
    ///      one that moves your funds. `abi.encodePacked` is correct and safe
    ///      here only because every piece is fixed-width.
    ///
    ///      `abi.encode(TYPEHASH, a)` equals EIP-712's encodeData only because
    ///      every field of Attestation is a static type. A string or bytes
    ///      field would have to be replaced by the keccak256 of its contents.
    function _hashToSign(Attestation calldata a) private view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(ATTESTATION_TYPEHASH, a));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @dev Split a 65-byte signature and recover the signer, rejecting the
    ///      shapes raw `ecrecover` is too permissive about.
    ///
    ///      WHY NOT OPENZEPPELIN: OZ's `ECDSA.recover` performs exactly these
    ///      checks - 65-byte length, high-s rejection, zero-address rejection,
    ///      with the same HALF_ORDER constant. They are written out here so
    ///      each one can be pointed at and explained; swapping this function
    ///      for the library call is a two-line change.
    function _recover(bytes32 hash, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) revert BadSignature();

        // Wallets hand back r ‖ s ‖ v as one blob. A calldata slice decodes in
        // place with no copy to memory; the final byte is v on its own. (An
        // assembly `calldataload` would be ~270 gas cheaper and far harder
        // to read - the wrong trade for code you want to be able to explain.)
        (bytes32 r, bytes32 s) = abi.decode(sig[:64], (bytes32, bytes32));
        uint8 v = uint8(sig[64]);

        // Two ways `ecrecover` will happily mislead you, closed in order:
        if (uint256(s) > HALF_ORDER) revert MalleableSignature(); // the mirror signature

        // ...and the big one: on ANY malformed input - a v that is not 27 or
        // 28 included - ecrecover does not revert, it returns address(0).
        // Without this check an owner slip like setRole(address(0), role, true)
        // would turn every garbage signature into a valid sign-off.
        address recovered = ecrecover(hash, v, r, s);
        if (recovered == address(0)) revert BadSignature();

        return recovered;
    }
}
