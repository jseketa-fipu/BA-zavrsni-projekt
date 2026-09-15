// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  AccessRegistry
/// @notice Who may register builds, and who holds which reviewer role.
///
///         This lives in its own contract, separate from the ledger
///         (ArtifactRegistry), on purpose: the ledger only ever *asks* this
///         contract "is X a publisher?" / "does X hold role R?" and never
///         decides policy itself. Reviewers can be changed, or a new role
///         added, without touching the ledger - and one AccessRegistry can
///         serve several ledgers.
contract AccessRegistry {
    /// @dev The one address allowed to change the lists. Set once, at
    ///      deployment. Weak point to be aware of: everything here is only as
    ///      safe as this key. In production it would be a multisig wallet.
    address public immutable owner;

    /// @notice Who is allowed to register builds.
    mapping(address => bool) public isPublisher;

    /// @notice Who holds which role. account => role => yes/no.
    ///         Roles are just bytes32 names (keccak256("QA") etc.); this
    ///         contract does not care what they mean.
    mapping(address => mapping(bytes32 => bool)) public holdsRole;

    event PublisherSet(address indexed publisher, bool allowed);
    event RoleSet(address indexed account, bytes32 indexed role, bool held);

    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        isPublisher[msg.sender] = true;
        emit PublisherSet(msg.sender, true);
    }

    /// @notice Allow (or disallow) an address to register builds.
    function setPublisher(address publisher, bool allowed) external onlyOwner {
        isPublisher[publisher] = allowed;
        emit PublisherSet(publisher, allowed);
    }

    /// @notice Give (or take away) a role.
    /// @dev Taking a role away does not undo signatures already recorded in a
    ///      ledger. A signature records what was true when it was made.
    function setRole(address account, bytes32 role, bool held) external onlyOwner {
        holdsRole[account][role] = held;
        emit RoleSet(account, role, held);
    }
}
