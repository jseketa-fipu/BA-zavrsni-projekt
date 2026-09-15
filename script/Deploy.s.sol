// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ArtifactRegistry} from "../src/ArtifactRegistry.sol";

/// @notice Deploys the registry with a quorum of 3 and gives the deployer all
///         three roles, so one account can run the whole demo.
///
///         Local:    forge script script/Deploy.s.sol --rpc-url anvil --private-key <key> --broadcast
///         Sepolia:  forge script script/Deploy.s.sol --rpc-url sepolia --account deployer --broadcast
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        (, address me,) = vm.readCallers(); // the account that is broadcasting

        ArtifactRegistry registry = new ArtifactRegistry(3);
        registry.setRole(me, registry.ROLE_BUILD(), true);
        registry.setRole(me, registry.ROLE_QA(), true);
        registry.setRole(me, registry.ROLE_SECURITY(), true);

        vm.stopBroadcast();

        console.log("ArtifactRegistry:", address(registry));
        console.log("publisher + all roles:", me);
        console.log("deployed in block:", block.number);
    }
}
