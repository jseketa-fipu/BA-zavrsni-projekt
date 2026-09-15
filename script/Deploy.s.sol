// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {AccessRegistry} from "../src/AccessRegistry.sol";
import {ArtifactRegistry} from "../src/ArtifactRegistry.sol";

/// @notice Deploys both contracts, wires them, and gives the deployer all three
///         roles so one account can run the whole demo.
///
///         Local:    forge script script/Deploy.s.sol --rpc-url anvil --private-key <key> --broadcast
///         Sepolia:  forge script script/Deploy.s.sol --rpc-url sepolia --account deployer --broadcast
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        (, address me,) = vm.readCallers(); // the account that is broadcasting

        AccessRegistry access = new AccessRegistry(); // deployer is owner + publisher
        ArtifactRegistry registry = new ArtifactRegistry(3, access);

        access.setRole(me, registry.ROLE_BUILD(), true);
        access.setRole(me, registry.ROLE_QA(), true);
        access.setRole(me, registry.ROLE_SECURITY(), true);

        vm.stopBroadcast();

        console.log("AccessRegistry:  ", address(access));
        console.log("ArtifactRegistry:", address(registry));
        console.log("publisher + all roles:", me);
    }
}
