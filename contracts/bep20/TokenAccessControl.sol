// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract TokenAccessControl is AccessControl {

    
    bytes32 public OWNER_ROLE = keccak256("OWNER");
    bytes32 public WHITELISTER_ADMIN_ROLE = keccak256("ADMIN_WHITELISTER");
    bytes32 public WHITELISTER_ROLE = keccak256("WHITELISTER");
    bytes32 public WHITELISTED_SENDER = keccak256("WHITELISTED_SENDER");
    bytes32 public WHITELISTED_RECIPIENT = keccak256("WHITELISTED_RECIPIENT");

    function initializeRoles(address owner,address whitelister) internal {

        
        OWNER_ROLE = keccak256("OWNER");
        WHITELISTER_ADMIN_ROLE = keccak256("ADMIN_WHITELISTER");
        WHITELISTER_ROLE = keccak256("WHITELISTER");
        WHITELISTED_SENDER = keccak256("WHITELISTED_SENDER");
        WHITELISTED_RECIPIENT = keccak256("WHITELISTED_RECIPIENT");

        _setupRole(DEFAULT_ADMIN_ROLE, owner);

        _setRoleAdmin(OWNER_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(WHITELISTER_ADMIN_ROLE, OWNER_ROLE);
        _setRoleAdmin(WHITELISTER_ROLE, WHITELISTER_ADMIN_ROLE);
        _setRoleAdmin(WHITELISTED_SENDER, WHITELISTER_ROLE);
        _setRoleAdmin(WHITELISTED_RECIPIENT, WHITELISTER_ROLE);
        
        _grantRole(OWNER_ROLE,owner);
        _grantRole(WHITELISTER_ADMIN_ROLE,owner);
        
        _grantRole(WHITELISTER_ROLE,whitelister);
    }

    function isOwner(address account) public virtual view returns(bool)
    {
        return hasRole(OWNER_ROLE, account);
    }

    function isWhitelisterAdmin(address account) public virtual view returns(bool)
    {
        return hasRole(WHITELISTER_ADMIN_ROLE, account);
    }

    function isWhitelister(address account) public virtual view returns(bool)
    {
        return hasRole(WHITELISTER_ROLE, account);
    }

    function isWhitelistedSender(address account) public virtual view returns(bool)
    {
        return hasRole(WHITELISTED_SENDER, account);
    }

    function isWhitelistedRecipient(address account) public virtual view returns(bool)
    {
        return hasRole(WHITELISTED_RECIPIENT, account);
    }

}