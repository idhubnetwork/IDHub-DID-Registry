pragma solidity ^0.4.24;

contract IDHubDIDRegistry {

  mapping(address => address) public owners;
  mapping(address => mapping(bytes32 => mapping(bytes32 => uint))) public publicKeys;
  mapping(address => mapping(bytes32 => mapping(bytes32 => uint))) public authentications;
  mapping(address => uint) public publicKeyChanged;
  mapping(address => uint) public authenticationChanged;
  mapping(address => uint) public attributeChanged;
  mapping(address => uint) public nonce;

  modifier onlyOwner(address identity, address actor) {
    require (actor == identityOwner(identity));
    _;
  }

  event DIDPublicKeyChanged(
    address indexed identity,
    bytes32 authenticationType,
    bytes32 authentication,
    uint validTo,
    uint previousChange
  );

  event DIDAuthenticationChanged(
    address indexed identity,
    bytes32 authenticationType,
    bytes32 authentication,
    uint validTo,
    uint previousChange
  );

  event DIDAttributeChanged(
    address indexed identity,
    bytes32 name,
    bytes value,
    uint validTo,
    uint previousChange
  );

  function identityOwner(address identity) public view returns(address) {
     address owner = owners[identity];
     if (owner != 0x0) {
       return owner;
     }
     return identity;
  }

  function checkSignature(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 hash) internal returns(address) {
    address signer = ecrecover(hash, sigV, sigR, sigS);
    require(signer == identityOwner(identity));
    nonce[signer]++;
    return signer;
  }

  function validPublicKey(address identity, bytes32 publicKeyType, bytes32 publicKey) public view returns(bool) {
    uint validity = publicKeys[identity][keccak256(publicKeyType)][publicKey];
    return (validity > now);
  }

  function validAuthentication(address identity, bytes32 authenticationType, bytes32 authentication) public view returns(bool) {
    uint validity = authentications[identity][keccak256(authenticationType)][authentication];
    return (validity > now);
  }

  function changeOwner(address identity, address actor, address newOwner) internal onlyOwner(identity, actor) {
    owners[identity] = newOwner;
    // changed[identity] = block.number;
  }

  function changeOwner(address identity, address newOwner) public {
    changeOwner(identity, msg.sender, newOwner);
  }

  function changeOwnerSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address newOwner) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, "changeOwner", newOwner);
    changeOwner(identity, checkSignature(identity, sigV, sigR, sigS, hash), newOwner);
  }

  function addPublicKey(address identity, address actor, bytes32 publicKeyType, bytes32 publicKey, uint validity) internal onlyOwner(identity, actor) {
    publicKeys[identity][keccak256(publicKeyType)][publicKey] = now + validity;
    emit DIDPublicKeyChanged(identity, publicKeyType, publicKey, now + validity, publicKeyChanged[identity]);
    publicKeyChanged[identity] = block.number;
  }

  function addPublicKey(address identity, bytes32 publicKeyType, bytes32 publicKey, uint validity) public {
    addPublicKey(identity, msg.sender, publicKeyType, publicKey, validity);
  }

  function addPublicKeySigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 publicKeyType, bytes32 publicKey, uint validity) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, "addPublicKey", publicKeyType, publicKey, validity);
    addPublicKey(identity, checkSignature(identity, sigV, sigR, sigS, hash), publicKeyType, publicKey, validity);
  }

  function revokePublicKey(address identity, address actor, bytes32 publicKeyType, bytes32 publicKey) internal onlyOwner(identity, actor) {
    publicKeys[identity][keccak256(publicKeyType)][publicKey] = now;
    emit DIDPublicKeyChanged(identity, publicKeyType, publicKey, now, publicKeyChanged[identity]);
    publicKeyChanged[identity] = block.number;
  }

  function revokePublicKey(address identity, bytes32 publicKeyType, bytes32 publicKey) public {
    revokePublicKey(identity, msg.sender, publicKeyType, publicKey);
  }

  function revokePublicKeySigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 publicKeyType, bytes32 publicKey) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, "revokePublicKey", publicKeyType, publicKey);
    revokePublicKey(identity, checkSignature(identity, sigV, sigR, sigS, hash), publicKeyType, publicKey);
  }

  function addAuthentication(address identity, address actor, bytes32 authenticationType, bytes32 authentication, uint validity) internal onlyOwner(identity, actor) {
    authentications[identity][keccak256(authenticationType)][authentication] = now + validity;
    emit DIDAuthenticationChanged(identity, authenticationType, authentication, now + validity, authenticationChanged[identity]);
    authenticationChanged[identity] = block.number;
  }

  function addAuthentication(address identity, bytes32 authenticationType, bytes32 authentication, uint validity) public {
    addAuthentication(identity, msg.sender, authenticationType, authentication, validity);
  }

  function addAuthenticationSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 authenticationType, bytes32 authentication, uint validity) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, "addAuthentication", authenticationType, authentication, validity);
    addAuthentication(identity, checkSignature(identity, sigV, sigR, sigS, hash), authenticationType, authentication, validity);
  }

  function revokeAuthentication(address identity, address actor, bytes32 authenticationType, bytes32 authentication) internal onlyOwner(identity, actor) {
    authentications[identity][keccak256(authenticationType)][authentication] = now;
    emit DIDAuthenticationChanged(identity, authenticationType, authentication, now, authenticationChanged[identity]);
    authenticationChanged[identity] = block.number;
  }

  function revokeAuthentication(address identity, bytes32 authenticationType, bytes32 authentication) public {
    revokeAuthentication(identity, msg.sender, authenticationType, authentication);
  }

  function revokeAuthenticationSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 authenticationType, bytes32 authentication) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identityOwner(identity)], identity, "revokeAuthentication", authenticationType, authentication);
    revokeAuthentication(identity, checkSignature(identity, sigV, sigR, sigS, hash), authenticationType, authentication);
  }

  function setAttribute(address identity, address actor, bytes32 name, bytes value, uint validity ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, now + validity, attributeChanged[identity]);
    attributeChanged[identity] = block.number;
  }

  function setAttribute(address identity, bytes32 name, bytes value, uint validity) public {
    setAttribute(identity, msg.sender, name, value, validity);
  }

  function setAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes value, uint validity) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identity], identity, "setAttribute", name, value, validity);
    setAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value, validity);
  }

  function revokeAttribute(address identity, address actor, bytes32 name, bytes value ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, 0, attributeChanged[identity]);
    attributeChanged[identity] = block.number;
  }

  function revokeAttribute(address identity, bytes32 name, bytes value) public {
    revokeAttribute(identity, msg.sender, name, value);
  }

  function revokeAttributeSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, bytes32 name, bytes value) public {
    bytes32 hash = keccak256(byte(0x19), byte(0), this, nonce[identity], identity, "revokeAttribute", name, value); 
    revokeAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hash), name, value);
  }

}