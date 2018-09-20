# IDHub DID Registry

This contract allows on and off-chain resolving and management for [DIDs (Decentralized IDentifiers)](https://w3c-ccg.github.io/did-spec/).

A DID is an [Identifier](https://w3c-ccg.github.io/did-spec/#decentralized-identifiers-dids) that allows you to lookup a [DID document](https://w3c-ccg.github.io/did-spec/#did-documents) that can be used to authenticate you and messages created by you.

It was designed as a way of resolving public keys for off chain authentication, where the public key resolution is handled through the use of decentralized technology.

This contract allows ethereum addresses to present signing information about themselves with no prior registration. It allows them to perform key rotation and specify different keys and services that can be used on it's behalf for both on and off-chain usage.