# MLS (Messaging Layer Security)

An Implementation of the [MLS (Messaging Layer Security) Standard (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420.html)
in Kotlin.

## What is MLS?

MLS is a standard to facilitate end-to-end-encrypted messaging applications, by employing a tree-based group key
management protocol that is designed to provide Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS).
The standard focuses on efficient group operations, making it suitable to serve group chats of up to multiple thousand
members.

Changes to the group state are carried out in so-called _epochs_, each of which is initiated by a _commit_, which
applies one or more change _proposals_ to the group state. These proposals may add a member, remove a member or
update a members key material, among others. The protocol ensures that any given client has access to the key material
of the group in any given epoch, if, and only if, the client was a member of the group during this epoch.

The members of the group are organized in a _ratchet tree_, which provides efficient means to encrypt a message for
any subset of the group's members. The ratchet tree is used to seed a _key schedule_, which updates the group's shared
key material for each epoch. From the key schedule, a _secret tree_ having the same structure as the ratchet tree is
derived, which provides a message encryption ratchet for each member of the group. The symmetric keys produced by said
ratchet are then used to protect messages sent in the group.

## This Library

This library provides a fully RFC-compliant Kotlin implementation of the MLS standard. It exposes a low-level API
with detail control about group operations, as well as a convenient high-level API that encapsulates most of the
complexity of the protocol and gives applications only the choices they absolutely need.

The low-level API is centered around the `com.github.traderjoe95.mls.protocol.group.GroupState` type, representing
the state of an MLS group during a single epoch. It is an immutable type, returning a new copy anytime something is
updated, so applications are responsible to keep a history of changes to the group state, if they require so.

The high-level API is provided by the `com.github.traderjoe95.mls.protocol.client.MlsClient` and
`com.github.traderjoe95.mls.protocol.client.GroupClient` classes. A `GroupClient` is a client for a single group
that provides convenient, high-level methods for group evolution. It keeps a history of group states such that
application messages received out of order (e.g. after an epoch change has already taken place) can still be
decrypted. An `MlsClient` is an entity capable of managing multiple group clients, keeping their state and facilitating
special tasks such as group resumption (subgroup branching or reinitialization).

The `demo` module provides a few examples on how the APIs of this library may be used.

### Prerequisites

This library is currently built with

* Kotlin JVM 1.9.22
* Java 21

This is likely to change in the not-too-distant future to ensure further compatibility, and to enable a future move to
Kotlin Multiplatform, in order to make this library available across all or most platforms supported by Kotlin.

### Modules

* `codec` implements the raw MLS codec, that is, as slightly enhanced TLS 1.3 presentation language
* `protocol` provides all MLS struct and enum types, as well as implementations of the MLS protocol
* `interop` provides the MLS test harness for interop testing
* `demo` is a collection of simple examples of library usage.

## Roadmap

Within each section below, the entries are decidedly _not ordered by priority_.

### Short-Term

* Polish high-level API, add missing functionality
* Implement the [MLS Test Harness](https://github.com/mlswg/mls-implementations/blob/main/test-harness.md) to facilitate
  interop testing
* Publishing to Maven Central, or similar
* Add support for the few missing bits from the standard
* Restructure the project
  * Remove the `ulid` module, as it is only used for the demo

### Mid-Term

* API documentation
* Provide a usable Java API
* Increase test coverage of the `protocol` module

### Long-Term

* Kotlin Multiplatform
