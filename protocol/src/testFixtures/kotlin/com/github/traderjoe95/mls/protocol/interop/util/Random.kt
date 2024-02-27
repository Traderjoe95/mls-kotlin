package com.github.traderjoe95.mls.protocol.interop.util

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.CredentialType
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.ExternalPskId
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference.Companion.asHashReference
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import java.time.Instant
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextUInt
import kotlin.random.nextULong
import kotlin.time.Duration.Companion.hours

fun Random.nextString(
  length: UIntRange = 0U..64U,
  chars: String = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
): String =
  nextUInt(length).let {
    (1U..it).map { chars[nextInt(chars.indices)] }.joinToString("")
  }

fun Random.nextUShort(
  from: UShort,
  to: UShort,
): UShort = nextUInt(from..to).toUShort()

fun Random.nextUShort(range: UIntRange): UShort = nextUInt(range).toUShort()

fun <T> Random.choice(from: List<T>): T = from[nextInt(from.indices)]

fun Random.nextAdd(cipherSuite: CipherSuite): Add {
  val (signaturePrivate, signaturePublic) = cipherSuite.generateSignatureKeyPair()

  return Add(
    KeyPackage.create(
      cipherSuite,
      cipherSuite.generateHpkeKeyPair().public,
      LeafNode.keyPackage(
        cipherSuite,
        cipherSuite.generateHpkeKeyPair().public,
        signaturePublic,
        BasicCredential(nextBytes(32)),
        Capabilities.create(listOf(CredentialType.Basic), listOf(cipherSuite)),
        Lifetime(Instant.now(), Instant.now().plusSeconds(3600)),
        listOf(),
        signaturePrivate,
      ),
      listOf(),
      signaturePrivate,
    ),
  )
}

fun Random.nextUpdate(
  cipherSuite: CipherSuite,
  groupId: GroupId = GroupId.new(),
): Update {
  val (signaturePrivateKey, signaturePublicKey) = cipherSuite.generateSignatureKeyPair()

  return Update(
    LeafNode.update(
      cipherSuite,
      signaturePublicKey,
      cipherSuite.generateHpkeKeyPair().public,
      BasicCredential(Random.nextBytes(32)),
      Capabilities.create(listOf(CredentialType.Basic), listOf(cipherSuite)),
      listOf(),
      LeafIndex(Random.nextUInt(0U..1U)),
      groupId,
      signaturePrivateKey,
    ),
  )
}

fun Random.nextRemove(leafRange: UIntRange): Remove = Remove(LeafIndex(nextUInt(leafRange)))

fun Random.nextPreSharedKey(cipherSuite: CipherSuite): PreSharedKey =
  PreSharedKey(
    if (nextDouble() < 0.5) {
      ExternalPskId(nextBytes(32), cipherSuite.hash(nextBytes(32)).asNonce)
    } else {
      ResumptionPskId(
        choice(ResumptionPskUsage.entries.filter { it.isValid }),
        GroupId.new(),
        nextULong(),
        cipherSuite.hash(nextBytes(32)).asNonce,
      )
    },
  )

fun Random.nextReInit(): ReInit =
  ReInit(
    GroupId.new(),
    ProtocolVersion.MLS_1_0,
    CipherSuite(choice(CipherSuite.VALID))!!,
    listOf(),
  )

fun Random.nextExternalInit(cipherSuite: CipherSuite): ExternalInit =
  ExternalInit(cipherSuite.export(cipherSuite.generateHpkeKeyPair().public, "MLS 1.0 external init secret").first)

fun Random.nextProposal(
  cipherSuite: CipherSuite,
  groupId: GroupId,
): Proposal =
  choice(
    listOf(
      { nextAdd(cipherSuite) },
      { nextUpdate(cipherSuite, groupId) },
      { nextRemove(0U..1U) },
      { nextPreSharedKey(cipherSuite) },
      { nextReInit() },
      { nextExternalInit(cipherSuite) },
    ),
  )()

fun Random.nextCommit(
  cipherSuite: CipherSuite,
  groupId: GroupId,
): Commit =
  Commit(
    List(nextInt(1..4)) {
      if (nextDouble() < 0.5) {
        nextProposal(cipherSuite, groupId)
      } else {
        cipherSuite.hash(nextBytes(32)).asHashReference.asProposalRef
      }
    },
  )

fun Random.nextGroupContext(
  cipherSuite: CipherSuite,
  groupId: GroupId? = null,
): GroupContext =
  GroupContext(
    ProtocolVersion.MLS_1_0,
    cipherSuite,
    groupId ?: GroupId.new(),
    nextULong(),
    nextBytes(cipherSuite.hashLen.toInt()),
    nextBytes(cipherSuite.hashLen.toInt()),
  )

fun Random.nextKeyPackage(
  cipherSuite: CipherSuite,
  signatureKeyPair: SignatureKeyPair = cipherSuite.generateSignatureKeyPair(),
): KeyPackage.Private =
  KeyPackage.generate(
    cipherSuite,
    signatureKeyPair,
    BasicCredential(Random.nextBytes(64)),
    Capabilities.create(listOf(CredentialType.Basic)),
    5.hours,
  )
