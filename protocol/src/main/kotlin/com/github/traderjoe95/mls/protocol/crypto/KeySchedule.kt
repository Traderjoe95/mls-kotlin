package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.tree.SecretTreeImpl
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface KeySchedule {
  val epochSecret: Secret

  val senderDataSecret: Secret
  val encryptionSecret: Secret
  val exporterSecret: Secret
  val externalSecret: Secret
  val confirmationKey: Secret
  val membershipKey: Secret
  val resumptionPsk: Secret
  val epochAuthenticator: Secret

  val secretTree: SecretTree

  fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret

  fun next(
    commitSecret: Secret,
    groupContext: GroupContext,
    leaves: UInt,
    pskSecret: Secret,
    externalInitSecret: Secret?,
  ): Triple<KeySchedule, Secret, Secret>

  companion object {
    context(Raise<JoinError>)
    fun join(
      cipherSuite: CipherSuite,
      joinerSecret: Secret,
      pskSecret: Secret,
      epoch: ULong,
      leaves: UInt,
      groupContext: GroupContext,
    ): KeySchedule =
      KeyScheduleImpl(
        cipherSuite,
        epoch,
        cipherSuite.expandWithLabel(
          cipherSuite.extract(joinerSecret, pskSecret),
          "epoch",
          groupContext.encoded,
        ),
        leaves = leaves,
      )

    context(Raise<JoinError>)
    fun joinExternal(
      cipherSuite: CipherSuite,
      externalInitSecret: Secret,
      commitSecret: Secret,
      pskSecret: Secret,
      epoch: ULong,
      leaves: UInt,
      groupContext: GroupContext,
    ): KeySchedule =
      join(
        cipherSuite,
        cipherSuite.expandWithLabel(
          cipherSuite.extract(externalInitSecret, commitSecret),
          "joiner",
          groupContext.encoded,
        ),
        pskSecret,
        epoch,
        leaves,
        groupContext,
      )
  }
}

internal class KeyScheduleImpl(
  private val cipherSuite: CipherSuite,
  private val epoch: ULong,
  override val epochSecret: Secret,
  private val externalPsks: Map<Int, Secret> = mapOf(),
  leaves: UInt,
) : KeySchedule, ICipherSuite by cipherSuite {
  override val senderDataSecret: Secret = throwAnyError { deriveSecret(epochSecret, "sender data") }
  override val encryptionSecret: Secret = throwAnyError { deriveSecret(epochSecret, "encryption") }
  override val exporterSecret: Secret = throwAnyError { deriveSecret(epochSecret, "exporter") }
  override val externalSecret: Secret = throwAnyError { deriveSecret(epochSecret, "external") }
  override val confirmationKey: Secret = throwAnyError { deriveSecret(epochSecret, "confirm") }
  override val membershipKey: Secret = throwAnyError { deriveSecret(epochSecret, "membership") }
  override val resumptionPsk: Secret = throwAnyError { deriveSecret(epochSecret, "resumption") }
  override val epochAuthenticator: Secret = throwAnyError { deriveSecret(epochSecret, "authentication") }

  private val initSecret: Secret = throwAnyError { deriveSecret(epochSecret, "init") }

  override val secretTree: SecretTree = SecretTreeImpl.create(leaves, encryptionSecret, cipherSuite)

  override fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret = throwAnyError { expandWithLabel(deriveSecret(exporterSecret, label), "exported", hash(context), length) }

  override fun next(
    commitSecret: Secret,
    groupContext: GroupContext,
    leaves: UInt,
    pskSecret: Secret,
    externalInitSecret: Secret?,
  ): Triple<KeySchedule, Secret, Secret> {
    val initSecret = externalInitSecret ?: this.initSecret

    val joinerSecret =
      cipherSuite.expandWithLabel(
        cipherSuite.extract(initSecret, commitSecret),
        "joiner",
        groupContext.encoded,
      )
    initSecret.wipe()

    val joinerExtracted = cipherSuite.extract(joinerSecret, pskSecret)
    val welcomeSecret = deriveSecret(joinerExtracted, "welcome")
    val epochSecret = expandWithLabel(joinerExtracted, "epoch", groupContext.encoded)

    return Triple(
      KeyScheduleImpl(cipherSuite, epoch + 1U, epochSecret, externalPsks, leaves),
      joinerSecret,
      welcomeSecret,
    )
  }

  companion object {
    fun new(cipherSuite: CipherSuite): KeySchedule =
      KeyScheduleImpl(
        cipherSuite,
        0UL,
        cipherSuite.generateSecret(cipherSuite.hashLen),
        mapOf(),
        1U,
      )
  }
}
