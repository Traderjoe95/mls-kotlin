package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

interface KeySchedule {
  val senderDataSecret: Secret
  val encryptionSecret: Secret
  val exporterSecret: Secret
  val externalSecret: Secret
  val confirmationKey: Secret
  val membershipKey: Secret
  val resumptionPsk: Secret
  val epochAuthenticator: Secret

  val initSecret: Secret

  val externalKeyPair: HpkeKeyPair

  fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret

  fun next(
    commitSecret: Secret,
    groupContext: GroupContext,
    pskSecret: Secret,
    externalInitSecret: Secret? = null,
  ): Triple<KeySchedule, Secret, Secret>

  companion object {
    fun uninitialized(
      cipherSuite: CipherSuite,
      initSecret: Secret = cipherSuite.generateSecret(cipherSuite.hashLen),
    ): KeySchedule = KeyScheduleInit(cipherSuite, initSecret)

    fun init(
      cipherSuite: CipherSuite,
      groupContext: GroupContext,
      initSecret: Secret = cipherSuite.generateSecret(cipherSuite.hashLen),
      commitSecret: Secret = Secret.zeroes(cipherSuite.hashLen),
      pskSecret: Secret = Secret.zeroes(cipherSuite.hashLen),
    ): KeySchedule = uninitialized(cipherSuite, initSecret).next(commitSecret, groupContext, pskSecret).first

    fun join(
      cipherSuite: CipherSuite,
      joinerSecret: Secret,
      pskSecret: Secret,
      groupContext: GroupContext,
    ): KeySchedule =
      KeyScheduleEpoch(
        cipherSuite,
        cipherSuite.expandWithLabel(
          cipherSuite.extract(joinerSecret, pskSecret),
          "epoch",
          groupContext.encoded,
        ),
      )
  }
}

internal class KeyScheduleInit(
  private val cipherSuite: CipherSuite,
  override val initSecret: Secret,
) : KeySchedule, ICipherSuite by cipherSuite {
  override val senderDataSecret: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val encryptionSecret: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val exporterSecret: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val externalSecret: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val confirmationKey: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val membershipKey: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val resumptionPsk: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val epochAuthenticator: Secret
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")
  override val externalKeyPair: HpkeKeyPair
    get() = throw UnsupportedOperationException("The key schedule is uninitialized")

  override fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Nothing {
    throw UnsupportedOperationException("The key schedule is uninitialized")
  }

  override fun next(
    commitSecret: Secret,
    groupContext: GroupContext,
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
      KeyScheduleEpoch(cipherSuite, epochSecret),
      joinerSecret,
      welcomeSecret,
    )
  }
}

internal class KeyScheduleEpoch(
  private val cipherSuite: CipherSuite,
  epochSecret: Secret,
) : KeySchedule, ICipherSuite by cipherSuite {
  override val senderDataSecret: Secret = deriveSecret(epochSecret, "sender data")
  override val encryptionSecret: Secret = deriveSecret(epochSecret, "encryption")
  override val exporterSecret: Secret = deriveSecret(epochSecret, "exporter")
  override val externalSecret: Secret = deriveSecret(epochSecret, "external")
  override val confirmationKey: Secret = deriveSecret(epochSecret, "confirm")
  override val membershipKey: Secret = deriveSecret(epochSecret, "membership")
  override val resumptionPsk: Secret = deriveSecret(epochSecret, "resumption")
  override val epochAuthenticator: Secret = deriveSecret(epochSecret, "authentication")

  override val initSecret: Secret = deriveSecret(epochSecret, "init")

  override val externalKeyPair: HpkeKeyPair by lazy { cipherSuite.deriveKeyPair(externalSecret) }

  override fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret = throwAnyError { expandWithLabel(deriveSecret(exporterSecret, label), "exported", hash(context), length) }

  override fun next(
    commitSecret: Secret,
    groupContext: GroupContext,
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
      KeyScheduleEpoch(cipherSuite, epochSecret),
      joinerSecret,
      welcomeSecret,
    )
  }

  companion object {
    fun new(cipherSuite: CipherSuite): KeySchedule =
      KeyScheduleEpoch(
        cipherSuite,
        cipherSuite.generateSecret(cipherSuite.hashLen),
      )
  }
}
