package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

sealed class KeyScheduleEvolution {
  protected abstract val cipherSuite: ICipherSuite
  internal abstract val initSecret: Secret

  fun nextEpoch(
    commitSecret: Secret,
    groupContext: GroupContext,
    pskSecret: Secret,
    forceInitSecret: Secret? = null,
  ): Triple<KeySchedule, Secret, Secret> {
    val initSecret = forceInitSecret ?: this.initSecret

    val joinerSecret =
      cipherSuite.expandWithLabel(
        cipherSuite.extract(initSecret, commitSecret),
        "joiner",
        groupContext.encoded,
      )
    initSecret.wipe()

    val joinerExtracted = cipherSuite.extract(joinerSecret, pskSecret)
    val welcomeSecret = cipherSuite.deriveSecret(joinerExtracted, "welcome")
    val epochSecret = cipherSuite.expandWithLabel(joinerExtracted, "epoch", groupContext.encoded)

    return Triple(
      KeySchedule(cipherSuite, epochSecret),
      joinerSecret,
      welcomeSecret,
    )
  }
}

class KeySchedule internal constructor(
  override val cipherSuite: ICipherSuite,
  epochSecret: Secret,
) : KeyScheduleEvolution() {
  internal val senderDataSecret: Secret = cipherSuite.deriveSecret(epochSecret, "sender data")
  internal val encryptionSecret: Secret = cipherSuite.deriveSecret(epochSecret, "encryption")
  internal val exporterSecret: Secret = cipherSuite.deriveSecret(epochSecret, "exporter")
  internal val externalSecret: Secret = cipherSuite.deriveSecret(epochSecret, "external")
  val confirmationKey: Secret = cipherSuite.deriveSecret(epochSecret, "confirm")
  val membershipKey: Secret = cipherSuite.deriveSecret(epochSecret, "membership")
  val resumptionPsk: Secret = cipherSuite.deriveSecret(epochSecret, "resumption")
  val epochAuthenticator: Secret = cipherSuite.deriveSecret(epochSecret, "authentication")

  override val initSecret: Secret = cipherSuite.deriveSecret(epochSecret, "init")

  val externalKeyPair: HpkeKeyPair by lazy { cipherSuite.deriveKeyPair(externalSecret) }

  fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret =
    cipherSuite.expandWithLabel(
      cipherSuite.deriveSecret(exporterSecret, label),
      "exported",
      cipherSuite.hash(context),
      length,
    )

  companion object {
    internal fun uninitialized(
      cipherSuite: CipherSuite,
      initSecret: Secret = cipherSuite.generateSecret(cipherSuite.hashLen),
    ): KeyScheduleEvolution = KeyScheduleInit(cipherSuite, initSecret)

    fun init(
      cipherSuite: CipherSuite,
      groupContext: GroupContext,
      initSecret: Secret = cipherSuite.generateSecret(cipherSuite.hashLen),
      commitSecret: Secret = Secret.zeroes(cipherSuite.hashLen),
      pskSecret: Secret = Secret.zeroes(cipherSuite.hashLen),
    ): KeySchedule = uninitialized(cipherSuite, initSecret).nextEpoch(commitSecret, groupContext, pskSecret).first

    fun join(
      cipherSuite: CipherSuite,
      joinerSecret: Secret,
      pskSecret: Secret,
      groupContext: GroupContext,
    ): KeySchedule =
      KeySchedule(
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
  override val cipherSuite: CipherSuite,
  override val initSecret: Secret,
) : KeyScheduleEvolution()
