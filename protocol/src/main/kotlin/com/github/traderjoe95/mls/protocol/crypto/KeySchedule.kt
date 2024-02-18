package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.RatchetError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.SecretTreeLeaf
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.log2

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

  fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret

  context(Raise<RatchetError>)
  suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType,
    generation: UInt,
  ): Pair<Nonce, Secret>

  suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType,
  ): Triple<Nonce, Secret, UInt>

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

  private val secretTreeLeaves: List<SecretTreeLeaf> =
    generateSequence(encryptionSecret) {
      throwAnyError { expandWithLabel(it, "tree", "left") }
    }.take(
      when (leaves) {
        1U -> 1
        else -> log2(leaves - 1U).toInt() + 2
      },
    ).toList().let { initSecrets ->
      var intermediate = initSecrets

      List(leaves.toInt()) { idx ->
        SecretTreeLeaf(
          throwAnyError { expandWithLabel(intermediate.last(), "handshake", "") },
          throwAnyError { expandWithLabel(intermediate.last(), "application", "") },
        ).also {
          val no = idx.toUInt() + 1U

          generateSequence(0) { it + 1 }.find { no % (1U shl it) != 0U }!!.let { nullBits ->
            intermediate.takeLast(nullBits + 1).forEach { it.wipe() }

            if (no < leaves) {
              intermediate = intermediate.dropLast(nullBits + 1) +
                generateSequence(
                  throwAnyError {
                    expandWithLabel(
                      intermediate.lastOrNull() ?: encryptionSecret,
                      "tree",
                      "right",
                    )
                  },
                ) {
                  throwAnyError {
                    expandWithLabel(it, "tree", "left")
                  }
                }.take(nullBits + 1).toList()
            }
          }
        }
      }
    }

  override fun mlsExporter(
    label: String,
    context: ByteArray,
    length: UShort,
  ): Secret = throwAnyError { expandWithLabel(deriveSecret(exporterSecret, label), "exported", hash(context), length) }

  context(Raise<RatchetError>)
  override suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType,
    generation: UInt,
  ): Pair<Nonce, Secret> =
    when (contentType) {
      ContentType.Application -> secretTreeLeaves[leafIndex.value].consumeApplicationRatchet(generation)
      ContentType.Proposal, ContentType.Commit ->
        secretTreeLeaves[leafIndex.value].consumeHandshakeRatchet(
          generation,
        )

      else -> error("Unreachable")
    }

  override suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType,
  ): Triple<Nonce, Secret, UInt> =
    when (contentType) {
      ContentType.Application -> secretTreeLeaves[leafIndex.value].consumeApplicationRatchet()
      ContentType.Proposal, ContentType.Commit -> secretTreeLeaves[leafIndex.value].consumeHandshakeRatchet()
      else -> error("Unreachable")
    }

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
