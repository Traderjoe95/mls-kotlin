package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.RatchetError
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.log2
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

interface SecretTree {
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

  interface Lookup {
    context(Raise<RatchetError>, Raise<EpochError>)
    suspend fun getNonceAndKey(
      epoch: ULong,
      leafIndex: LeafIndex,
      contentType: ContentType,
      generation: UInt,
    ): Pair<Nonce, Secret>
  }
}

class Ratchet(
  val type: String,
  val cipherSuite: ICipherSuite,
  private var currentSecret: Secret,
  private var currentGeneration: UInt = 0U,
  private val unused: MutableMap<UInt, Pair<Nonce, Secret>> = mutableMapOf(),
) {
  companion object {
    const val SKIP_LIMIT = 255U
    const val BACKLOG_LIMIT = 64U
  }

  private val mutex: Mutex = Mutex()

  suspend fun consume(): Triple<Nonce, Secret, UInt> =
    mutex.withLock {
      Triple(nonce, key, currentGeneration).also { advance() }
    }

  context(Raise<RatchetError>)
  suspend fun consume(generation: UInt): Pair<Nonce, Secret> =
    mutex.withLock {
      if (generation > currentGeneration + SKIP_LIMIT) raise(RatchetError.StepTooLarge(type, generation))

      if (generation < currentGeneration) {
        unused.remove(generation) ?: raise(RatchetError.GenerationGone(type, generation))
      } else if (generation == currentGeneration) {
        (nonce to key).also { advance() }
      } else {
        skipTo(generation).run { nonce to key }.also { advance() }
      }
    }

  private fun skipTo(generation: UInt): Ratchet =
    apply {
      (currentGeneration..<generation).forEach {
        unused += it to (nonce to key)
        advance()
      }
    }

  private fun advance() {
    val oldSecret = currentSecret
    currentSecret = next
    currentGeneration++

    oldSecret.wipe()

    unused.remove(currentGeneration - BACKLOG_LIMIT)?.also { (n, s) ->
      n.wipe()
      s.wipe()
    }
  }

  private val next: Secret
    get() = deriveTreeSecret(currentSecret, "secret", currentGeneration)

  private val nonce: Nonce
    get() = deriveTreeSecret(currentSecret, "nonce", currentGeneration, cipherSuite.nonceLen).asNonce

  private val key: Secret
    get() = deriveTreeSecret(currentSecret, "key", currentGeneration, cipherSuite.keyLen)

  private fun deriveTreeSecret(
    secret: Secret,
    label: String,
    generation: UInt,
    length: UShort = cipherSuite.hashLen,
  ): Secret = throwAnyError { cipherSuite.expandWithLabel(secret, label, generation.toBytes(4U), length) }
}

data class SecretTreeLeaf(
  private val handshakeRatchet: Ratchet,
  private val applicationRatchet: Ratchet,
) {
  constructor(handshakeSeed: Secret, applicationSeed: Secret, cipherSuite: ICipherSuite) : this(
    Ratchet("handshake", cipherSuite, handshakeSeed),
    Ratchet("application", cipherSuite, applicationSeed),
  )

  context(Raise<RatchetError>)
  suspend fun consumeHandshakeRatchet(generation: UInt): Pair<Nonce, Secret> = handshakeRatchet.consume(generation)

  suspend fun consumeHandshakeRatchet(): Triple<Nonce, Secret, UInt> = handshakeRatchet.consume()

  context(Raise<RatchetError>)
  suspend fun consumeApplicationRatchet(generation: UInt): Pair<Nonce, Secret> = applicationRatchet.consume(generation)

  suspend fun consumeApplicationRatchet(): Triple<Nonce, Secret, UInt> = applicationRatchet.consume()
}

internal class SecretTreeImpl private constructor(private val leaves: Array<SecretTreeLeaf>) : SecretTree {
  context(Raise<RatchetError>)
  override suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType,
    generation: UInt,
  ): Pair<Nonce, Secret> =
    when (contentType) {
      ContentType.Application -> leaves[leafIndex.value].consumeApplicationRatchet(generation)
      ContentType.Proposal, ContentType.Commit -> leaves[leafIndex.value].consumeHandshakeRatchet(generation)
      else -> error("Unreachable")
    }

  override suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType,
  ): Triple<Nonce, Secret, UInt> =
    when (contentType) {
      ContentType.Application -> leaves[leafIndex.value].consumeApplicationRatchet()
      ContentType.Proposal, ContentType.Commit -> leaves[leafIndex.value].consumeHandshakeRatchet()
      else -> error("Unreachable")
    }

  companion object {
    internal fun create(
      leaves: UInt,
      encryptionSecret: Secret,
      cipherSuite: ICipherSuite,
    ): SecretTree =
      generateSequence(encryptionSecret) { cipherSuite.expandWithLabel(it, "tree", "left") }.take(
        when (leaves) {
          1U -> 1
          else -> log2(leaves - 1U).toInt() + 2
        },
      ).toList().let { initSecrets ->
        var intermediate = initSecrets

        Array(leaves.toInt()) { idx ->
          SecretTreeLeaf(
            cipherSuite.expandWithLabel(intermediate.last(), "handshake", ""),
            cipherSuite.expandWithLabel(intermediate.last(), "application", ""),
            cipherSuite,
          ).also {
            val no = idx.toUInt() + 1U

            generateSequence(0) { it + 1 }.find { no % (1U shl it) != 0U }!!.let { nullBits ->
              intermediate.takeLast(nullBits + 1).forEach { it.wipe() }

              if (no < leaves) {
                intermediate = intermediate.dropLast(nullBits + 1) +
                  generateSequence(
                    cipherSuite.expandWithLabel(
                      intermediate.lastOrNull() ?: encryptionSecret,
                      "tree",
                      "right",
                    ),
                  ) {
                    cipherSuite.expandWithLabel(it, "tree", "left")
                  }.take(nullBits + 1).toList()
              }
            }
          }
        }
      }.let(::SecretTreeImpl)
  }
}
