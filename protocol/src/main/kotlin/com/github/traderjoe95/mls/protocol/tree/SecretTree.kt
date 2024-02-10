package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.RatchetError
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

interface SecretTree {
  context(Raise<RatchetError>)
  suspend fun getNonceAndKey(
    epoch: ULong,
    leafIndex: UInt,
    contentType: ContentType,
    generation: UInt,
  ): Pair<Nonce, Secret>

  suspend fun getNonceAndKey(
    leafIndex: UInt,
    contentType: ContentType,
  ): Triple<Nonce, Secret, UInt>
}

class Ratchet(
  val type: String,
  private var currentSecret: Secret,
  private var currentGeneration: UInt = 0U,
  private val unused: MutableMap<UInt, Pair<Nonce, Secret>> = mutableMapOf(),
) {
  companion object {
    const val SKIP_LIMIT = 255U
    const val BACKLOG_LIMIT = 64U
  }

  private val mutex: Mutex = Mutex()

  context(ICipherSuite)
  suspend fun consume(): Triple<Nonce, Secret, UInt> =
    mutex.withLock {
      Triple(nonce, key, currentGeneration).also { advance() }
    }

  context(ICipherSuite, Raise<RatchetError>)
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

  context(ICipherSuite)
  private fun skipTo(generation: UInt): Ratchet =
    apply {
      (currentGeneration..<generation).forEach {
        unused += it to (nonce to key)
        advance()
      }
    }

  context(ICipherSuite)
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

  context(ICipherSuite)
  private val next: Secret
    get() = deriveTreeSecret(currentSecret, "secret", currentGeneration)

  context(ICipherSuite)
  private val nonce: Nonce
    get() = deriveTreeSecret(currentSecret, "nonce", currentGeneration, nonceLen).asNonce

  context(ICipherSuite)
  private val key: Secret
    get() = deriveTreeSecret(currentSecret, "key", currentGeneration, keyLen)

  private fun ICipherSuite.deriveTreeSecret(
    secret: Secret,
    label: String,
    generation: UInt,
    length: UShort = hashLen,
  ): Secret = throwAnyError { expandWithLabel(secret, label, generation.toBytes(4U), length) }
}

data class SecretTreeLeaf(
  private val handshakeRatchet: Ratchet,
  private val applicationRatchet: Ratchet,
) {
  constructor(handshakeSeed: Secret, applicationSeed: Secret) : this(
    Ratchet("handshake", handshakeSeed),
    Ratchet("application", applicationSeed),
  )

  context(ICipherSuite, Raise<RatchetError>)
  suspend fun consumeHandshakeRatchet(generation: UInt): Pair<Nonce, Secret> = handshakeRatchet.consume(generation)

  context(ICipherSuite)
  suspend fun consumeHandshakeRatchet(): Triple<Nonce, Secret, UInt> = handshakeRatchet.consume()

  context(ICipherSuite, Raise<RatchetError>)
  suspend fun consumeApplicationRatchet(generation: UInt): Pair<Nonce, Secret> = applicationRatchet.consume(generation)

  context(ICipherSuite)
  suspend fun consumeApplicationRatchet(): Triple<Nonce, Secret, UInt> = applicationRatchet.consume()
}
