package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
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
    contentType: ContentType<*>,
    generation: UInt,
  ): Pair<Nonce, Secret>

  suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType<*>,
  ): Triple<Nonce, Secret, UInt>

  interface Lookup

  companion object {
    fun create(
      cipherSuite: ICipherSuite,
      encryptionSecret: Secret,
      leaves: UInt,
    ): SecretTree = SecretTreeImpl.create(leaves, encryptionSecret, cipherSuite)
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
    const val BACKLOG_LIMIT = 255U

    internal fun ICipherSuite.deriveTreeSecret(
      secret: Secret,
      label: String,
      generation: UInt,
      length: UShort = hashLen,
    ): Secret = expandWithLabel(secret, label, generation.toBytes(4U), length)
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
    get() = cipherSuite.deriveTreeSecret(currentSecret, "secret", currentGeneration)

  private val nonce: Nonce
    get() = cipherSuite.deriveTreeSecret(currentSecret, "nonce", currentGeneration, cipherSuite.nonceLen).asNonce

  private val key: Secret
    get() = cipherSuite.deriveTreeSecret(currentSecret, "key", currentGeneration, cipherSuite.keyLen)
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
    contentType: ContentType<*>,
    generation: UInt,
  ): Pair<Nonce, Secret> =
    when (contentType) {
      ContentType.Application -> leaves[leafIndex.value].consumeApplicationRatchet(generation)
      ContentType.Proposal, ContentType.Commit -> leaves[leafIndex.value].consumeHandshakeRatchet(generation)
      else -> error("Unreachable")
    }

  override suspend fun getNonceAndKey(
    leafIndex: LeafIndex,
    contentType: ContentType<*>,
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
      with(cipherSuite) {
        // Traverse the tree in-order, that way every intermediate secret only needs to be computed once
        // First generate the left flank of the tree: Start with the encryption secret and step down to the leaf, deriving
        // the "left" child secret on each step.
        generateSequence(encryptionSecret) { expandWithLabel(it, "tree", "left") }
          .take(if (leaves == 1U) 1 else log2(leaves - 1U).toInt() + 2)
          .toList()
          .let { initSecrets ->
            var intermediate = initSecrets

            Array(leaves.toInt()) { idx ->
              // Calculate the leaf init secrets
              SecretTreeLeaf(
                expandWithLabel(intermediate.last(), "handshake", ""),
                expandWithLabel(intermediate.last(), "application", ""),
                cipherSuite,
              ).also {
                val no = idx.toUInt() + 1U

                // Find out how many steps to go back up the tree to reach the next leaf.
                // This is basically done by finding the first non-zero bit in the current leafIdx + 1
                generateSequence(1) { it + 1 }.find { no % (1U shl it) != 0U }!!.let { backTrack ->
                  // Wipe intermediate secrets that are no longer needed
                  intermediate
                    .takeLast(backTrack)
                    .forEach { it.wipe() }

                  if (no < leaves) {
                    // Backtrack by dropping the last n steps, then go one step right and continue by stepping down to
                    // the left until reaching the leaf
                    intermediate = intermediate.dropLast(backTrack)
                    val stepRight = expandWithLabel(intermediate.lastOrNull() ?: encryptionSecret, "tree", "right")

                    intermediate =
                      intermediate +
                      generateSequence(stepRight) { expandWithLabel(it, "tree", "left") }
                        .take(backTrack)
                        .toList()
                  }
                }
              }
            }
          }
      }.let(::SecretTreeImpl)
  }
}
