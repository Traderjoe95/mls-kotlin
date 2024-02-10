package de.traderjoe.ulid.internal

import java.security.SecureRandom

@JvmInline
internal value class Randomness internal constructor(internal val bytes: ByteArray) {
  internal fun increment(): Randomness = Randomness(bytes.increment())

  internal companion object {
    private val rand = SecureRandom()

    internal fun random(): Randomness = Randomness(ByteArray(10).also { rand.nextBytes(it) })

    internal fun fromBytes(bytes: ByteArray): Randomness = Randomness(bytes)

    private fun ByteArray.increment(): ByteArray {
      val result = copyOf()

      for (i in indices.reversed()) {
        result[i] = (result[i] + 1).toByte()

        if (result[i] != 0.toByte()) break
      }

      return result
    }
  }
}
