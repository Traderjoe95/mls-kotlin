package com.github.traderjoe95.mls.protocol.message.padding.randomized

import com.github.traderjoe95.mls.codec.util.fromBytes
import com.github.traderjoe95.mls.protocol.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.nextBytes
import com.github.traderjoe95.mls.protocol.util.wipe
import java.security.SecureRandom
import kotlin.math.ln
import kotlin.math.pow
import kotlin.math.round

data class CovertPadding(val proportion: Double = 0.1) : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray(content.size + calculatePaddingLength(content.size)).also {
      content.copyInto(it)
      content.wipe()
    }

  private fun calculatePaddingLength(size: Int): Int {
    val fixedPadding = maxOf(0, (proportion * 500).toInt() - size)

    val effSize = 200 + 1e8 * ln(1 + 1e-8 * (size + fixedPadding))

    // The original implementation uses little-endian byte order when converting the random bytes to an integer.
    // This implementation uses big-endian, but it makes no difference, as the bytes are random anyway and could
    // also have occurred in reverse order in the first place.
    val r = ln(2.0.pow(65)) - ln(1.0 + 2 * ULong.fromBytes(RAND.nextBytes(8)).toDouble())

    return fixedPadding + round(r * proportion * effSize).toInt()
  }

  companion object {
    private val RAND = SecureRandom()
  }
}
