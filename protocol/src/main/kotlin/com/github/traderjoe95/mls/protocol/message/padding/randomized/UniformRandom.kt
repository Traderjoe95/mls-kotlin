package com.github.traderjoe95.mls.protocol.message.padding.randomized

import com.github.traderjoe95.mls.protocol.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.wipe
import java.security.SecureRandom

data class UniformRandom(val maxPadding: UInt) : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray(content.size + RAND.nextInt(maxPadding.toInt() + 1)).also {
      content.copyInto(it)
      content.wipe()
    }

  companion object {
    private val RAND = SecureRandom()
  }
}
