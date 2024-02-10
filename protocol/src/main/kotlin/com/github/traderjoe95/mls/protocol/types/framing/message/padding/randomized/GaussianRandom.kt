package com.github.traderjoe95.mls.protocol.types.framing.message.padding.randomized

import com.github.traderjoe95.mls.protocol.types.framing.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.TruncatedRoundedGaussian
import com.github.traderjoe95.mls.protocol.util.wipe

data class GaussianRandom(val meanPadding: UInt, val stdDev: Double) : PaddingStrategy {
  init {
    require(meanPadding > 0U) { "The mean padding must be positive"}
    require(stdDev > 0) { "The standard deviation must be positive" }
  }

  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray(content.size + RAND.next(meanPadding, stdDev).toInt()).also {
      content.copyInto(it)
      content.wipe()
    }

  companion object {
    private val RAND = TruncatedRoundedGaussian()
  }
}
