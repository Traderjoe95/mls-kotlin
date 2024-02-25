package com.github.traderjoe95.mls.protocol.types.framing.message.padding.deterministic

import com.github.traderjoe95.mls.protocol.types.framing.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.wipe

data object Padme : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray(calculatePaddedLength(content.size)).also {
      content.copyInto(it)
      content.wipe()
    }

  private fun calculatePaddedLength(size: Int): Int {
    if (size == 1) return 1

    val e = log2(size)
    val s = log2(e) + 1

    val lastBits = e - s
    val bitMask = (1 shl lastBits) - 1

    return (size + bitMask) and bitMask.inv()
  }
}
