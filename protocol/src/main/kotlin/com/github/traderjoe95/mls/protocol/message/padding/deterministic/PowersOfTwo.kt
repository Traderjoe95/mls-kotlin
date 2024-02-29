package com.github.traderjoe95.mls.protocol.message.padding.deterministic

import com.github.traderjoe95.mls.protocol.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.wipe

object PowersOfTwo : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray(1 shl (log2(content.size.toUInt()).toInt() + 1)).also { target ->
      content.copyInto(target)
      content.wipe()
    }
}
