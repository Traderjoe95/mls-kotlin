package com.github.traderjoe95.mls.protocol.message.padding.deterministic

import com.github.traderjoe95.mls.protocol.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.wipe

data class Constant(val padding: UInt) : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray(content.size + padding.toInt()).also { target ->
      content.copyInto(target)
      content.wipe()
    }
}
