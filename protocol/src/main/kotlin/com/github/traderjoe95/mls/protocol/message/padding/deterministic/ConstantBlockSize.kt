package com.github.traderjoe95.mls.protocol.types.framing.message.padding.deterministic

import com.github.traderjoe95.mls.protocol.types.framing.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.util.wipe

data class ConstantBlockSize(val blockSize: UInt) : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray =
    ByteArray((content.size / blockSize.toInt() + 1) * blockSize.toInt()).also { target ->
      content.copyInto(target)
      content.wipe()
    }
}
