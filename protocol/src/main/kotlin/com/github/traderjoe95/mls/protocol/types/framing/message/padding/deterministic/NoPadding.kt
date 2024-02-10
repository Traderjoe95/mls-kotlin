package com.github.traderjoe95.mls.protocol.types.framing.message.padding.deterministic

import com.github.traderjoe95.mls.protocol.types.framing.message.padding.PaddingStrategy

object NoPadding : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray = content
}
