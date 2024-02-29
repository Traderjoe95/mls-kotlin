package com.github.traderjoe95.mls.protocol.message.padding.deterministic

import com.github.traderjoe95.mls.protocol.message.padding.PaddingStrategy

data object NoPadding : PaddingStrategy {
  override fun applyPadding(content: ByteArray): ByteArray = content
}
