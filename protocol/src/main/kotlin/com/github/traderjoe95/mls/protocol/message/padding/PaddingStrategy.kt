package com.github.traderjoe95.mls.protocol.types.framing.message.padding

interface PaddingStrategy {
  fun applyPadding(content: ByteArray): ByteArray

  operator fun invoke(content: ByteArray): ByteArray = applyPadding(content)
}
