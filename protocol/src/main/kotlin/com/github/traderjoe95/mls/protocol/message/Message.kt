package com.github.traderjoe95.mls.protocol.message

import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

sealed interface Message {
  val wireFormat: WireFormat

  val encoded: ByteArray
}
