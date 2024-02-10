package com.github.traderjoe95.mls.protocol.types.framing.content

import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

sealed interface Content {
  val contentType: ContentType
}
