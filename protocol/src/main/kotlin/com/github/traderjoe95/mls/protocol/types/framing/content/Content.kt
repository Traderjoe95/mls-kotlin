package com.github.traderjoe95.mls.protocol.types.framing.content

import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

sealed interface Content<out T : Content<T>> {
  val contentType: ContentType<T>

  sealed interface Handshake<out T : Handshake<T>> : Content<T> {
    override val contentType: ContentType.Handshake<T>
  }
}
