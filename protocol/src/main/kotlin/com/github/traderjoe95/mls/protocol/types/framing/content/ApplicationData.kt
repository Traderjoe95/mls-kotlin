package com.github.traderjoe95.mls.protocol.types.framing.content

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

@JvmInline
value class ApplicationData(override val bytes: ByteArray) : Content, RefinedBytes<ApplicationData> {
  override val contentType: ContentType
    get() = ContentType.Application

  companion object : Encodable<ApplicationData> {
    override val dataT: DataType<ApplicationData> = RefinedBytes.dataT(::ApplicationData)
  }
}
