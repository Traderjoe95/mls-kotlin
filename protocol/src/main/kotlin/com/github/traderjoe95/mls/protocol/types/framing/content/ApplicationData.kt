package com.github.traderjoe95.mls.protocol.types.framing.content

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

data class ApplicationData(val data: ByteArray) : Content {
  override val contentType: ContentType = ContentType.Application

  companion object : Encodable<ApplicationData> {
    override val dataT: DataType<ApplicationData> = opaque[V].derive({ ApplicationData(it) }, { it.data })
  }
}
