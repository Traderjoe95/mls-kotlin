package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.asUtf8String
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint16

internal data class KdfLabel(
  val length: UShort,
  val label: String,
  val context: ByteArray,
) : Struct3T.Shape<UShort, String, ByteArray> {
  companion object : Encodable<KdfLabel> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<KdfLabel> =
      struct("KDFLabel") {
        it.field("length", uint16.asUShort)
          .field("label", opaque[V].asUtf8String)
          .field("context", opaque[V])
      }.lift(::KdfLabel)

    fun create(
      length: UShort,
      label: String,
      context: ByteArray,
    ): KdfLabel = KdfLabel(length, "MLS 1.0 $label", context)
  }
}
