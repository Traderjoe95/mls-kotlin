package com.github.traderjoe95.mls.protocol.types.tree.leaf

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint64
import java.time.Instant

data class Lifetime(
  val notBefore: ULong,
  val notAfter: ULong,
) : Struct2T.Shape<ULong, ULong>, LeafNodeInfo {
  constructor(notBefore: Instant, notAfter: Instant) : this(
    notBefore.epochSecond.toULong(),
    notAfter.epochSecond.toULong(),
  )

  val notBeforeInstant: Instant
    get() = Instant.ofEpochSecond(notBefore.toLong())
  val notAfterInstant: Instant
    get() = Instant.ofEpochSecond(notAfter.toLong())

  companion object : Encodable<Lifetime> {
    override val dataT: DataType<Lifetime> =
      struct("Lifetime") {
        it.field("not_before", uint64.asULong)
          .field("not_after", uint64.asULong)
      }.lift(::Lifetime)
  }
}
