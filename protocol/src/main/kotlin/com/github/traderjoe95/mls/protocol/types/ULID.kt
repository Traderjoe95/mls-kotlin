package com.github.traderjoe95.mls.protocol.types

import arrow.core.raise.recover
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import de.traderjoe.ulid.ULID

val ULID.Companion.T: DataType<ULID>
  get() =
    opaque[V].derive(
      {
        recover({ fromBytes(it).bind() }) {
          raise(DecoderError.UnexpectedError("Expected ${it.expected} bytes, but got ${it.length}"))
        }
      },
      { it.toBytes() },
    )
