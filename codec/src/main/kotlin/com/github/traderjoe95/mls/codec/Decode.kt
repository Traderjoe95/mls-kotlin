package com.github.traderjoe95.mls.codec

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.DataType.Companion.done
import com.github.traderjoe95.mls.codec.util.full

context(Raise<DecoderError>)
infix fun <V> ByteArray.decodeAs(dataType: DataType<V>): V = dataType.decode(full).done()

context(Raise<DecoderError>)
infix fun <V> ByteArray.decodeWithPadding(dataType: DataType<V>): V =
  dataType.decode(full).let { (result, remaining) ->
    if (remaining.hasRemaining && remaining.data.any { it != 0.toByte() }) {
      raise(DecoderError.ExtraDataInStream(remaining.firstIndex, remaining.size))
    }

    result
  }
